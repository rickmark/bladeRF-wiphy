/*
 * This file is part of the bladeRF-linux-mac80211 project
 *
 * Copyright (C) 2020 Nuand LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/nl80211.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libbladeRF.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>

#include "bladeRF-wiphy.h"

#define TWENTY_MHZ (20 * 1000 * 1000)
#define FORTY_MHZ  (40 * 1000 * 1000)
#define EIGHTY_MHZ (80 * 1000 * 1000)

pthread_mutex_t log_mutex;

typedef struct {
   // bladeRF device handle
   struct bladerf *bladeRF_dev;

   // bladeRF frequency variables
   bladerf_frequency local_freq;
   bladerf_frequency local_tx_freq;
   unsigned int force_freq;
   bladerf_frequency updated_freq;

   unsigned int half_rate_only;

   // TX/RX gain variables
   int tx_gain;
   int tx_mod;
   int disable_agc;
   int rx_gain;
   int tun_tap;
   int tun_tap_fd;

   struct nl_sock *netlink_sock;
   int netlink_family;
} wiphy_device_t;


bool debug_mode = 1;

wiphy_device_t wiphy_devices[1];



struct tx_rate {
   uint8_t idx;
   uint8_t count;
};

struct tx_rate_info {
   uint8_t  idx;
   uint16_t info;
};

int set_new_frequency(bladerf_frequency freq);
int rx_frame(struct nl_sock *netlink_sock, int netlink_family, uint8_t *ptr, int len, int mod);
int start_mac80211(char *cmd, wiphy_device_t *wiphy_device);
int start_tun_tap(char *cmd, wiphy_device_t *wiphy_device);


unsigned int bytes_to_dwords(int bytes) {
    return (bytes + 3) / 4;
}

int bladerf_tx_frame(uint8_t *data, int len, int modulation, uint64_t cookie) {
    uint8_t *frame;
    int status;
    int frame_len;
    struct bladeRF_wiphy_header_tx *bwh_t;
    struct bladerf_metadata meta;
    memset(&meta, '0', sizeof(meta));

    frame_len = len + sizeof(struct bladeRF_wiphy_header_tx);
    frame = (uint8_t *)malloc(frame_len);
    bwh_t = (struct bladeRF_wiphy_header_tx *)frame;
    memset(frame, 0, frame_len);
    memcpy(frame + sizeof(struct bladeRF_wiphy_header_tx), data, len);

    bwh_t->len = len;

    if (wiphy_devices[0].half_rate_only) {
       if (modulation == 1 || modulation == 3) {
          modulation--;
       } else if (modulation > 4) {
          modulation = 4;
       }
    }

    bwh_t->modulation = modulation;
    bwh_t->bandwidth = 2;
    bwh_t->cookie = cookie;

    if (debug_mode > 2) {
        printf("TX =...");
        fflush(stdout);
    }

    status = bladerf_sync_tx(wiphy_devices[0].bladeRF_dev, frame, bytes_to_dwords(frame_len), &meta, 0);
    if (debug_mode > 2) {
        printf("%d\n", status);
    }

    return 0;
}

void dump_packet(uint8_t *payload_data, int payload_len)
{
   int i;
   printf("Frame payload (len=%d):\n", payload_len);
   for (i = 0; i < payload_len; i++) {
      if ((i % 16) == 0) {
         printf("  %.4x :", i);
      }
      printf(" %.2x", payload_data[i]);

      if ((i % 16) == 15) {
         printf("\n");
      }
   }
}


int netlink_frame_callback(struct nl_msg *netlink_message, void *arg)
{
   wiphy_device_t *wiphy_device = (wiphy_device_t *)arg;

   /* netlink variables */
   struct nlmsghdr   *netlink_header = NULL;
   struct genlmsghdr *genlink_header = NULL;

   struct nlattr *genlink_attribute_head = NULL;
   int            genlink_attribute_len  = 0;

   struct nlattr *attribute_table[NL80211_ATTR_MAX + 1];

   /* frame variables */
   uint8_t *payload_data;
   int      payload_len;
   int i;
   uint64_t cookie;
   uint32_t frequency;
   uint32_t flags;
   uint8_t *mac;
   uint8_t frame_type;

   struct tx_rate       *tx_rate;
   int                   tx_rate_len;
   struct tx_rate_info  *tx_rate_info;
   int                   tx_rate_info_len;

   netlink_header = nlmsg_hdr(netlink_message);
   genlink_header = genlmsg_hdr(netlink_header);

   if (genlink_header->cmd != NL80211_CMD_FRAME && 
       genlink_header->cmd != NL80211_CMD_SET_WIPHY) {
      return 0;
   }

   /* parse attributes into table */
   genlink_attribute_len = genlmsg_attrlen(genlink_header, 0);
   genlink_attribute_head = genlmsg_attrdata(genlink_header, 0);
   nla_parse(attribute_table, NL80211_ATTR_MAX, genlink_attribute_head,
                                            genlink_attribute_len, NULL);

   if (attribute_table[NL80211_ATTR_WIPHY_FREQ]) {
      frequency = nla_get_u32(attribute_table[NL80211_ATTR_WIPHY_FREQ]);
   }

   if (genlink_header->cmd == NL80211_CMD_FRAME) {
      payload_data    = nla_data(attribute_table[NL80211_ATTR_FRAME]);
      payload_len     = nla_len(attribute_table[NL80211_ATTR_FRAME]);

      mac       = nla_data(attribute_table[NL80211_ATTR_MAC]);
      cookie    = nla_get_u64(attribute_table[NL80211_ATTR_COOKIE]);
      flags     = nla_get_u32(attribute_table[NL80211_ATTR_STA_FLAGS]);

      tx_rate     = nla_data(attribute_table[ NL80211_CMD_SET_TX_BITRATE_MASK ]);
      tx_rate_len = nla_len(attribute_table[ NL80211_CMD_SET_TX_BITRATE_MASK]);

      tx_rate_info     = nla_data(attribute_table[ NL80211_ATTR_TX_RATES ]);
      tx_rate_info_len = nla_len(attribute_table[ NL80211_ATTR_TX_RATES]);

      frame_type = (payload_data[0] >> 2) & 0x3;

      if (debug_mode) {
         //pthread_mutex_lock(&log_mutex);
         printf("TX frame:\n");
         printf("Frame cookie = %lu\n", cookie);
         /* display center frequency of channel in MHz */
         printf("Frequency = %d\n", frequency);

         /* display MAC address of transmitter */
         printf("TX MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2],
               mac[3], mac[4], mac[5]);

         /* display TX rate selection table */
         printf("Rates:\n");
         for (i = 0; i < (tx_rate_len / sizeof(struct tx_rate)); i++) {
            if (tx_rate[i].idx == 255)
               break;
            printf("   [%d] rate=%d count=%d\n", i, tx_rate[i].idx, tx_rate[i].count);
         }
         printf("Rate info:\n");
         for (i = 0; i < (tx_rate_info_len / sizeof(struct tx_rate_info)); i++) {
            if (tx_rate_info[i].idx == 0)
               break;
            printf("   [%d] rate=%d rate_info=%d\n", i, tx_rate_info[i].idx, tx_rate_info[i].info);
         }

         printf("Flags: %x (tx_status_req=%d, no_ack=%d, stat_ack=%d)\n",
               flags, !!(flags & 1), !!(flags & 2), !!(flags & 4));
         printf("Payload type: ");
         if (frame_type == 0) {
            printf("Management");
         }
         printf("\n");

         dump_packet(payload_data, payload_len);
         printf("\n\n\n");
         //pthread_mutex_unlock(&log_mutex);
      }

      return bladerf_tx_frame(payload_data, payload_len, tx_rate[0].idx, cookie); 
   } else if (genlink_header->cmd == NL80211_CMD_SET_CHANNEL) {
      set_new_frequency(frequency);
      wiphy_device->updated_freq = 1;
   }

   return 0;
}

int tx_cb(struct nl_sock *netlink_sock, int netlink_family, struct bladeRF_wiphy_header_rx *bwh_r)
{
   int status = 0;
   void *ret_ptr = NULL;
   struct nl_msg *netlink_msg = NULL;
   netlink_msg = nlmsg_alloc();
   ret_ptr = genlmsg_put(netlink_msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0, /* TX INFO */ 3, 0);
   nla_put(netlink_msg, 2 /* TRANSMITTER */, 6, "\x42\x00\x00\x00\x00\x00");
   nla_put_u32(netlink_msg, 4 /* FLAGS */, /* ACK */ bwh_r->type == 2 ? 4 : 0);
   struct tx_rate tr[4];
   memset(&tr, 0, sizeof(tr));
   tr[0].idx = bwh_r->modulation;
   tr[0].count = 1;
   nla_put_u32(netlink_msg, 6 /* SIGNAL */, -30);
   nla_put(netlink_msg, 7 /* RATE */, sizeof(tr), &tr);
   nla_put_u64(netlink_msg, 8 /* COOKIE */, bwh_r->cookie);

   status = nl_send_auto(netlink_sock, netlink_msg);
   if (status < 0) {
      printf("nl_send_auto() failed with error=%d\n", status);
      return -1;
   }
   nlmsg_free(netlink_msg);
   return 0;
}

int rx_frame(struct nl_sock *netlink_sock, int netlink_family, uint8_t *ptr, int len, int mod)
{
   int status = 0;
   void *ret_ptr = NULL;
   struct nl_msg *netlink_msg = NULL;
   int band_rate_modifier = (wiphy_devices[0].local_freq > 2500) ? 0 : 4;

   netlink_msg = nlmsg_alloc();
   ret_ptr = genlmsg_put(netlink_msg, NL_AUTO_PORT, NL_AUTO_SEQ, netlink_family, 0, 0, /* FRAME */ 2, 0);
   if (!ret_ptr) {
      printf("genlmsg_put() failed\n");
      return -1;
   }
   nla_put(netlink_msg, 1 /* RECEIVER */, 6, "\x42\x00\x00\x00\x00\x00");
   nla_put(netlink_msg, 3 /* FRAME */, len, ptr);
   nla_put_u32(netlink_msg, 5 /* RX RATE */, mod + band_rate_modifier);
   nla_put_u32(netlink_msg, 6 /* SIGNAL */, -50);
   if (!wiphy_devices[0].force_freq && wiphy_devices[0].updated_freq)
      nla_put_u32(netlink_msg, 19 /* FREQ */, wiphy_devices[0].local_freq);

   status = nl_send_auto(netlink_sock, netlink_msg);
   if (status < 0) {
      printf("nl_send_auto() failed with error=%d\n", status);
      return -1;
   }
   nlmsg_free(netlink_msg);
   return 0;
}

int set_new_frequency(bladerf_frequency freq) {
   bladerf_frequency tx_freq;
   int status = 0;

   if (wiphy_devices[0].force_freq)
      return 0;

   if (freq == wiphy_devices[0].local_freq)
      return 0;

   if (!wiphy_devices[0].bladeRF_dev)
      return 0;

   if (debug_mode) {
      printf("Changing channel to %lu Hz\n", freq);
   }

   status = bladerf_set_frequency(wiphy_devices[0].bladeRF_dev, BLADERF_CHANNEL_RX(0), freq);
   if (status != 0) {
      printf("Could not set RX frequency to freq=% " BLADERF_PRIuFREQ " Hz, error=%d, %s\n", freq, status, bladerf_strerror(status));
      return status;
   }

   if (wiphy_devices[0].local_tx_freq) {
      tx_freq = wiphy_devices[0].local_tx_freq;
   } else {
      tx_freq = freq;
   }
   status = bladerf_set_frequency(wiphy_devices[0].bladeRF_dev, BLADERF_CHANNEL_TX(0), tx_freq);
   if (status != 0) {
      printf("Could not set TX frequency to freq=%" BLADERF_PRIuFREQ ", error=%d, %s\n", tx_freq, status, bladerf_strerror(status));
      return status;
   }

   printf("Set RX to %" BLADERF_PRIuFREQ " and TX to %" BLADERF_PRIuFREQ "\n", freq, tx_freq);

   wiphy_devices[0].local_freq = freq;

   return 0;
}

int config_bladeRF(char *dev_str, wiphy_device_t *wiphy_device) {
   int status = 0;
   struct bladerf_version fpga_ver;
   const int num_buffers = 4096;
   const int num_dwords_buffer = 4096; // 4096 bytes
   const int num_transfers = 16;
   const int stream_timeout = 10000000;


   bladerf_sample_rate sample_rate = TWENTY_MHZ;
   bladerf_bandwidth   req_bw, actual_bw;
   req_bw = TWENTY_MHZ;


   printf("Opening bladeRF with dev_str=%s\n", dev_str ? : "(NULL)");
   status = bladerf_open(&wiphy_device->bladeRF_dev, NULL);
   if (status != 0) {
      printf("Error opening bladeRF error=%d\n", status);
      return status;
   }

   status = bladerf_fpga_version(wiphy_device->bladeRF_dev, &fpga_ver);
   if (status != 0) {
      printf("Could not query FPGA version, error=%d\n", status);
      return status;
   }

   if (fpga_ver.major == 0 && fpga_ver.minor < 12) {
      printf("FPGA version %d.%d.%d detected, "
            "however at minimum FPGA version 0.12.0 is required.\n",
            fpga_ver.major, fpga_ver.minor, fpga_ver.patch);
      return -1;
   }

   status = bladerf_sync_config(wiphy_device->bladeRF_dev, BLADERF_RX_X1,
                     BLADERF_FORMAT_PACKET_META, num_buffers, num_dwords_buffer,
                     num_transfers, stream_timeout);
   if (status != 0) {
      printf("Could not config RX sync config, error=%d\n", status);
      return status;
   }

   status = bladerf_sync_config(wiphy_device->bladeRF_dev, BLADERF_TX_X1,
                     BLADERF_FORMAT_PACKET_META, num_buffers, num_dwords_buffer,
                     num_transfers, stream_timeout);
   if (status != 0) {
      printf("Could not config TX sync config, error=%d\n", status);
      return status;
   }

   status = bladerf_set_sample_rate(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_RX(0),
                              sample_rate, NULL);
   if (status != 0) {
      printf("Could not set RX sample rate, error=%d\n", status);
      return status;
   }

   status = bladerf_set_sample_rate(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_TX(0),
                              sample_rate, NULL);
   if (status != 0) {
      printf("Could not set TX sample rate, error=%d\n", status);
      return status;
   }

   if (wiphy_devices[0].disable_agc) {
      if (debug_mode) {
         printf("Disabling AGC and setting RX gain to %d\n", wiphy_devices[0].rx_gain);
      }
      status = bladerf_set_gain_mode(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_RX(0), BLADERF_GAIN_MGC);
      if (status != 0) {
         printf("Could not disable AGC and set RX gain mode to manual, error=%d\n", status);
         return status;
      }
      status = bladerf_set_gain(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_RX(0), wiphy_devices[0].rx_gain);
      if (status != 0) {
         printf("Could not set manual RX gain, error=%d\n", status);
         return status;
      }
   }

   status = bladerf_enable_module(wiphy_device->bladeRF_dev, BLADERF_MODULE_TX, true);
   if (status != 0) {
      printf("Could not enable TX module, error=%d\n", status);
      return status;
   }

   status = bladerf_enable_module(wiphy_device->bladeRF_dev, BLADERF_MODULE_RX, true);
   if (status != 0) {
      printf("Could not enable RX module, error=%d\n", status);
      return status;
   }
   bladerf_set_gain_stage(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_TX(0), "dsa", wiphy_devices[0].tx_gain);
   bladerf_set_bias_tee(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_RX(0), true);
   bladerf_set_bias_tee(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_RX(1), true);
   bladerf_set_bias_tee(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_TX(0), true);
   bladerf_set_bias_tee(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_TX(1), true);

   status = bladerf_set_bandwidth(wiphy_device->bladeRF_dev, BLADERF_CHANNEL_RX(0), req_bw, &actual_bw);
   if (status != 0) {
      printf("Could not set RX bandwidth, error=%d\n", status);
      return status;
   }
   printf("RX bandwidth set to %d Hz\n", actual_bw);

   status = bladerf_set_bandwidth(wiphy_devices[0].bladeRF_dev, BLADERF_CHANNEL_TX(0), req_bw, &actual_bw);
   if (status != 0) {
      printf("Could not set TX bandwidth, error=%d\n", status);
      return status;
   }
   printf("TX bandwidth set to %d Hz\n", actual_bw);


   return 0;
}

int receive_test() {
   uint8_t *data = malloc(4096 * 16);
   memset(data, 0, 4096 * 16);
   uint8_t *lut = 0;
   uint32_t max_cnt = 0;
   uint32_t tmp;
   int status;
   while(1) {
      struct bladerf_metadata meta;
      struct bladeRF_wiphy_header_rx *bwh_r = (struct bladeRF_wiphy_header_rx *)data;
      memset(&meta, '0', sizeof(meta));
      if (!max_cnt)
         fprintf(stderr, "Awaiting first benchmark packet.");
      status = bladerf_sync_rx(wiphy_devices[0].bladeRF_dev, data, 1000, &meta, max_cnt ? 2500 : 0);
      if (status == -6) {
         int i;
         int cnt = 0;
         for (i = 0; i < max_cnt; i++) {
            if (lut[i])
               cnt++;
         }
         printf("Packet success rate: %f %%\n", 100*((float)cnt)/max_cnt);
         return 0;
      } else if (status) {
         return -1;
      }
      if (bwh_r->len-4 < 32)
         continue;
      if (memcmp(data+16, "\x12\x34\x56\x78", 4))
         continue;
      if (!lut) {
         max_cnt = *(uint32_t *)(data+16+28);
         lut = (uint8_t *)malloc(sizeof(uint8_t) * max_cnt);
         if (!lut)
            return -1;
         memset(lut, 0, sizeof(uint8_t) * max_cnt);
      }
      tmp = *(uint32_t *)(data+16+32);
      if (tmp > max_cnt)
         continue;
      lut[tmp] = 1;
      fprintf(stderr, "\r%d / %d                       \r", tmp, max_cnt);
   }
}

void *rx_thread(void *arg) {
   wiphy_device_t *wiphy_device = (wiphy_device_t *)arg;

   bladerf_trim_dac_write(wiphy_device->bladeRF_dev, 0x0ea8);
   uint8_t *data = malloc(4096 * 16);
   memset(data, 0, 4096 * 16);
   while(1) {
      struct bladerf_metadata meta;
      memset(&meta, '0', sizeof(meta));
      bladerf_sync_rx(wiphy_device->bladeRF_dev, data, 1000, &meta, 0);
      struct bladeRF_wiphy_header_rx *bwh_r = (struct bladeRF_wiphy_header_rx *)data;
      int i;
      if (debug_mode) {
         //pthread_mutex_lock(&log_mutex);
         printf("RX frame:\n");
         if (debug_mode > 2) {
            printf("Bytes:\n");
            for (i = 0; i < 48; i++)
               printf("%.2x ", data[i]);
         }

         char *type_str = "Unknown";
         if (bwh_r->type == 1) {
            type_str = "Packet";
         } else if (bwh_r->type == 2) {
            type_str = "ACK";
         } else if (bwh_r->type == 3) {
            type_str = "Missing ACK";
         }

         printf("Type:   %d (%s)\n", bwh_r->type, type_str);
         if (bwh_r->type == 1) {
            printf("Length: %d\n", bwh_r->len);
            printf("Rsvd2:  0x%.8x\n", bwh_r->rsvd2);
         } else {
            printf("Cookie: %d\n", bwh_r->cookie);
         }
         printf("Modulation: %d\n",  bwh_r->modulation);
         printf("Bandwidth:  %d\n",  bwh_r->bandwidth);
         printf("Rsvd3:      0x%.8x\n", bwh_r->rsvd3);

         if (bwh_r->type == 1)
            dump_packet(data+16, bwh_r->len);
         printf("\n\n\n");
         //pthread_mutex_unlock(&log_mutex);
      }

      if (wiphy_device->tun_tap) {
         if (bwh_r->type == 1) {
            write(wiphy_device->tun_tap_fd, data+16, bwh_r->len - 4);
         }
      } else {
         if (bwh_r->type != 1) {
            tx_cb(wiphy_device->netlink_sock, wiphy_device->netlink_family, bwh_r);
         }
         if (bwh_r->type == 1) {
            rx_frame(wiphy_device->netlink_sock, wiphy_device->netlink_family, data+16, bwh_r->len-4, bwh_r->modulation);
         }
      }

   }
}

int transmit_test(uint32_t count, int mod, int length) {
   int i;
   char *data;

   data = (char *)malloc(length + 40);
   memset(data, 0, length + 40);
   memcpy(data, "\x12\x34\x56\x78", 4);
   memset(data+4, 0xff, 18);
   memcpy(data+28, &count, sizeof(count));

   printf("Sending %d packets at %d modulation and %d bytes long:\n", count, mod, length);
   for (i = 0; i < count; i++) {
      memcpy(data+32, &i, sizeof(i));
      if (bladerf_tx_frame(data, length, mod, 0xbd81))
         return -1;
   }
   sleep(5);
   return 0;
}

#ifndef LIBBLADERF_API_VERSION
#error LIBBLADERF_API_VERSION is not defined in headers. At minimum libbladeRF version 2.4.0 is required.
#endif
#if ( LIBBLADERF_API_VERSION < 0x2040000 )
#error Incompatible libbladeRF header version. At minimum libbladeRF version 2.4.0 is required.
#endif

int main(int argc, char *argv[])
{
   int status;
   struct nl_cb *netlink_cb = NULL;
   unsigned long freq = 0;
   unsigned long tx_freq = 0;
   int trx_test = 0;
#define TRX_TEST_NONE 0
#define TRX_TEST_RX   1
#define TRX_TEST_TX   2
   int tx_count = 100;
   int tx_len = 200;
   int cmd;

   pthread_mutex_init(&log_mutex, NULL);
   struct bladerf_version ver;
   memset(wiphy_devices, 0, sizeof(wiphy_devices));
   wiphy_device_t *wiphy_device = &wiphy_devices[0];

   bladerf_version(&ver);
   if (ver.major < 2 || (ver.major == 2 && ver.minor < 4)) {
      printf("Incorrect version (%d.%d.%d) of libbladeRF detected.\n"
             "At minimum libbladeRF version 2.4.0 is required.\n",
             ver.major, ver.minor, ver.patch);
      return -1;
   }

   char *dev_str = NULL;
   while (-1 != ( cmd = getopt(argc, argv, "rt:l:c:d:f:s:a:g:m:vVhHT"))) {
      if (cmd == 'd') {
         dev_str = strdup(optarg);
      } else if (cmd == 'f') {
         freq = atol(optarg);
         printf("Overriding RX/TX frequency to %luMHz\n", freq);
      } else if (cmd == 's') {
         wiphy_devices[0].local_tx_freq = atol(optarg);
         printf("Overriding TX frequency to %luMHz\n", wiphy_devices[0].local_tx_freq);
      } else if (cmd == 'r') {
         trx_test = TRX_TEST_RX;
      } else if (cmd == 'c') {
         tx_count = atol(optarg);
      } else if (cmd == 'l') {
         tx_len = atol(optarg);
      } else if (cmd == 'm') {
         wiphy_device->tx_mod = atol(optarg);
      } else if (cmd == 't') {
         trx_test = TRX_TEST_TX;
         wiphy_device->tx_mod = atol(optarg);
      } else if (cmd == 'a') {
         wiphy_device->disable_agc = 1;
         wiphy_device->rx_gain = atoi(optarg);
         printf("Overriding AGC and setting RX gain to %d\n", wiphy_device->rx_gain);
      } else if (cmd == 'g') {
         wiphy_device->tx_gain = atol(optarg);
         printf("Overriding DSA gain to %d\n", wiphy_device->tx_gain);
      } else if (cmd == 'v') {
         debug_mode = 10;
      } else if (cmd == 'V') {
         debug_mode = 0;
      } else if (cmd == 'H') {
         wiphy_device->half_rate_only = 1;
         printf("Overriding rate selection to half rates\n");
      } else if (cmd == 'T') {
         wiphy_device->tun_tap = 1;
      } else if (cmd == 'h') {
         fprintf(stderr,
               "usage: bladeRF-linux-mac80211 [-d device_string] [-f frequency] [-s TX_frequency] [-H] [-r] [-t <tx test modulation>]\n"
               "                              [-m TX_mod] [-c count] [-l length] [-v] [-V] [-a RX_gain] [-g tx_dsa_gain] [-T]\n"
               "\n"
               "\t\n"
               "\tdevice_string, uses the standard libbladeRF bladerf_open() syntax\n"
               "\tfrequency, center frequency expressed in MHz\n"
               "\ttx_dsa_gain, maximum gain occurs at `0', values are in dB\n"
               "\tRX_gain, setting this disables AGC, and sets the RX gain to the specified number\n"
               "\tTX_frequency, specifies the split TX frequency\n"
               "\tTX_mod, override TX modulation\n"
               "\t-H selects half rates\n"
               "\t-v enables very verbose mode\n"
               "\t-V disables verbose mode entirely\n"
               "\t-T enable TUN/TAP\n"
         );
         return -1;

      }
   }

   if (config_bladeRF(dev_str, wiphy_device)) {
      return -1;
   }

   if (trx_test != TRX_TEST_NONE) {
      status = set_new_frequency(freq);
      wiphy_device->force_freq = 1;
      if (trx_test == TRX_TEST_RX) {
         return receive_test();
      } else if (trx_test == TRX_TEST_TX) {
         if (tx_len < 32) {
            printf("specify a packet length greater than 32 with -l\n");
            return -1;
         }
         return transmit_test(tx_count, wiphy_device->tx_mod, tx_len);
      }
   }

   if (freq) {
      status = set_new_frequency(freq);
      wiphy_device->force_freq = 1;
   } else {
      status = set_new_frequency(2412 * 1000UL * 1000UL);
   }

   if (status) {
      printf("Could not set frequency\n");
      return -1;
   }
   if (wiphy_device->tun_tap) {
      return start_tun_tap(argv[0], wiphy_device);
   } else {
      return start_mac80211(argv[0], wiphy_device);
   }
}

int start_mac80211(char *cmd, wiphy_device_t *wiphy_device) {
   int status;
   struct nl_cb *netlink_cb = NULL;
   void *ret_ptr = NULL;

   wiphy_device->netlink_sock = nl_socket_alloc();
   if (!wiphy_device->netlink_sock) {
      printf("nl_socket_alloc() failed\n");
      return -1;
   }


   /* connect netlink socket to generic netlink family MAC80211_HWSIM */
   status = genl_connect(wiphy_devices[0].netlink_sock);
   if (status) {
      printf("genl_connect() failed with error=%d\n", status);
      return -1;
   }

   wiphy_device->netlink_family = genl_ctrl_resolve(wiphy_devices[0].netlink_sock, "MAC80211_HWSIM");
   if (wiphy_device->netlink_family < 0) {
      printf("genl_ctrl_resolve() failed with error=%d\n", wiphy_device->netlink_family);
      printf("perhaps mac80211_hwsim.ko isn't loaded?\n");
      return -1;
   }


   /* create and set netlink_frame_callback as netlink callback */
   netlink_cb = nl_cb_alloc(NL_CB_DEFAULT);
   if (!netlink_cb) {
      printf("nl_cb_alloc() failed\n");
      return -1;
   }

   status = nl_cb_set(netlink_cb, NL_CB_MSG_IN, NL_CB_CUSTOM, netlink_frame_callback, wiphy_device);
   if (status) {
      printf("nl_cb_set() failed with error=%d\n", status);
      return -1;
   }


   /* send HWSIM_CMD_REGISTER generic netlink message */
   struct nl_msg *netlink_msg = NULL;
   netlink_msg = nlmsg_alloc();
   ret_ptr = genlmsg_put(netlink_msg, NL_AUTO_PORT, NL_AUTO_SEQ, wiphy_device->netlink_family, 0, 0, /* REGISTER */ 1, 0);
   if (!ret_ptr) {
      printf("genlmsg_put() failed\n");
      return -1;
   }

   status = nl_send_auto(wiphy_device->netlink_sock, netlink_msg);
   if (status < 0) {
      printf("nl_send_auto() failed with error=%d\n", status);
      return -1;
   }
   nlmsg_free(netlink_msg);

   printf("netlink registration complete\n");

   pthread_t rx_th;
   pthread_create(&rx_th, NULL, rx_thread, &wiphy_devices[0]);


   int i = 0;
   /* receive and dispatch netlink messages */
   while(1) {
      status = nl_recvmsgs(wiphy_device->netlink_sock, netlink_cb);
      if (status == -NLE_PERM) {
         printf("attain CAP_NET_ADMIN via `sudo setcap cap_net_admin+eip %s` "
                "or start again with sudo\n", cmd);
         return -1;
      }
      if (status != NLE_SUCCESS && status != -NLE_SEQ_MISMATCH && status != -7 && status != -8) {
         printf("nl_recvmsgs() failed with error=%d\n", status);
         return -1;
      }
   }

   return 0;
}

int start_tun_tap(char *cmd, wiphy_device_t *wiphy_device) {
   int status;
   struct ifreq ifreq;
   uint8_t payload_data[4096];
   pthread_t rx_th;

   wiphy_devices[0].tun_tap_fd = open("/dev/net/tun", O_RDWR);
   if (wiphy_devices[0].tun_tap == -EPERM) {
         printf("attain CAP_NET_ADMIN via `sudo setcap cap_net_admin+eip %s` "
                "or start again with sudo\n", cmd);
         return -1;
   } else if (wiphy_devices[0].tun_tap == -ENOENT) {
         printf("start_tun_tap() failed with error=%d\n", wiphy_device->netlink_family);
         printf("perhaps tun.ko isn't loaded?\n");
   }

   memset(&ifreq, 0, sizeof(ifreq));
   ifreq.ifr_flags = IFF_TAP | IFF_NO_PI;
   strncpy(ifreq.ifr_name, "bladelan", IFNAMSIZ);
   status = ioctl(wiphy_device->tun_tap_fd, TUNSETIFF, &ifreq);

   if (status) {
      printf("could not ioctl(TUNSETIFF), error=%d\n", status);
      close(wiphy_device->tun_tap_fd);
      return -1;
   }

   printf("Registered `%s' TAP interface\n", ifreq.ifr_name);

   pthread_create(&rx_th, NULL, rx_thread, NULL);

   while(1) {
      status = read(wiphy_device->tun_tap_fd, payload_data, 4096);
      if (status < 0) {
         return -1;
      }

      if (debug_mode) {
         printf("TAP TX frame:\n");
         printf("\tMod: %d\n", wiphy_devices[0].tx_mod);
         dump_packet(payload_data, status);
         printf("\n\n");
      }

      status = bladerf_tx_frame(payload_data, status, wiphy_devices[0].tx_mod, 0);
      if (status < 0) {
         return -1;
      }
   }

   return 0;
}
