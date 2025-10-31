
## Building

```shell
mkdir build
cd build
cmake ..
make
```

## Load Kernel Modules

```shell
modprobe mac80211
modprobe cfg80211
insmod /lib/modules/$(uname -r)/internal/drivers/net/wireless/virtual/mac80211_hwsim.ko.xz 
```

## Running

```shell
sudo ./bladeRF-wiphy
```