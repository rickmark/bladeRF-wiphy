cmake_minimum_required(VERSION 3.10)
project(bladeRF-linux-mac80211 C)

# Find pkg-config
find_package(PkgConfig REQUIRED)

# Find required packages
pkg_check_modules(NL_GENL REQUIRED libnl-genl-3.0)
pkg_check_modules(BLADERF REQUIRED libbladeRF)
pkg_check_modules(PCAP REQUIRED libpcap)

# Find pthread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Create executable
add_executable(bladeRF-wiphy bladeRF-linux-mac80211.c)

# Set compile options
target_compile_options(bladeRF-wiphy PRIVATE -g3)

# Link libraries
target_include_directories(bladeRF-wiphy PRIVATE
    ${NL_GENL_INCLUDE_DIRS}
    ${BLADERF_INCLUDE_DIRS}
    ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(bladeRF-wiphy PRIVATE
    ${NL_GENL_LIBRARIES}
    ${BLADERF_LIBRARIES}
    ${PCAP_LIBRARIES}
    Threads::Threads
)

target_link_directories(bladeRF-wiphy PRIVATE
    ${NL_GENL_LIBRARY_DIRS}
    ${BLADERF_LIBRARY_DIRS}
)