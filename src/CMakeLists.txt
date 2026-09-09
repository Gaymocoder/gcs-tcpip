project(GCS_TcpIp_Library LANGUAGES C)

set(GCS_TCPIP_SOURCES
    gcs_types.c
    gcs_checksum.c
    gcs_ethernet.c
    gcs_arp.c
    gcs_ipv4.c
    gcs_icmp.c
    gcs_tcp.c
    gcs_pcap.c
    gcs_stack.c)

# TAP опирается на linux/if_tun.h и существует только под Linux.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND GCS_TCPIP_SOURCES gcs_tap.c)
endif()

add_library(gcsll_tcpip STATIC ${GCS_TCPIP_SOURCES})

gcst_export_prepare(gcsll_tcpip)
gcs_target_c_tuning(gcsll_tcpip)
