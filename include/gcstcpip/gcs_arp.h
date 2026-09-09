#ifndef __GCSTCPIP_ARP_H__
#define __GCSTCPIP_ARP_H__

#include "gcstcpip/gcs_ethernet.h"

#define GCS_ARP_HDR_LEN     28
#define GCS_ARP_HW_ETHERNET 1
#define GCS_ARP_OP_REQUEST  1
#define GCS_ARP_OP_REPLY    2

typedef struct
{
    uint16_t  hw_type;
    uint16_t  proto_type;
    uint8_t   hw_len;
    uint8_t   proto_len;
    uint16_t  opcode;
    gcs_mac_t sender_mac;
    gcs_ipv4_t sender_ip;
    gcs_mac_t target_mac;
    gcs_ipv4_t target_ip;
} gcs_arp_packet_t;

bool gcs_arp_parse (const uint8_t *data, size_t len, gcs_arp_packet_t *_return);
bool gcs_arp_write (gcs_buf_t *buf, const gcs_arp_packet_t *pkt);

const char *gcs_arp_opcode_name (uint16_t opcode);

#endif /* __GCSTCPIP_ARP_H__ */
