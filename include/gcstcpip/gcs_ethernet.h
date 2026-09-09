#ifndef __GCSTCPIP_ETHERNET_H__
#define __GCSTCPIP_ETHERNET_H__

#include "gcstcpip/gcs_types.h"

#define GCS_ETH_HDR_LEN   14
#define GCS_ETH_MIN_FRAME 60

#define GCS_ETHERTYPE_IPV4 0x0800u
#define GCS_ETHERTYPE_ARP  0x0806u

typedef struct
{
    gcs_mac_t dst;
    gcs_mac_t src;
    uint16_t  ethertype;
    const uint8_t *payload;
    size_t         payload_len;
} gcs_eth_frame_t;

bool gcs_eth_parse (const uint8_t *data, size_t len, gcs_eth_frame_t *_return);

/* Пишет заголовок в начало buf->data, полезная нагрузка должна уже лежать следом. */
bool gcs_eth_write_header (gcs_buf_t *buf, const gcs_mac_t *dst,
                           const gcs_mac_t *src, uint16_t ethertype);

const char *gcs_ethertype_name (uint16_t ethertype);

#endif /* __GCSTCPIP_ETHERNET_H__ */
