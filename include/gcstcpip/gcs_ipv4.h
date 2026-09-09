#ifndef __GCSTCPIP_IPV4_H__
#define __GCSTCPIP_IPV4_H__

#include "gcstcpip/gcs_types.h"

#define GCS_IPV4_MIN_HDR_LEN 20
#define GCS_IPV4_VERSION      4

#define GCS_IP_PROTO_ICMP  1
#define GCS_IP_PROTO_TCP   6
#define GCS_IP_PROTO_UDP  17

#define GCS_IPV4_FLAG_DF 0x4000u
#define GCS_IPV4_FLAG_MF 0x2000u

typedef struct
{
    uint8_t    version;
    uint8_t    ihl;            /* в байтах, уже умножено на 4 */
    uint8_t    dscp_ecn;
    uint16_t   total_len;
    uint16_t   id;
    uint16_t   flags_frag;
    uint8_t    ttl;
    uint8_t    protocol;
    uint16_t   checksum;
    gcs_ipv4_t src;
    gcs_ipv4_t dst;
    const uint8_t *payload;
    size_t         payload_len;
} gcs_ipv4_header_t;

bool gcs_ipv4_header_parse (const uint8_t *data, size_t len, gcs_ipv4_header_t *_return);

/* Проверяет контрольную сумму заголовка. */
bool gcs_ipv4_checksum_valid (const uint8_t *data, size_t ihl);

/* Пишет 20-байтовый заголовок и проставляет контрольную сумму. */
bool gcs_ipv4_write_header (uint8_t *out, size_t cap, gcs_ipv4_t src, gcs_ipv4_t dst,
                            uint8_t protocol, uint16_t payload_len, uint16_t id, uint8_t ttl);

const char *gcs_ip_proto_name (uint8_t protocol);

#endif /* __GCSTCPIP_IPV4_H__ */
