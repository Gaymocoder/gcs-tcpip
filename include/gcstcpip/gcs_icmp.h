#ifndef __GCSTCPIP_ICMP_H__
#define __GCSTCPIP_ICMP_H__

#include "gcstcpip/gcs_ipv4.h"

#define GCS_ICMP_HDR_LEN        8
#define GCS_ICMP_TYPE_ECHO_REPLY   0
#define GCS_ICMP_TYPE_ECHO_REQUEST 8

typedef struct
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
    const uint8_t *payload;
    size_t         payload_len;
} gcs_icmp_echo_t;

bool gcs_icmp_parse_echo (const uint8_t *data, size_t len, gcs_icmp_echo_t *_return);

/* Формирует echo reply из разобранного запроса. Возвращает длину ICMP-сообщения. */
size_t gcs_icmp_build_echo_reply (uint8_t *out, size_t cap, const gcs_icmp_echo_t *request);

const char *gcs_icmp_type_name (uint8_t type);

#endif /* __GCSTCPIP_ICMP_H__ */
