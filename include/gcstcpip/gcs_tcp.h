#ifndef __GCSTCPIP_TCP_H__
#define __GCSTCPIP_TCP_H__

#include "gcstcpip/gcs_ipv4.h"

#define GCS_TCP_MIN_HDR_LEN 20

#define GCS_TCP_FIN 0x01u
#define GCS_TCP_SYN 0x02u
#define GCS_TCP_RST 0x04u
#define GCS_TCP_PSH 0x08u
#define GCS_TCP_ACK 0x10u
#define GCS_TCP_URG 0x20u

typedef enum
{
    GCS_TCP_CLOSED = 0,
    GCS_TCP_LISTEN,
    GCS_TCP_SYN_RECEIVED,
    GCS_TCP_ESTABLISHED,
    GCS_TCP_CLOSE_WAIT,
    GCS_TCP_LAST_ACK
} gcs_tcp_state_t;

typedef struct
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;      /* в байтах */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
    const uint8_t *payload;
    size_t         payload_len;
} gcs_tcp_header_t;

typedef struct
{
    gcs_tcp_state_t state;
    gcs_ipv4_t      local_ip;
    gcs_ipv4_t      remote_ip;
    uint16_t        local_port;
    uint16_t        remote_port;
    uint32_t        snd_nxt;
    uint32_t        rcv_nxt;
    uint32_t        iss;
    uint64_t        bytes_received;
} gcs_tcp_connection_t;

bool gcs_tcp_parse (const uint8_t *data, size_t len, gcs_tcp_header_t *_return);

bool gcs_tcp_checksum_valid (const gcs_ipv4_header_t *ip, const uint8_t *seg, size_t seg_len);

/* Собирает сегмент с заголовком и полезной нагрузкой, считает контрольную сумму. */
size_t gcs_tcp_build_segment (uint8_t *out, size_t cap,
                              gcs_ipv4_t src_ip, gcs_ipv4_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              uint32_t seq, uint32_t ack, uint8_t flags,
                              uint16_t window, const uint8_t *payload, size_t payload_len);

void        gcs_tcp_connection_init (gcs_tcp_connection_t *conn, gcs_ipv4_t local_ip, uint16_t local_port);
const char *gcs_tcp_state_name (gcs_tcp_state_t state);
void        gcs_tcp_flags_format (uint8_t flags, char *_return, size_t cap);

#endif /* __GCSTCPIP_TCP_H__ */
