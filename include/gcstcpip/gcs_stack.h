#ifndef __GCSTCPIP_STACK_H__
#define __GCSTCPIP_STACK_H__

#include "gcstcpip/gcs_arp.h"
#include "gcstcpip/gcs_icmp.h"
#include "gcstcpip/gcs_tcp.h"

#include <stdio.h>

#define GCS_STACK_MTU        1500
#define GCS_STACK_FRAME_CAP  (GCS_STACK_MTU + GCS_ETH_HDR_LEN)

typedef struct
{
    gcs_mac_t            mac;
    gcs_ipv4_t           ip;
    gcs_tcp_connection_t conn;
    bool                 verbose;
    uint16_t             ip_id;
} gcs_stack_t;

void gcs_stack_init (gcs_stack_t *stack, const gcs_mac_t *mac, gcs_ipv4_t ip, uint16_t listen_port);

/* Обрабатывает входящий кадр. Если нужен ответ, кладёт его в out и возвращает длину. */
size_t gcs_stack_handle_frame (gcs_stack_t *stack, const uint8_t *frame, size_t len,
                               uint8_t *out, size_t out_cap);

#endif /* __GCSTCPIP_STACK_H__ */
