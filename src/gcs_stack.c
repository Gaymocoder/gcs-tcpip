#include "gcstcpip/gcs_stack.h"
#include "gcstcpip/gcs_checksum.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define GCS_TCP_WINDOW 4096

GCS_PRINTF (2, 3)
static void gcs_log (const gcs_stack_t *stack, const char *fmt, ...)
{
    if (!stack->verbose)
    {
        return;
    }

    va_list ap;
    va_start (ap, fmt);
    vfprintf (stdout, fmt, ap);
    va_end (ap);
}

void gcs_stack_init (gcs_stack_t *stack, const gcs_mac_t *mac, gcs_ipv4_t ip, uint16_t listen_port)
{
    memset (stack, 0, sizeof (*stack));

    stack->mac     = *mac;
    stack->ip      = ip;
    stack->verbose = true;
    stack->ip_id   = 1;

    gcs_tcp_connection_init (&stack->conn, ip, listen_port);
}

/* --- ARP --- */

static size_t gcs_stack_handle_arp (gcs_stack_t *stack, const gcs_eth_frame_t *eth,
                                    uint8_t *out, size_t out_cap)
{
    gcs_arp_packet_t req;

    if (!gcs_arp_parse (eth->payload, eth->payload_len, &req))
    {
        return 0;
    }

    char sip [16];
    char tip [16];
    char smac [18];
    gcs_ipv4_format (req.sender_ip, sip, sizeof (sip));
    gcs_ipv4_format (req.target_ip, tip, sizeof (tip));
    gcs_mac_format (&req.sender_mac, smac, sizeof (smac));

    gcs_log (stack, "  ARP %s: who-has %s tell %s (%s)\n",
             gcs_arp_opcode_name (req.opcode), tip, sip, smac);


    if (req.opcode != GCS_ARP_OP_REQUEST)
    {
        return 0;
    }


    if (req.target_ip != stack->ip)
    {
        gcs_log (stack, "  ARP: не наш адрес, игнорируем\n");
        return 0;
    }

    if (out_cap < GCS_ETH_HDR_LEN + GCS_ARP_HDR_LEN)
    {
        return 0;
    }

    gcs_buf_t frame = { out, 0, out_cap };
    gcs_eth_write_header (&frame, &req.sender_mac, &stack->mac, GCS_ETHERTYPE_ARP);

    gcs_arp_packet_t reply;
    reply.hw_type    = GCS_ARP_HW_ETHERNET;
    reply.proto_type = GCS_ETHERTYPE_IPV4;
    reply.hw_len     = GCS_MAC_LEN;
    reply.proto_len  = 4;
    reply.opcode     = GCS_ARP_OP_REPLY;
    reply.sender_mac = stack->mac;
    reply.sender_ip  = stack->ip;
    reply.target_mac = req.sender_mac;
    reply.target_ip  = req.sender_ip;

    gcs_buf_t body = { out + GCS_ETH_HDR_LEN, 0, out_cap - GCS_ETH_HDR_LEN };
    gcs_arp_write (&body, &reply);

    gcs_log (stack, "  -> ARP reply: %s is-at ", tip);

    char omac [18];
    gcs_mac_format (&stack->mac, omac, sizeof (omac));
    gcs_log (stack, "%s\n", omac);

    return GCS_ETH_HDR_LEN + GCS_ARP_HDR_LEN;
}

/* --- ICMP --- */

static size_t gcs_stack_handle_icmp (gcs_stack_t *stack, const gcs_eth_frame_t *eth,
                                     const gcs_ipv4_header_t *ip,
                                     uint8_t *out, size_t out_cap)
{
    gcs_icmp_echo_t echo;

    if (!gcs_icmp_parse_echo (ip->payload, ip->payload_len, &echo))
    {
        gcs_log (stack, "  ICMP: битая контрольная сумма, отбрасываем\n");
        return 0;
    }

    gcs_log (stack, "  ICMP %s id=%u seq=%u len=%zu\n",
             gcs_icmp_type_name (echo.type), echo.id, echo.seq, echo.payload_len);

    if (echo.type != GCS_ICMP_TYPE_ECHO_REQUEST || ip->dst != stack->ip)
    {
        return 0;
    }

    size_t icmp_off = GCS_ETH_HDR_LEN + GCS_IPV4_MIN_HDR_LEN;

    if (out_cap < icmp_off + GCS_ICMP_HDR_LEN + echo.payload_len)
    {
        return 0;
    }

    size_t icmp_len = gcs_icmp_build_echo_reply (out + icmp_off, out_cap - icmp_off, &echo);

    if (icmp_len == 0)
    {
        return 0;
    }

    gcs_ipv4_write_header (out + GCS_ETH_HDR_LEN, out_cap - GCS_ETH_HDR_LEN,
                           stack->ip, ip->src, GCS_IP_PROTO_ICMP,
                           (uint16_t) icmp_len, stack->ip_id++, 64);

    gcs_buf_t frame = { out, 0, out_cap };
    gcs_eth_write_header (&frame, &eth->src, &stack->mac, GCS_ETHERTYPE_IPV4);

    gcs_log (stack, "  -> ICMP echo-reply id=%u seq=%u\n", echo.id, echo.seq);

    return icmp_off + icmp_len;
}

/* --- TCP --- */

static size_t gcs_stack_emit_tcp (gcs_stack_t *stack, const gcs_eth_frame_t *eth,
                                  const gcs_ipv4_header_t *ip, const gcs_tcp_header_t *tcp,
                                  uint32_t seq, uint32_t ack, uint8_t flags,
                                  const uint8_t *payload, size_t payload_len,
                                  uint8_t *out, size_t out_cap)
{
    size_t tcp_off = GCS_ETH_HDR_LEN + GCS_IPV4_MIN_HDR_LEN;

    if (out_cap < tcp_off + GCS_TCP_MIN_HDR_LEN + payload_len)
    {
        return 0;
    }

    size_t seg_len = gcs_tcp_build_segment (out + tcp_off, out_cap - tcp_off,
                                            stack->ip, ip->src,
                                            tcp->dst_port, tcp->src_port,
                                            seq, ack, flags, GCS_TCP_WINDOW,
                                            payload, payload_len);

    if (seg_len == 0)
    {
        return 0;
    }

    gcs_ipv4_write_header (out + GCS_ETH_HDR_LEN, out_cap - GCS_ETH_HDR_LEN,
                           stack->ip, ip->src, GCS_IP_PROTO_TCP,
                           (uint16_t) seg_len, stack->ip_id++, 64);

    gcs_buf_t frame = { out, 0, out_cap };
    gcs_eth_write_header (&frame, &eth->src, &stack->mac, GCS_ETHERTYPE_IPV4);

    char fl [8];
    gcs_tcp_flags_format (flags, fl, sizeof (fl));
    gcs_log (stack, "  -> TCP [%s] seq=%u ack=%u len=%zu\n", fl, seq, ack, payload_len);

    return tcp_off + seg_len;
}

static size_t gcs_stack_handle_tcp (gcs_stack_t *stack, const gcs_eth_frame_t *eth,
                                    const gcs_ipv4_header_t *ip,
                                    uint8_t *out, size_t out_cap)
{
    gcs_tcp_header_t tcp;

    if (!gcs_tcp_parse (ip->payload, ip->payload_len, &tcp))
    {
        return 0;
    }

    if (!gcs_tcp_checksum_valid (ip, ip->payload, ip->payload_len))
    {
        gcs_log (stack, "  TCP: битая контрольная сумма, отбрасываем\n");
        return 0;
    }


    char fl [8];
    gcs_tcp_flags_format (tcp.flags, fl, sizeof (fl));
    gcs_log (stack, "  TCP %u -> %u [%s] seq=%u ack=%u len=%zu  состояние=%s\n",
             tcp.src_port, tcp.dst_port, fl, tcp.seq, tcp.ack, tcp.payload_len,
             gcs_tcp_state_name (stack->conn.state));

    gcs_tcp_connection_t *c = &stack->conn;

    if (tcp.dst_port != c->local_port)
    {
        gcs_log (stack, "  TCP: порт закрыт, шлём RST\n");
        return gcs_stack_emit_tcp (stack, eth, ip, &tcp,
                                   tcp.ack, tcp.seq + 1, GCS_TCP_RST | GCS_TCP_ACK,
                                   NULL, 0, out, out_cap);
    }

    switch (c->state)
    {
        case GCS_TCP_LISTEN:
        {
            if ((tcp.flags & GCS_TCP_SYN) == 0)
            {
                return 0;
            }

            c->remote_ip   = ip->src;
            c->remote_port = tcp.src_port;
            c->rcv_nxt     = tcp.seq + 1;
            c->snd_nxt     = c->iss + 1;
            c->state       = GCS_TCP_SYN_RECEIVED;

            gcs_log (stack, "  состояние: LISTEN -> SYN_RECEIVED\n");

            return gcs_stack_emit_tcp (stack, eth, ip, &tcp,
                                       c->iss, c->rcv_nxt, GCS_TCP_SYN | GCS_TCP_ACK,
                                       NULL, 0, out, out_cap);
        }

        case GCS_TCP_SYN_RECEIVED:
        {
            if ((tcp.flags & GCS_TCP_ACK) == 0)
            {
                return 0;
            }

            c->state = GCS_TCP_ESTABLISHED;
            gcs_log (stack, "  состояние: SYN_RECEIVED -> ESTABLISHED\n");
            return 0;
        }

        case GCS_TCP_ESTABLISHED:
        {
            if (tcp.flags & GCS_TCP_FIN)
            {
                c->rcv_nxt = tcp.seq + 1;
                c->state   = GCS_TCP_LAST_ACK;
                gcs_log (stack, "  состояние: ESTABLISHED -> LAST_ACK (получен FIN)\n");

                return gcs_stack_emit_tcp (stack, eth, ip, &tcp,
                                           c->snd_nxt, c->rcv_nxt,
                                           GCS_TCP_FIN | GCS_TCP_ACK,
                                           NULL, 0, out, out_cap);
            }

            if (tcp.payload_len == 0)
            {
                return 0;
            }

            c->rcv_nxt        = tcp.seq + (uint32_t) tcp.payload_len;
            c->bytes_received += tcp.payload_len;

            gcs_log (stack, "  данные (%zu Б), эхо обратно\n", tcp.payload_len);

            size_t frame_len = gcs_stack_emit_tcp (stack, eth, ip, &tcp,
                                                   c->snd_nxt, c->rcv_nxt,
                                                   GCS_TCP_ACK | GCS_TCP_PSH,
                                                   tcp.payload, tcp.payload_len,
                                                   out, out_cap);
            c->snd_nxt += (uint32_t) tcp.payload_len;
            return frame_len;
        }

        case GCS_TCP_LAST_ACK:
        {
            if (tcp.flags & GCS_TCP_ACK)
            {
                c->state = GCS_TCP_CLOSED;
                gcs_log (stack, "  состояние: LAST_ACK -> CLOSED\n");
            }

            return 0;
        }

        case GCS_TCP_CLOSED:
        case GCS_TCP_CLOSE_WAIT:
        default:
            return 0;
    }
}

/* --- точка входа --- */

size_t gcs_stack_handle_frame (gcs_stack_t *stack, const uint8_t *frame, size_t len,
                               uint8_t *out, size_t out_cap)
{
    gcs_eth_frame_t eth;


    if (!gcs_eth_parse (frame, len, &eth))
    {
        return 0;
    }

    char dmac [18];
    char smac [18];
    gcs_mac_format (&eth.dst, dmac, sizeof (dmac));
    gcs_mac_format (&eth.src, smac, sizeof (smac));

    gcs_log (stack, "  Ethernet %s -> %s  тип=0x%04x (%s)\n",
             smac, dmac, eth.ethertype, gcs_ethertype_name (eth.ethertype));

    /* Принимаем только свой юникаст и широковещательные кадры. */
    if (!gcs_mac_equal (&eth.dst, &stack->mac) && !gcs_mac_is_broadcast (&eth.dst))
    {
        gcs_log (stack, "  кадр не нам, отбрасываем\n");
        return 0;
    }

    size_t reply_len = 0;

    if (eth.ethertype == GCS_ETHERTYPE_ARP)
    {
        reply_len = gcs_stack_handle_arp (stack, &eth, out, out_cap);
    }
    else if (eth.ethertype == GCS_ETHERTYPE_IPV4)
    {
        gcs_ipv4_header_t ip;

        if (!gcs_ipv4_header_parse (eth.payload, eth.payload_len, &ip))
        {
            return 0;
        }

        if (!gcs_ipv4_checksum_valid (eth.payload, ip.ihl))
        {
            gcs_log (stack, "  IPv4: битая контрольная сумма заголовка\n");
            return 0;
        }

        char sip [16];
        char dip [16];
        gcs_ipv4_format (ip.src, sip, sizeof (sip));
        gcs_ipv4_format (ip.dst, dip, sizeof (dip));

        gcs_log (stack, "  IPv4 %s -> %s  протокол=%u (%s) ttl=%u len=%u\n",
                 sip, dip, ip.protocol, gcs_ip_proto_name (ip.protocol),
                 ip.ttl, ip.total_len);

        if (ip.protocol == GCS_IP_PROTO_ICMP)
        {
            reply_len = gcs_stack_handle_icmp (stack, &eth, &ip, out, out_cap);
        }
        else if (ip.protocol == GCS_IP_PROTO_TCP)
        {
            reply_len = gcs_stack_handle_tcp (stack, &eth, &ip, out, out_cap);
        }
        else
        {
            gcs_log (stack, "  протокол не поддержан\n");
        }
    }
    else
    {
        gcs_log (stack, "  ethertype не поддержан\n");
    }

    if (reply_len > 0)
    {
    }

    return reply_len;
}

