#include "gcstcpip/gcs_tcp.h"
#include "gcstcpip/gcs_checksum.h"

#include <stdio.h>
#include <string.h>

bool gcs_tcp_parse (const uint8_t *data, size_t len, gcs_tcp_header_t *_return)
{
    if (data == NULL || _return == NULL || len < GCS_TCP_MIN_HDR_LEN)
    {
        return false;
    }

    uint8_t data_offset = (uint8_t) ((data [12] >> 4) * 4);

    if (data_offset < GCS_TCP_MIN_HDR_LEN || data_offset > len)
    {
        return false;
    }

    _return->src_port    = gcs_rd16be (data);
    _return->dst_port    = gcs_rd16be (data + 2);
    _return->seq         = gcs_rd32be (data + 4);
    _return->ack         = gcs_rd32be (data + 8);
    _return->data_offset = data_offset;
    _return->flags       = (uint8_t) (data [13] & 0x3F);
    _return->window      = gcs_rd16be (data + 14);
    _return->checksum    = gcs_rd16be (data + 16);
    _return->urgent      = gcs_rd16be (data + 18);

    _return->payload     = data + data_offset;
    _return->payload_len = len - data_offset;

    return true;
}

bool gcs_tcp_checksum_valid (const gcs_ipv4_header_t *ip, const uint8_t *seg, size_t seg_len)
{
    if (ip == NULL || seg == NULL || seg_len < GCS_TCP_MIN_HDR_LEN)
    {
        return false;
    }

    uint32_t seed = gcs_pseudo_header_sum (ip->src, ip->dst, GCS_IP_PROTO_TCP,
                                           (uint16_t) seg_len);

    return gcs_checksum_accum (seg, seg_len, seed) == 0;
}

size_t gcs_tcp_build_segment (uint8_t *out, size_t cap,
                              gcs_ipv4_t src_ip, gcs_ipv4_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              uint32_t seq, uint32_t ack, uint8_t flags,
                              uint16_t window, const uint8_t *payload, size_t payload_len)
{
    size_t total = GCS_TCP_MIN_HDR_LEN + payload_len;

    if (out == NULL || cap < total)
    {
        return 0;
    }

    gcs_wr16be (out, src_port);
    gcs_wr16be (out + 2, dst_port);
    gcs_wr32be (out + 4, seq);
    gcs_wr32be (out + 8, ack);
    out [12] = (uint8_t) ((GCS_TCP_MIN_HDR_LEN / 4) << 4);
    out [13] = flags;
    gcs_wr16be (out + 14, window);
    gcs_wr16be (out + 16, 0);
    gcs_wr16be (out + 18, 0);

    if (payload_len > 0 && payload != NULL)
    {
        memcpy (out + GCS_TCP_MIN_HDR_LEN, payload, payload_len);
    }

    uint32_t seed = gcs_pseudo_header_sum (src_ip, dst_ip, GCS_IP_PROTO_TCP,
                                           (uint16_t) total);
    gcs_wr16be (out + 16, gcs_checksum_accum (out, total, seed));

    return total;
}

void gcs_tcp_connection_init (gcs_tcp_connection_t *conn, gcs_ipv4_t local_ip, uint16_t local_port)
{
    memset (conn, 0, sizeof (*conn));

    conn->state      = GCS_TCP_LISTEN;
    conn->local_ip   = local_ip;
    conn->local_port = local_port;
    /* Фиксированный ISS: воспроизводимость важнее непредсказуемости в учебном стеке. */
    conn->iss        = 0x00C0FFEEu;
}

const char *gcs_tcp_state_name (gcs_tcp_state_t state)
{
    switch (state)
    {
        case GCS_TCP_CLOSED:       return "CLOSED";
        case GCS_TCP_LISTEN:       return "LISTEN";
        case GCS_TCP_SYN_RECEIVED: return "SYN_RECEIVED";
        case GCS_TCP_ESTABLISHED:  return "ESTABLISHED";
        case GCS_TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
        case GCS_TCP_LAST_ACK:     return "LAST_ACK";
        default:                   return "?";
    }
}

void gcs_tcp_flags_format (uint8_t flags, char *_return, size_t cap)
{
    if (_return == NULL || cap == 0)
    {
        return;
    }

    snprintf (_return, cap, "%s%s%s%s%s%s",
              (flags & GCS_TCP_URG) ? "U" : "",
              (flags & GCS_TCP_ACK) ? "A" : "",
              (flags & GCS_TCP_PSH) ? "P" : "",
              (flags & GCS_TCP_RST) ? "R" : "",
              (flags & GCS_TCP_SYN) ? "S" : "",
              (flags & GCS_TCP_FIN) ? "F" : "");

    if (_return [0] == '\0' && cap > 1)
    {
        _return [0] = '-';
        _return [1] = '\0';
    }
}
