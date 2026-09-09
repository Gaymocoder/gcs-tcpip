#include "gcstcpip/gcs_ipv4.h"
#include "gcstcpip/gcs_checksum.h"

bool gcs_ipv4_header_parse (const uint8_t *data, size_t len, gcs_ipv4_header_t *_return)
{
    if (data == NULL || _return == NULL || len < GCS_IPV4_MIN_HDR_LEN)
    {
        return false;
    }

    uint8_t version = (uint8_t) (data [0] >> 4);
    uint8_t ihl     = (uint8_t) ((data [0] & 0x0F) * 4);

    if (version != GCS_IPV4_VERSION || ihl < GCS_IPV4_MIN_HDR_LEN || ihl > len)
    {
        return false;
    }

    uint16_t total_len = gcs_rd16be (data + 2);

    /* Кадр может быть дополнен до 60 байт, поэтому total_len <= len. */
    if (total_len < ihl || total_len > len)
    {
        return false;
    }

    _return->version    = version;
    _return->ihl        = ihl;
    _return->dscp_ecn   = data [1];
    _return->total_len  = total_len;
    _return->id         = gcs_rd16be (data + 4);
    _return->flags_frag = gcs_rd16be (data + 6);
    _return->ttl        = data [8];
    _return->protocol   = data [9];
    _return->checksum   = gcs_rd16be (data + 10);
    _return->src        = gcs_rd32be (data + 12);
    _return->dst        = gcs_rd32be (data + 16);

    _return->payload     = data + ihl;
    _return->payload_len = (size_t) (total_len - ihl);

    return true;
}

bool gcs_ipv4_checksum_valid (const uint8_t *data, size_t ihl)
{
    if (data == NULL || ihl < GCS_IPV4_MIN_HDR_LEN)
    {
        return false;
    }

    /* Сумма всего заголовка вместе с полем checksum должна давать ноль. */
    return gcs_checksum (data, ihl) == 0;
}

bool gcs_ipv4_write_header (uint8_t *out, size_t cap, gcs_ipv4_t src, gcs_ipv4_t dst,
                            uint8_t protocol, uint16_t payload_len, uint16_t id, uint8_t ttl)
{
    if (out == NULL || cap < GCS_IPV4_MIN_HDR_LEN)
    {
        return false;
    }

    out [0] = (uint8_t) ((GCS_IPV4_VERSION << 4) | (GCS_IPV4_MIN_HDR_LEN / 4));
    out [1] = 0;
    gcs_wr16be (out + 2, (uint16_t) (GCS_IPV4_MIN_HDR_LEN + payload_len));
    gcs_wr16be (out + 4, id);
    gcs_wr16be (out + 6, GCS_IPV4_FLAG_DF);
    out [8] = ttl;
    out [9] = protocol;
    gcs_wr16be (out + 10, 0);
    gcs_wr32be (out + 12, src);
    gcs_wr32be (out + 16, dst);

    gcs_wr16be (out + 10, gcs_checksum (out, GCS_IPV4_MIN_HDR_LEN));

    return true;
}

const char *gcs_ip_proto_name (uint8_t protocol)
{
    switch (protocol)
    {
        case GCS_IP_PROTO_ICMP: return "ICMP";
        case GCS_IP_PROTO_TCP:  return "TCP";
        case GCS_IP_PROTO_UDP:  return "UDP";
        default:                return "other";
    }
}
