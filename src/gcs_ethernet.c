#include "gcstcpip/gcs_ethernet.h"

#include <string.h>

bool gcs_eth_parse (const uint8_t *data, size_t len, gcs_eth_frame_t *_return)
{
    if (data == NULL || _return == NULL || len < GCS_ETH_HDR_LEN)
    {
        return false;
    }

    memcpy (_return->dst.addr, data, GCS_MAC_LEN);
    memcpy (_return->src.addr, data + GCS_MAC_LEN, GCS_MAC_LEN);

    _return->ethertype   = gcs_rd16be (data + 12);
    _return->payload     = data + GCS_ETH_HDR_LEN;
    _return->payload_len = len - GCS_ETH_HDR_LEN;

    return true;
}

bool gcs_eth_write_header (gcs_buf_t *buf, const gcs_mac_t *dst,
                           const gcs_mac_t *src, uint16_t ethertype)
{
    if (buf == NULL || buf->data == NULL || buf->cap < GCS_ETH_HDR_LEN)
    {
        return false;
    }

    memcpy (buf->data, dst->addr, GCS_MAC_LEN);
    memcpy (buf->data + GCS_MAC_LEN, src->addr, GCS_MAC_LEN);
    gcs_wr16be (buf->data + 12, ethertype);

    return true;
}

const char *gcs_ethertype_name (uint16_t ethertype)
{
    switch (ethertype)
    {
        case GCS_ETHERTYPE_IPV4: return "IPv4";
        case GCS_ETHERTYPE_ARP:  return "ARP";
        default:                 return "unknown";
    }
}
