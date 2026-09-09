#include "gcstcpip/gcs_arp.h"

#include <string.h>

bool gcs_arp_parse (const uint8_t *data, size_t len, gcs_arp_packet_t *_return)
{
    if (data == NULL || _return == NULL || len < GCS_ARP_HDR_LEN)
    {
        return false;
    }

    _return->hw_type    = gcs_rd16be (data);
    _return->proto_type = gcs_rd16be (data + 2);
    _return->hw_len     = data [4];
    _return->proto_len  = data [5];
    _return->opcode     = gcs_rd16be (data + 6);

    /* Поддерживаем только Ethernet/IPv4. */
    if (_return->hw_len != GCS_MAC_LEN || _return->proto_len != 4)
    {
        return false;
    }

    memcpy (_return->sender_mac.addr, data + 8, GCS_MAC_LEN);
    _return->sender_ip = gcs_rd32be (data + 14);
    memcpy (_return->target_mac.addr, data + 18, GCS_MAC_LEN);
    _return->target_ip = gcs_rd32be (data + 24);

    return true;
}

bool gcs_arp_write (gcs_buf_t *buf, const gcs_arp_packet_t *pkt)
{
    if (buf == NULL || buf->data == NULL || pkt == NULL || buf->cap < GCS_ARP_HDR_LEN)
    {
        return false;
    }

    gcs_wr16be (buf->data, pkt->hw_type);
    gcs_wr16be (buf->data + 2, pkt->proto_type);
    buf->data [4] = pkt->hw_len;
    buf->data [5] = pkt->proto_len;
    gcs_wr16be (buf->data + 6, pkt->opcode);

    memcpy (buf->data + 8, pkt->sender_mac.addr, GCS_MAC_LEN);
    gcs_wr32be (buf->data + 14, pkt->sender_ip);
    memcpy (buf->data + 18, pkt->target_mac.addr, GCS_MAC_LEN);
    gcs_wr32be (buf->data + 24, pkt->target_ip);

    buf->len = GCS_ARP_HDR_LEN;
    return true;
}

const char *gcs_arp_opcode_name (uint16_t opcode)
{
    switch (opcode)
    {
        case GCS_ARP_OP_REQUEST: return "request";
        case GCS_ARP_OP_REPLY:   return "reply";
        default:                 return "unknown";
    }
}
