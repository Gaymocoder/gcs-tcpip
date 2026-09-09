#include "gcstcpip/gcs_icmp.h"
#include "gcstcpip/gcs_checksum.h"

#include <string.h>

bool gcs_icmp_parse_echo (const uint8_t *data, size_t len, gcs_icmp_echo_t *_return)
{
    if (data == NULL || _return == NULL || len < GCS_ICMP_HDR_LEN)
    {
        return false;
    }

    if (gcs_checksum (data, len) != 0)
    {
        return false;
    }

    _return->type     = data [0];
    _return->code     = data [1];
    _return->checksum = gcs_rd16be (data + 2);
    _return->id       = gcs_rd16be (data + 4);
    _return->seq      = gcs_rd16be (data + 6);

    _return->payload     = data + GCS_ICMP_HDR_LEN;
    _return->payload_len = len - GCS_ICMP_HDR_LEN;

    return true;
}

size_t gcs_icmp_build_echo_reply (uint8_t *out, size_t cap, const gcs_icmp_echo_t *request)
{
    if (out == NULL || request == NULL)
    {
        return 0;
    }

    size_t total = GCS_ICMP_HDR_LEN + request->payload_len;

    if (cap < total)
    {
        return 0;
    }

    out [0] = GCS_ICMP_TYPE_ECHO_REPLY;
    out [1] = 0;
    gcs_wr16be (out + 2, 0);
    gcs_wr16be (out + 4, request->id);
    gcs_wr16be (out + 6, request->seq);

    if (request->payload_len > 0)
    {
        memcpy (out + GCS_ICMP_HDR_LEN, request->payload, request->payload_len);
    }

    gcs_wr16be (out + 2, gcs_checksum (out, total));

    return total;
}

const char *gcs_icmp_type_name (uint8_t type)
{
    switch (type)
    {
        case GCS_ICMP_TYPE_ECHO_REPLY:   return "echo-reply";
        case GCS_ICMP_TYPE_ECHO_REQUEST: return "echo-request";
        default:                         return "other";
    }
}
