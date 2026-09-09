#include "gcstcpip/gcs_checksum.h"

uint16_t gcs_checksum_finish (uint32_t sum)
{
    while ((sum >> 16) != 0)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t) (~sum & 0xFFFF);
}

uint16_t gcs_checksum_accum (const uint8_t *data, size_t len, uint32_t seed)
{
    uint32_t sum = seed;
    size_t   i   = 0;

    while (i + 1 < len)
    {
        sum += gcs_rd16be (data + i);
        i   += 2;
    }

    /* Нечётный хвост дополняется нулевым байтом справа. */
    if (i < len)
    {
        sum += (uint32_t) data [i] << 8;
    }

    return gcs_checksum_finish (sum);
}

uint16_t gcs_checksum (const uint8_t *data, size_t len)
{
    return gcs_checksum_accum (data, len, 0);
}

uint32_t gcs_pseudo_header_sum (gcs_ipv4_t src, gcs_ipv4_t dst,
                                uint8_t protocol, uint16_t l4_len)
{
    uint32_t sum = 0;

    sum += (src >> 16) & 0xFFFF;
    sum += src & 0xFFFF;
    sum += (dst >> 16) & 0xFFFF;
    sum += dst & 0xFFFF;
    sum += (uint32_t) protocol;
    sum += (uint32_t) l4_len;

    return sum;
}
