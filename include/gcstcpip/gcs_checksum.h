#ifndef __GCSTCPIP_CHECKSUM_H__
#define __GCSTCPIP_CHECKSUM_H__

#include "gcstcpip/gcs_types.h"

/* Контрольная сумма по RFC 1071: сумма 16-битных слов в дополнении до единицы. */
uint16_t gcs_checksum        (const uint8_t *data, size_t len);
uint16_t gcs_checksum_accum  (const uint8_t *data, size_t len, uint32_t seed);
uint16_t gcs_checksum_finish (uint32_t sum);

/* Псевдозаголовок TCP/UDP: src, dst, protocol, длина L4-сегмента. */
uint32_t gcs_pseudo_header_sum (gcs_ipv4_t src, gcs_ipv4_t dst,
                                uint8_t protocol, uint16_t l4_len);

#endif /* __GCSTCPIP_CHECKSUM_H__ */
