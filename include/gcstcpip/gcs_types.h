#ifndef __GCSTCPIP_TYPES_H__
#define __GCSTCPIP_TYPES_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* В MinGW архетип "printf" означает семантику msvcrt, где нет %z, поэтому
   GCC там требует "gnu_printf". Clang такого архетипа не знает и ругается
   -Wignored-attributes, но его проверка формата и так учитывает цель. */
#if defined(__MINGW32__) && !defined(__clang__)
#  define GCS_PRINTF(fmt_idx, arg_idx) __attribute__ ((format (gnu_printf, fmt_idx, arg_idx)))
#elif defined(__GNUC__) || defined(__clang__)
#  define GCS_PRINTF(fmt_idx, arg_idx) __attribute__ ((format (printf, fmt_idx, arg_idx)))
#else
#  define GCS_PRINTF(fmt_idx, arg_idx)
#endif

#define GCS_MAC_LEN 6

typedef struct
{
    uint8_t addr [GCS_MAC_LEN];
} gcs_mac_t;

/* IPv4-адрес хранится в host byte order */
typedef uint32_t gcs_ipv4_t;

/* Плоский буфер кадра. Владение памятью остаётся за вызывающим. */
typedef struct
{
    uint8_t *data;
    size_t   len;
    size_t   cap;
} gcs_buf_t;

static inline uint16_t gcs_rd16be (const uint8_t *p)
{
    return (uint16_t) ((uint16_t) p [0] << 8 | (uint16_t) p [1]);
}

static inline uint32_t gcs_rd32be (const uint8_t *p)
{
    return (uint32_t) p [0] << 24 | (uint32_t) p [1] << 16
         | (uint32_t) p [2] << 8  | (uint32_t) p [3];
}

static inline void gcs_wr16be (uint8_t *p, uint16_t v)
{
    p [0] = (uint8_t) (v >> 8);
    p [1] = (uint8_t) (v & 0xFF);
}

static inline void gcs_wr32be (uint8_t *p, uint32_t v)
{
    p [0] = (uint8_t) (v >> 24);
    p [1] = (uint8_t) (v >> 16);
    p [2] = (uint8_t) (v >> 8);
    p [3] = (uint8_t) (v & 0xFF);
}

bool     gcs_mac_parse  (const char *str, gcs_mac_t *_return);
void     gcs_mac_format (const gcs_mac_t *mac, char *_return, size_t cap);
bool     gcs_mac_equal  (const gcs_mac_t *a, const gcs_mac_t *b);
bool     gcs_mac_is_broadcast (const gcs_mac_t *mac);

bool     gcs_ipv4_parse  (const char *str, gcs_ipv4_t *_return);
void     gcs_ipv4_format (gcs_ipv4_t ip, char *_return, size_t cap);

#endif /* __GCSTCPIP_TYPES_H__ */
