#ifndef __GCSTCPIP_TAP_H__
#define __GCSTCPIP_TAP_H__

#include "gcstcpip/gcs_types.h"

#ifdef __linux__

#include <sys/types.h>

#define GCS_TAP_NAME_CAP 16

typedef struct
{
    int  fd;
    char name [GCS_TAP_NAME_CAP];
} gcs_tap_t;

/* Требует CAP_NET_ADMIN. При отказе возвращает false и заполняет errno. */
bool    gcs_tap_open  (gcs_tap_t *_return, const char *requested_name);
ssize_t gcs_tap_read  (gcs_tap_t *tap, uint8_t *out, size_t cap);
ssize_t gcs_tap_write (gcs_tap_t *tap, const uint8_t *data, size_t len);
void    gcs_tap_close (gcs_tap_t *tap);

#endif /* __linux__ */

#endif /* __GCSTCPIP_TAP_H__ */
