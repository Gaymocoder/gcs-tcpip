#include "gcstcpip/gcs_tap.h"

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

bool gcs_tap_open (gcs_tap_t *_return, const char *requested_name)
{
    if (_return == NULL)
    {
        errno = EINVAL;
        return false;
    }

    _return->fd = open ("/dev/net/tun", O_RDWR);

    if (_return->fd < 0)
    {
        return false;
    }

    struct ifreq ifr;
    memset (&ifr, 0, sizeof (ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (requested_name != NULL)
    {
        strncpy (ifr.ifr_name, requested_name, IFNAMSIZ - 1);
    }

    /* Требует CAP_NET_ADMIN. Без неё ядро отвечает EPERM. */
    if (ioctl (_return->fd, TUNSETIFF, &ifr) < 0)
    {
        int saved = errno;
        close (_return->fd);
        _return->fd = -1;
        errno = saved;
        return false;
    }

    strncpy (_return->name, ifr.ifr_name, GCS_TAP_NAME_CAP - 1);
    _return->name [GCS_TAP_NAME_CAP - 1] = '\0';

    return true;
}

ssize_t gcs_tap_read (gcs_tap_t *tap, uint8_t *out, size_t cap)
{
    return read (tap->fd, out, cap);
}

ssize_t gcs_tap_write (gcs_tap_t *tap, const uint8_t *data, size_t len)
{
    return write (tap->fd, data, len);
}

void gcs_tap_close (gcs_tap_t *tap)
{
    if (tap != NULL && tap->fd >= 0)
    {
        close (tap->fd);
        tap->fd = -1;
    }
}

#endif /* __linux__ */
