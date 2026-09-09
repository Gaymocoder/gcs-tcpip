#include "gcstcpip/gcs_types.h"

#include <stdio.h>
#include <string.h>

bool gcs_mac_parse (const char *str, gcs_mac_t *_return)
{
    unsigned int octets [GCS_MAC_LEN];

    if (str == NULL || _return == NULL)
    {
        return false;
    }

    if (sscanf (str, "%x:%x:%x:%x:%x:%x",
                &octets [0], &octets [1], &octets [2],
                &octets [3], &octets [4], &octets [5]) != GCS_MAC_LEN)
    {
        return false;
    }

    for (size_t i = 0; i < GCS_MAC_LEN; ++i)
    {
        if (octets [i] > 0xFF)
        {
            return false;
        }

        _return->addr [i] = (uint8_t) octets [i];
    }

    return true;
}

void gcs_mac_format (const gcs_mac_t *mac, char *_return, size_t cap)
{
    if (mac == NULL || _return == NULL || cap == 0)
    {
        return;
    }

    snprintf (_return, cap, "%02x:%02x:%02x:%02x:%02x:%02x",
              mac->addr [0], mac->addr [1], mac->addr [2],
              mac->addr [3], mac->addr [4], mac->addr [5]);
}

bool gcs_mac_equal (const gcs_mac_t *a, const gcs_mac_t *b)
{
    return memcmp (a->addr, b->addr, GCS_MAC_LEN) == 0;
}

bool gcs_mac_is_broadcast (const gcs_mac_t *mac)
{
    for (size_t i = 0; i < GCS_MAC_LEN; ++i)
    {
        if (mac->addr [i] != 0xFF)
        {
            return false;
        }
    }

    return true;
}

bool gcs_ipv4_parse (const char *str, gcs_ipv4_t *_return)
{
    unsigned int a, b, c, d;

    if (str == NULL || _return == NULL)
    {
        return false;
    }

    if (sscanf (str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    {
        return false;
    }

    if (a > 255 || b > 255 || c > 255 || d > 255)
    {
        return false;
    }

    *_return = (gcs_ipv4_t) (a << 24 | b << 16 | c << 8 | d);
    return true;
}

void gcs_ipv4_format (gcs_ipv4_t ip, char *_return, size_t cap)
{
    if (_return == NULL || cap == 0)
    {
        return;
    }

    snprintf (_return, cap, "%u.%u.%u.%u",
              (unsigned) ((ip >> 24) & 0xFF), (unsigned) ((ip >> 16) & 0xFF),
              (unsigned) ((ip >> 8) & 0xFF),  (unsigned) (ip & 0xFF));
}
