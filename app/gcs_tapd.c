/* Живой драйвер поверх TAP-интерфейса. Требует CAP_NET_ADMIN. */
#include "gcstcpip/gcs_stack.h"
#include "gcstcpip/gcs_tap.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_running = 1;

static void on_signal (int signo)
{
    (void) signo;
    g_running = 0;
}

int main (int argc, char **argv)
{
    const char *ifname  = "gcstap0";
    const char *ip_str  = "10.0.0.2";
    const char *mac_str = "0a:00:00:00:00:02";
    uint16_t    port    = 8080;

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp (argv [i], "--dev") == 0 && i + 1 < argc)       { ifname  = argv [++i]; }
        else if (strcmp (argv [i], "--ip") == 0 && i + 1 < argc)   { ip_str  = argv [++i]; }
        else if (strcmp (argv [i], "--mac") == 0 && i + 1 < argc)  { mac_str = argv [++i]; }
        else if (strcmp (argv [i], "--port") == 0 && i + 1 < argc) { port = (uint16_t) atoi (argv [++i]); }
    }

    gcs_mac_t  mac;
    gcs_ipv4_t ip;

    if (!gcs_mac_parse (mac_str, &mac) || !gcs_ipv4_parse (ip_str, &ip))
    {
        fprintf (stderr, "Не разобрал адрес интерфейса\n");
        return 2;
    }

    gcs_tap_t tap;

    if (!gcs_tap_open (&tap, ifname))
    {
        fprintf (stderr, "gcs_tap_open(%s): %s\n", ifname, strerror (errno));

        if (errno == EPERM)
        {
            fprintf (stderr,
                     "Нужна привилегия CAP_NET_ADMIN. Варианты:\n"
                     "  sudo setcap cap_net_admin+ep ./GCS.Tapd\n"
                     "  либо запуск от root\n"
                     "Без неё используйте GCS.Replay и заранее записанный pcap.\n");
        }

        return 1;
    }

    printf ("Интерфейс %s поднят. Настройте его и шлите трафик:\n", tap.name);
    printf ("  sudo ip addr add 10.0.0.1/24 dev %s\n", tap.name);
    printf ("  sudo ip link set %s up\n", tap.name);
    printf ("  ping 10.0.0.2\n\n");

    signal (SIGINT, on_signal);
    signal (SIGTERM, on_signal);

    gcs_stack_t stack;
    gcs_stack_init (&stack, &mac, ip, port);

    uint8_t frame [GCS_STACK_FRAME_CAP];
    uint8_t reply [GCS_STACK_FRAME_CAP];

    while (g_running)
    {
        ssize_t len = gcs_tap_read (&tap, frame, sizeof (frame));

        if (len < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            perror ("read");
            break;
        }

        size_t reply_len = gcs_stack_handle_frame (&stack, frame, (size_t) len,
                                                   reply, sizeof (reply));

        if (reply_len > 0)
        {
            gcs_tap_write (&tap, reply, reply_len);
        }
    }

    gcs_tap_close (&tap);

    return 0;
}
