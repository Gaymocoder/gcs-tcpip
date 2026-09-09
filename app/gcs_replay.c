/* Прогон стека по заранее записанному pcap: без привилегий и полностью воспроизводимо. */
#include "gcstcpip/gcs_pcap.h"
#include "gcstcpip/gcs_stack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage (const char *argv0)
{
    fprintf (stderr,
             "Использование: %s --in <вход.pcap> [--out <выход.pcap>]\n"
             "               [--ip <адрес>] [--mac <MAC>] [--port <порт>] [--quiet]\n",
             argv0);
}

int main (int argc, char **argv)
{
    const char *in_path  = NULL;
    const char *out_path = NULL;
    const char *ip_str   = "10.0.0.2";
    const char *mac_str  = "0a:00:00:00:00:02";
    uint16_t    port     = 8080;
    bool        quiet    = false;

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp (argv [i], "--in") == 0 && i + 1 < argc)        { in_path  = argv [++i]; }
        else if (strcmp (argv [i], "--out") == 0 && i + 1 < argc)  { out_path = argv [++i]; }
        else if (strcmp (argv [i], "--ip") == 0 && i + 1 < argc)   { ip_str   = argv [++i]; }
        else if (strcmp (argv [i], "--mac") == 0 && i + 1 < argc)  { mac_str  = argv [++i]; }
        else if (strcmp (argv [i], "--port") == 0 && i + 1 < argc) { port = (uint16_t) atoi (argv [++i]); }
        else if (strcmp (argv [i], "--quiet") == 0)                { quiet = true; }
        else { usage (argv [0]); return 2; }
    }

    if (in_path == NULL)
    {
        usage (argv [0]);
        return 2;
    }

    gcs_mac_t  mac;
    gcs_ipv4_t ip;

    if (!gcs_mac_parse (mac_str, &mac) || !gcs_ipv4_parse (ip_str, &ip))
    {
        fprintf (stderr, "Не разобрал адрес интерфейса\n");
        return 2;
    }

    gcs_pcap_reader_t reader;

    if (!gcs_pcap_open_read (&reader, in_path))
    {
        fprintf (stderr, "Не открыл %s\n", in_path);
        return 1;
    }

    gcs_pcap_writer_t writer;
    bool have_writer = false;

    if (out_path != NULL)
    {
        have_writer = gcs_pcap_open_write (&writer, out_path);

        if (!have_writer)
        {
            fprintf (stderr, "Не открыл на запись %s\n", out_path);
            gcs_pcap_close_read (&reader);
            return 1;
        }
    }

    gcs_stack_t stack;
    gcs_stack_init (&stack, &mac, ip, port);
    stack.verbose = !quiet;

    printf ("Интерфейс: ip=%s mac=%s, слушаем TCP-порт %u\n", ip_str, mac_str, port);
    printf ("Вход: %s\n\n", in_path);

    uint8_t  frame [GCS_STACK_FRAME_CAP];
    uint8_t  reply [GCS_STACK_FRAME_CAP];
    uint32_t ts_sec  = 0;
    uint32_t ts_usec = 0;
    size_t   index   = 0;
    size_t   replies = 0;
    size_t   len     = 0;

    while ((len = gcs_pcap_read_frame (&reader, frame, sizeof (frame), &ts_sec, &ts_usec)) > 0)
    {
        index += 1;
        printf ("[%zu] кадр %zu Б\n", index, len);

        size_t reply_len = gcs_stack_handle_frame (&stack, frame, len, reply, sizeof (reply));

        if (reply_len > 0)
        {
            replies += 1;

            if (have_writer)
            {
                gcs_pcap_write_frame (&writer, reply, reply_len, ts_sec, ts_usec + 1);
            }
        }

        printf ("\n");
    }

    printf ("Обработано кадров: %zu, отправлено ответов: %zu\n", index, replies);
    printf ("Состояние TCP: %s\n", gcs_tcp_state_name (stack.conn.state));

    gcs_pcap_close_read (&reader);

    if (have_writer)
    {
        gcs_pcap_close_write (&writer);
        printf ("\nОтветные кадры записаны в %s\n", out_path);
    }

    return 0;
}
