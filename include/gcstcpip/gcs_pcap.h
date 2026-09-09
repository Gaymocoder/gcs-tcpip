#ifndef __GCSTCPIP_PCAP_H__
#define __GCSTCPIP_PCAP_H__

#include "gcstcpip/gcs_types.h"
#include <stdio.h>

#define GCS_PCAP_MAGIC       0xA1B2C3D4u
#define GCS_PCAP_LINKTYPE_EN10MB 1
#define GCS_PCAP_MAX_FRAME   65535

typedef struct
{
    FILE    *fp;
    uint32_t linktype;
} gcs_pcap_reader_t;

typedef struct
{
    FILE *fp;
} gcs_pcap_writer_t;

bool   gcs_pcap_open_read  (gcs_pcap_reader_t *_return, const char *path);
/* Возвращает число прочитанных байт кадра, 0 — конец файла. */
size_t gcs_pcap_read_frame (gcs_pcap_reader_t *reader, uint8_t *out, size_t cap,
                            uint32_t *ts_sec, uint32_t *ts_usec);
void   gcs_pcap_close_read (gcs_pcap_reader_t *reader);

bool gcs_pcap_open_write  (gcs_pcap_writer_t *_return, const char *path);
bool gcs_pcap_write_frame (gcs_pcap_writer_t *writer, const uint8_t *data, size_t len,
                           uint32_t ts_sec, uint32_t ts_usec);
void gcs_pcap_close_write (gcs_pcap_writer_t *writer);

#endif /* __GCSTCPIP_PCAP_H__ */
