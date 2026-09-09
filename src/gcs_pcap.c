#include "gcstcpip/gcs_pcap.h"

#include <string.h>

typedef struct
{
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} gcs_pcap_file_header_t;

bool gcs_pcap_open_read (gcs_pcap_reader_t *_return, const char *path)
{
    if (_return == NULL || path == NULL)
    {
        return false;
    }

    memset (_return, 0, sizeof (*_return));

    _return->fp = fopen (path, "rb");

    if (_return->fp == NULL)
    {
        return false;
    }

    gcs_pcap_file_header_t hdr;

    if (fread (&hdr, sizeof (hdr), 1, _return->fp) != 1)
    {
        fclose (_return->fp);
        _return->fp = NULL;
        return false;
    }

    /* Читаем только файлы в порядке байт этой машины: их же и пишем. */
    if (hdr.magic != GCS_PCAP_MAGIC)
    {
        fclose (_return->fp);
        _return->fp = NULL;
        return false;
    }

    _return->linktype = hdr.linktype;

    return true;
}

size_t gcs_pcap_read_frame (gcs_pcap_reader_t *reader, uint8_t *out, size_t cap,
                            uint32_t *ts_sec, uint32_t *ts_usec)
{
    if (reader == NULL || reader->fp == NULL || out == NULL)
    {
        return 0;
    }

    uint32_t rec [4];

    if (fread (rec, sizeof (rec), 1, reader->fp) != 1)
    {
        return 0;
    }

    uint32_t incl = rec [2];

    if (incl > GCS_PCAP_MAX_FRAME || incl > cap)
    {
        return 0;
    }

    if (fread (out, 1, incl, reader->fp) != incl)
    {
        return 0;
    }

    if (ts_sec  != NULL) { *ts_sec  = rec [0]; }
    if (ts_usec != NULL) { *ts_usec = rec [1]; }

    return incl;
}

void gcs_pcap_close_read (gcs_pcap_reader_t *reader)
{
    if (reader != NULL && reader->fp != NULL)
    {
        fclose (reader->fp);
        reader->fp = NULL;
    }
}

bool gcs_pcap_open_write (gcs_pcap_writer_t *_return, const char *path)
{
    if (_return == NULL || path == NULL)
    {
        return false;
    }

    _return->fp = fopen (path, "wb");

    if (_return->fp == NULL)
    {
        return false;
    }

    gcs_pcap_file_header_t hdr;
    memset (&hdr, 0, sizeof (hdr));

    hdr.magic         = GCS_PCAP_MAGIC;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.snaplen       = GCS_PCAP_MAX_FRAME;
    hdr.linktype      = GCS_PCAP_LINKTYPE_EN10MB;

    if (fwrite (&hdr, sizeof (hdr), 1, _return->fp) != 1)
    {
        fclose (_return->fp);
        _return->fp = NULL;
        return false;
    }

    return true;
}

bool gcs_pcap_write_frame (gcs_pcap_writer_t *writer, const uint8_t *data, size_t len,
                           uint32_t ts_sec, uint32_t ts_usec)
{
    if (writer == NULL || writer->fp == NULL || data == NULL)
    {
        return false;
    }

    uint32_t rec [4] = { ts_sec, ts_usec, (uint32_t) len, (uint32_t) len };

    if (fwrite (rec, sizeof (rec), 1, writer->fp) != 1)
    {
        return false;
    }

    return fwrite (data, 1, len, writer->fp) == len;
}

void gcs_pcap_close_write (gcs_pcap_writer_t *writer)
{
    if (writer != NULL && writer->fp != NULL)
    {
        fclose (writer->fp);
        writer->fp = NULL;
    }
}
