/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/atomic.h"
#include "lune/err.h"
#include "lune/log.h"
#include "lune/mem.h"
#include "lune/net_if.h"
#include "lune/os/linux.h"

#include "drv/net_if.h"
#include "err/err.h"
#include "net/pbuf.h"
#include "nrt/nrt.h"
#include "utils/cap.h"

/*
    Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
*/

/*        
    |    magic    |major  | minor |   thiszone  |   sigfigs   |   snaplen   |  linktype   |
    | d4 c3 b2 a1 | 02 00 | 04 00 | 00 00 00 00 | 00 00 00 00 | ff ff 00 00 | 01 00 00 00 |
*/

typedef struct pcap_hdr_s {
    unsigned int magic_number;              /* magic number */
    unsigned short version_major;           /* major version number */
    unsigned short version_minor;           /* minor version number */
    int thiszone;                           /* GMT to local correction */
    unsigned int sigfigs;                   /* accuracy of timestamps */
    unsigned int snaplen;                   /* max length of captured packets, in octets */
    unsigned int network;                   /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    unsigned int ts_sec;                    /* timestamp seconds */
    unsigned int ts_usec;                   /* timestamp microseconds */
    unsigned int incl_len;                  /* number of octets of packet saved in file */
    unsigned int orig_len;                  /* actual length of packet */
} pcaprec_hdr_t;

static const pcap_hdr_t s_pcap_hdr = {
    .magic_number = 0xa1b2c3d4,
    .version_major = 2,
    .version_minor = 4,
    .thiszone = 0,
    .sigfigs = 0,
    .snaplen = 0xffff,
    .network = 1,
};

typedef struct _cap_file {
    FILE *fp;
    char *file_name;
    lune_atomic32_t ref_cnt;
#define CAP_MAX_CAP_FILE_SIZE               100000000
    unsigned int written_size;
#define CAP_FILE_REACH_LIMIT_FLAG           0x0001
#define CAP_IS_FILE_REACH_LIMIT(cf)         \
    ((cf)->flags & CAP_FILE_REACH_LIMIT_FLAG)
#define CAP_SET_FILE_REACH_LIMIT(cf)        \
    do { (cf)->flags = ((cf)->flags | (CAP_FILE_REACH_LIMIT_FLAG)); } while (0)
#define CAP_CLEAR_FILE_REACH_LIMIT(cf)      \
    do { (cf)->flags = ((cf)->flags & (~CAP_FILE_REACH_LIMIT_FLAG)); } while (0)
    unsigned int flags;
} cap_file_t;

#pragma pack(8)
typedef struct _cap_nrt_msg_hdr {
#define CAP_NRT_MSG_TYPE_BUF                (0)
#define CAP_NRT_MSG_TYPE_PBUF               (1)
    unsigned long type;
    void *cap_fp;
    lune_time_val_t tv;
} cap_nrt_msg_hdr_t;

typedef struct _cap_nrt_msg_pbuf_hdr {
    pbuf_t *pbuf;
    const unsigned char *buf;
    unsigned int len;
} cap_nrt_msg_pbuf_hdr_t;
#pragma pack()

static pthread_spinlock_t s_cap_file_lock;
static unsigned char s_cap_file_offset = 0;
static cap_file_t s_cap_file_array[NRT_RT_CONN_MAX_NUM] = {{0}};

const char *cap_get_file_name(void *cap_fp)
{
    return ((cap_file_t *)cap_fp)->file_name;
}

static inline void cap_file_hold(cap_file_t *cf)
{
    lune_assert(cf->ref_cnt >= 0);
    lune_atomic32_inc(&cf->ref_cnt);
}

static inline void cap_file_put(cap_file_t *cf)
{
    lune_assert(cf->ref_cnt > 0);
    if (lune_atomic32_dec_is_zero(&cf->ref_cnt)) {
        if (!CAP_IS_FILE_REACH_LIMIT(cf)) {
            fflush(cf->fp);
            if (0 != fclose(cf->fp)) {
                lune_log(LUNE_WARN, "failed to close cap file %s: %s", cf->file_name, strerror(errno));
            }
            cf->fp = NULL;
        }

        lune_free_mt(cf->file_name);
        cf->file_name = NULL;

        cf->written_size = 0;
        cf->flags = 0;
    }
}

void *cap_start(const char *file_name)
{
    cap_file_t *cf;
    unsigned int len;
    unsigned char i = 0;

    lune_assert(NULL != file_name);

    pthread_spin_lock(&s_cap_file_lock);
    while (i < NRT_RT_CONN_MAX_NUM) {
        if (NULL == s_cap_file_array[s_cap_file_offset].fp) {
            cf = &s_cap_file_array[s_cap_file_offset];

            if (NULL == (cf->fp = fopen(file_name, "wb"))) {
                ERR_SET_ERR(LUNE_ERR_SYS_ERR);
                lune_log(LUNE_WARN, "failed to open cap file %s: %s", file_name, strerror(errno));
                goto ERR_1;
            }

            len = strlen(file_name) + 1;
            if (NULL == (cf->file_name = lune_malloc_mt(len))) {
                ERR_SET_ERR(LUNE_ERR_NO_MEM);
                goto ERR_2;
            }

            if (sizeof(pcap_hdr_t) != fwrite(&s_pcap_hdr, 1, sizeof(pcap_hdr_t), cf->fp)) {
                ERR_SET_ERR(LUNE_ERR_SYS_ERR);
                lune_log(LUNE_WARN, "failed to write cap file %s: %s", file_name, strerror(errno));
                if (0 != fclose(cf->fp)) {
                    lune_log(LUNE_WARN, "failed to close cap file %s: %s", file_name, strerror(errno));
                }
                goto ERR_3;
            }

            pthread_spin_unlock(&s_cap_file_lock);

            memcpy(cf->file_name, file_name, len);

            lune_atomic32_set(&cf->ref_cnt, 0);
            cap_file_hold(cf);

            cf->written_size = 0;
            cf->written_size += sizeof(pcap_hdr_t);
            cf->flags = 0;

            s_cap_file_offset = (s_cap_file_offset + 1) % NRT_RT_CONN_MAX_NUM;

            return (void *)cf;
        }

        s_cap_file_offset = (s_cap_file_offset + 1) % NRT_RT_CONN_MAX_NUM;
        i++;
    }

    pthread_spin_unlock(&s_cap_file_lock);
    return NULL;

ERR_3:
    lune_free_mt(cf->file_name);

ERR_2:
    if (0 != fclose(cf->fp)) {
        lune_log(LUNE_WARN, "failed to close cap file %s: %s", file_name, strerror(errno));
    }
    cf->fp = NULL;

ERR_1:
    pthread_spin_unlock(&s_cap_file_lock);
    return NULL;
}

void cap_stop(void *cap_fp)
{
    lune_assert(NULL != cap_fp);
    cap_file_put((cap_file_t *)cap_fp);
}

int cap_write_pkt(void *cap_fp, const unsigned char *buf, unsigned int len)
{
    unsigned char *wbuf;
    cap_nrt_msg_hdr_t *hdr;
    pbuf_t *pbuf;

    lune_assert(NULL != cap_fp);
    lune_assert(NULL != buf);
    lune_assert(len > 0 && len <= LUNE_NET_IF_MAX_MTU);
    lune_assert(nrt_is_initialized());

    if (NULL == (pbuf = NET_IF_GET_CURR_TX_PBUF())
        || !PBUF_IS_REF(pbuf)) {
        pbuf = NULL;
        wbuf = nrt_get_req_buf(NRT_REQ_TYPE_CAP, len + sizeof(cap_nrt_msg_hdr_t));
    } else {
        wbuf = nrt_get_req_buf(NRT_REQ_TYPE_CAP, sizeof(cap_nrt_msg_pbuf_hdr_t) + sizeof(cap_nrt_msg_hdr_t));
    }

    if (unlikely(NULL == wbuf)) {
        lune_log_once(LUNE_WARN, "failed to capture packet: %s",
            ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
        return ERR_GET_LAST_ERR();
    }

    cap_file_hold(cap_fp);

    hdr = (cap_nrt_msg_hdr_t *)wbuf;
    hdr->cap_fp = cap_fp;
    time_get_time_of_day(&hdr->tv);
    if (NULL == pbuf) {
        hdr->type = CAP_NRT_MSG_TYPE_BUF;
        memcpy(wbuf + sizeof(cap_nrt_msg_hdr_t), buf, len);
    } else {
        cap_nrt_msg_pbuf_hdr_t *pbuf_hdr;
        hdr->type = CAP_NRT_MSG_TYPE_PBUF;
        pbuf_hdr = (cap_nrt_msg_pbuf_hdr_t *)(wbuf + sizeof(cap_nrt_msg_hdr_t));
        pbuf_hdr->pbuf = pbuf;
        pbuf_hdr->buf = buf;
        pbuf_hdr->len = len;
        pbuf_hold(pbuf);
    }

    nrt_req_buf_done();
    return 0;
}

int cap_write_pkt_to_file(void *cap_fp,
    lune_time_val_t *tv, const unsigned char *buf, unsigned int len)
{
    pcaprec_hdr_t pcap_hdr;
    cap_file_t *cf = (cap_file_t *)cap_fp;

    if (CAP_IS_FILE_REACH_LIMIT(cf)) {
        return ERR_SET_ERR(LUNE_ERR_BUF_FULL);
    }

    pcap_hdr.ts_sec = tv->tv_sec;
    pcap_hdr.ts_usec = tv->tv_usec;
    pcap_hdr.incl_len = pcap_hdr.orig_len = len;

    if (sizeof(pcaprec_hdr_t) != fwrite(&pcap_hdr, 1, sizeof(pcaprec_hdr_t), cf->fp)) {
        lune_log(LUNE_INFO, "failed to write captured packet to file %s: %s",
            cf->file_name, strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    cf->written_size += sizeof(pcaprec_hdr_t);

    if (len != fwrite(buf, 1, len, cf->fp)) {
        lune_log(LUNE_INFO, "failed to write captured packet to file %s: %s",
            cf->file_name, strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    cf->written_size += len;

    if (CAP_MAX_CAP_FILE_SIZE <= cf->written_size) {
        CAP_SET_FILE_REACH_LIMIT(cf);

        fflush(cf->fp);
        if (0 != fclose(cf->fp)) {
            lune_log(LUNE_INFO, "failed to close cap file %s: %s",
                cf->file_name, strerror(errno));
        }
        cf->fp = NULL;

        lune_log(LUNE_INFO, "packet capture in %s has reached file limit (%.1fMB): "
            "%.1fMB captured",
            cf->file_name,
            (float)CAP_MAX_CAP_FILE_SIZE / 1000000,
            (float)cf->written_size / 1000000);
    }

    return 0;
}

int cap_process_nrt_msg(const unsigned char *msg, unsigned int msg_len)
{
    pcaprec_hdr_t pcap_hdr;
    const cap_nrt_msg_hdr_t *hdr;
    const unsigned char *pkt_buf;
    unsigned int pkt_len;
    cap_file_t *cf;
    pbuf_t *pbuf;
    int err;

    lune_assert(NULL != msg);
    lune_assert(msg_len > 0);

    hdr = (const cap_nrt_msg_hdr_t *)msg;
    lune_assert(NULL != hdr->cap_fp);

    cf = (cap_file_t *)hdr->cap_fp;

    if (CAP_NRT_MSG_TYPE_BUF == hdr->type) {
        pbuf = NULL;
        pkt_buf = msg + sizeof(cap_nrt_msg_hdr_t);
        pkt_len = msg_len - sizeof(cap_nrt_msg_hdr_t);
    } else {
        /* CAP_NRT_MSG_TYPE_PBUF */
        const cap_nrt_msg_pbuf_hdr_t *pbuf_hdr =
            (const cap_nrt_msg_pbuf_hdr_t *)(msg + sizeof(cap_nrt_msg_hdr_t));
        pbuf = pbuf_hdr->pbuf;
        pkt_buf = pbuf_hdr->buf;
        pkt_len = pbuf_hdr->len;
    }

    if (CAP_IS_FILE_REACH_LIMIT(cf)) {
        err = ERR_SET_ERR(LUNE_ERR_BUF_FULL);
        goto ERR;
    }

    pcap_hdr.ts_sec = hdr->tv.tv_sec;
    pcap_hdr.ts_usec = hdr->tv.tv_usec;
    pcap_hdr.incl_len = pcap_hdr.orig_len = pkt_len;

    if (sizeof(pcaprec_hdr_t) != fwrite(&pcap_hdr, 1, sizeof(pcaprec_hdr_t), cf->fp)) {
        lune_log(LUNE_INFO, "failed to write captured packet to file %s: %s",
            cf->file_name, strerror(errno));
        err = ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR;
    }

    cf->written_size += sizeof(pcaprec_hdr_t);

    if (pkt_len != fwrite(pkt_buf, 1, pkt_len, cf->fp)) {
        lune_log(LUNE_INFO, "failed to write captured packet to file %s: %s",
            cf->file_name, strerror(errno));
        err = ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        goto ERR;
    }

    cf->written_size += pkt_len;

    if (CAP_MAX_CAP_FILE_SIZE <= cf->written_size) {
        CAP_SET_FILE_REACH_LIMIT(cf);

        fflush(cf->fp);
        if (0 != fclose(cf->fp)) {
            lune_log(LUNE_INFO, "failed to close cap file %s: %s",
                cf->file_name, strerror(errno));
        }
        cf->fp = NULL;

        lune_log(LUNE_INFO, "packet capture in %s has reached file limit (%.1fMB): "
            "%.1fMB captured",
            cf->file_name,
            (float)CAP_MAX_CAP_FILE_SIZE / 1000000,
            (float)cf->written_size / 1000000);
    }

    if (NULL != pbuf) {
        pbuf_put(pbuf);
    }

    cap_file_put(cf);
    return 0;

ERR:
    if (NULL != pbuf) {
        pbuf_put(pbuf);
    }

    cap_file_put(cf);
    return err;
}

int cap_init(void)
{
    unsigned char i;

    s_cap_file_offset = 0;

    if (0 != pthread_spin_init(&s_cap_file_lock, PTHREAD_PROCESS_PRIVATE)) {
        lune_log(LUNE_INFO, "failed to initialize NRT message queue lock: %s",
            strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    for (i = 0; i < NRT_RT_CONN_MAX_NUM; i++) {
        s_cap_file_array[i].fp = NULL;
        s_cap_file_array[i].file_name = NULL;
        lune_atomic32_set(&s_cap_file_array[i].ref_cnt, 0);
        s_cap_file_array[i].written_size = 0;
        s_cap_file_array[i].flags = 0;
    }

    return 0;
}

void cap_fini(void)
{
    unsigned char i;

    for (i = 0; i < NRT_RT_CONN_MAX_NUM; i++) {
        if (NULL != s_cap_file_array[i].fp) {
            if (!CAP_IS_FILE_REACH_LIMIT(&s_cap_file_array[i])) {
                fflush(s_cap_file_array[i].fp);
                if (0 != fclose(s_cap_file_array[i].fp)) {
                    lune_log(LUNE_INFO, "failed to close cap file %s: %s",
                        s_cap_file_array[i].file_name, strerror(errno));
                }
                s_cap_file_array[i].fp = NULL;
            }

            if (unlikely(0 != lune_atomic32_get(&s_cap_file_array[i].ref_cnt))) {
                /* i.e. interface not disabled & deleted */
                lune_log(LUNE_INFO, "packet capture not stopped properly for %s",
                    s_cap_file_array[i].file_name);
            }

            lune_assert(NULL != s_cap_file_array[i].file_name);
            lune_free_mt(s_cap_file_array[i].file_name);
            s_cap_file_array[i].file_name = NULL;

            s_cap_file_array[i].written_size = 0;
            s_cap_file_array[i].flags = 0;
        }
    }

    lune_assert(!pthread_spin_destroy(&s_cap_file_lock));

    s_cap_file_offset = 0;
}
