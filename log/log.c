/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/err.h"
#include "lune/log.h"
#include "lune/os/linux.h"
#include "lune/time.h"
#include "lune/timer.h"

#include "err/err.h"
#include "kernel/sched.h"
#include "kernel/timer.h"
#include "lib/utils.h"
#include "log/log.h"
#include "nrt/nrt.h"
#include "rt/core.h"

#define LOG_MAX_LOG_FILE_SIZE           (200000000)

#define LOG_MAX_BUF_SIZE                (0x400)

#define LOG_CACHED_LOG_FLUSH_INTVL      (1 * LUNE_TIME_SECOND)

#define LOG_DATETIME_MAX_BUF_LEN        (256)

#define LOG_LOCAL_IS_INIT()             (NULL != s_log_rt_log_fp)

/* RT log instance */
#pragma pack(8)
typedef struct _log_file {
    FILE *fp;
    lune_log_level_en level;
} log_file_t;
#pragma pack()

static const char s_log_level_char[LUNE_LOG_LEVEL_NUM] = {
    'C',
    'W',
    'I',
    'D',
    'V',
};

static FILE *s_log_nrt_log_fp = NULL;
static lune_log_level_en s_log_nrt_log_level;
static char s_log_nrt_log_file[LUNE_MAX_NAME_BUF_LEN] = {0};

static pthread_spinlock_t s_log_rt_log_file_lock;
static unsigned char s_log_rt_log_file_offset = 0;
static log_file_t s_log_rt_log_file_array[NRT_RT_CONN_MAX_NUM] = {{0}};

static __thread lune_log_level_en s_log_rt_log_level;
static __thread unsigned char s_log_rt_log_file_id;
static __thread void *s_log_rt_log_fp = NULL;
static __thread char s_log_rt_log_file[LUNE_MAX_NAME_BUF_LEN] = {0};
static __thread unsigned int s_log_rt_log_size = 0;

static __thread const char *s_log_rt_cached_log_file_name;
static __thread int s_log_rt_cached_log_line_num;
static __thread unsigned int s_log_rt_cached_log_repeat_times;
static __thread char s_log_rt_cached_log_buf[LOG_MAX_BUF_SIZE];
static __thread int s_log_rt_cached_log_len;
static __thread lune_log_level_en s_log_rt_cached_log_level;
static __thread lune_timer_t s_log_rt_cached_log_tmr;

__thread unsigned int g_log_cpu_usage_flag = 1;

unsigned char log_get_id(void)
{
    return s_log_rt_log_file_id;
}

lune_log_level_en log_get_level(void)
{
    return (CORE_IS_RT_CORE()) ? s_log_rt_log_level : s_log_nrt_log_level;
}

static int log_write_log(char *log_buf, int len, lune_log_level_en level)
{
    unsigned char *buf;

    if ((unsigned int)-1 == s_log_rt_log_size) {
        /* already hit log file limit */
        return -LUNE_ERR_BUF_FULL;
    } else if (len + s_log_rt_log_size > LOG_MAX_LOG_FILE_SIZE) {
        s_log_rt_log_size = (unsigned int)-1;
        fprintf(stderr, "failed to log %s: file size exceeds limit\n", s_log_rt_log_file);
        return ERR_SET_ERR(LUNE_ERR_BUF_FULL);
    }

    s_log_rt_log_size += (len + 23);    /* plus log level, data time, etc. */

    /*
        1 Byte (id) + 1 Byte (level) + log string + 1 Byte (\0)
    */
    if (NULL == (buf = nrt_get_req_buf(NRT_REQ_TYPE_LOG, len + 3))) {
        fprintf(stderr, "failed to log %s: %s\n",
            s_log_rt_log_file, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_BUF_FULL)));
        return ERR_GET_LAST_ERR();
    }

    buf[0] = s_log_rt_log_file_id;
    buf[1] = (unsigned char)level;
    memcpy(&buf[2], log_buf, len);
    buf[len + 2] = '\0';

    nrt_req_buf_done();
    return 0;
}

static void log_flush_cached_log_timer_func(void *data __attribute__((unused)))
{
    int len;

    lune_assert(s_log_rt_cached_log_repeat_times > 0);
    lune_assert(s_log_rt_cached_log_level != LUNE_INVALID_LOG_LEVEL);

    if (s_log_rt_cached_log_repeat_times > 1) {
        len = sprintf(s_log_rt_cached_log_buf + s_log_rt_cached_log_len,
            ": repeated times %d", s_log_rt_cached_log_repeat_times);
        s_log_rt_cached_log_len += len;
    }

    (void)log_write_log(s_log_rt_cached_log_buf, s_log_rt_cached_log_len, s_log_rt_cached_log_level);

    s_log_rt_cached_log_file_name = NULL;
    s_log_rt_cached_log_line_num = 0;
    s_log_rt_cached_log_len = 0;
    s_log_rt_cached_log_level = LUNE_INVALID_LOG_LEVEL;
    s_log_rt_cached_log_repeat_times = 0;
}

int log_local_init(const char *log_file, lune_log_level_en log_level)
{
    int i = 0;
    log_file_t *lf;

#ifdef LUNE_DEBUG
    log_level = (log_level < LUNE_DBG) ? LUNE_DBG : log_level;
#endif

    lune_assert(nrt_local_is_init());

    pthread_spin_lock(&s_log_rt_log_file_lock);
    while (i < NRT_RT_CONN_MAX_NUM) {
        if (NULL == s_log_rt_log_file_array[s_log_rt_log_file_offset].fp) {
            lf = &s_log_rt_log_file_array[s_log_rt_log_file_offset];

            if (NULL == (lf->fp = fopen(log_file, "w"))) {
                pthread_spin_unlock(&s_log_rt_log_file_lock);
                lune_log(LUNE_CRIT, "failed to open log file %s: %s",
                    log_file, strerror(errno));
                return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
            }

            pthread_spin_unlock(&s_log_rt_log_file_lock);

            s_log_rt_log_level = lf->level = log_level;
            s_log_rt_log_file_id = s_log_rt_log_file_offset;
            s_log_rt_log_fp = (void *)lf;
            strcpy(s_log_rt_log_file, log_file);

            s_log_rt_log_file_offset = (s_log_rt_log_file_offset + 1) % NRT_RT_CONN_MAX_NUM;

            s_log_rt_cached_log_file_name = NULL;
            s_log_rt_cached_log_line_num = 0;
            s_log_rt_cached_log_repeat_times = 0;
            memset(s_log_rt_cached_log_buf, 0x00, LOG_MAX_BUF_SIZE);
            s_log_rt_cached_log_len = 0;
            s_log_rt_cached_log_level = LUNE_INVALID_LOG_LEVEL;
            timer_init_timer(&s_log_rt_cached_log_tmr, LUNE_TIMER_ONCE,
                LUNE_TIMER_RES_DEFAULT, log_flush_cached_log_timer_func, NULL);

            return 0;
        }

        s_log_rt_log_file_offset = (s_log_rt_log_file_offset + 1) % NRT_RT_CONN_MAX_NUM;
        i++;
    }

    pthread_spin_unlock(&s_log_rt_log_file_lock);

    s_log_rt_log_size = 0;

    return ERR_SET_ERR(LUNE_ERR_EXCEED_LIMITS);
}

void log_local_fini(void)
{
    if (LUNE_TIMER_IS_ADDED(s_log_rt_cached_log_tmr)) {
        timer_del_timer(&s_log_rt_cached_log_tmr);
    }
    s_log_rt_log_fp = NULL;
}

void log_cleanup(unsigned char id)
{
    if (unlikely(NULL == s_log_rt_log_file_array[id].fp)) {
        lune_log(LUNE_INFO, "failed to clean up log file: file not found");
        return;
    }

    fflush(s_log_rt_log_file_array[id].fp);
    fclose(s_log_rt_log_file_array[id].fp);
    s_log_rt_log_file_array[id].fp = NULL;
}

int log_init(const char *log_file, lune_log_level_en log_level)
{
    unsigned char i;

#ifdef LUNE_DEBUG
    log_level = (log_level < LUNE_DBG) ? LUNE_DBG : log_level;
#endif

    if (NULL == log_file) {
        s_log_nrt_log_fp = stdout;
        s_log_nrt_log_file[0] = 0;
    } else {
        if (NULL == (s_log_nrt_log_fp = fopen(log_file, "w"))) {
            fprintf(stderr, "failed to open log file %s: %s\n",
                log_file, strerror(errno));
            return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
        }
        strcpy(s_log_nrt_log_file, log_file);
    }
    s_log_nrt_log_level = log_level;

    if (0 != pthread_spin_init(&s_log_rt_log_file_lock, PTHREAD_PROCESS_PRIVATE)) {
        lune_log(LUNE_CRIT, "failed to initialize NRT message queue lock: %s",
            strerror(errno));
        return ERR_SET_ERR(LUNE_ERR_SYS_ERR);
    }

    for (i = 0; i < NRT_RT_CONN_MAX_NUM; i++) {
        s_log_rt_log_file_array[i].fp = NULL;
        s_log_rt_log_file_array[i].level = LUNE_LOG_DEFAULT_LEVEL;
    }

    return 0;
}

void log_fini()
{
    unsigned char i;

    for (i = 0; i < NRT_RT_CONN_MAX_NUM; i++) {
        if (NULL != s_log_rt_log_file_array[i].fp) {
            fflush(s_log_rt_log_file_array[i].fp);
            fclose(s_log_rt_log_file_array[i].fp);
            s_log_rt_log_file_array[i].fp = NULL;
        }
    }

    lune_assert(!pthread_spin_destroy(&s_log_rt_log_file_lock));

    if (s_log_nrt_log_fp != stdout) {
        fflush(s_log_nrt_log_fp);
        fclose(s_log_nrt_log_fp);
        s_log_nrt_log_fp = NULL;
    }
}

lune_log_level_en log_get_log_level(const char ch)
{
    lune_log_level_en i;

    for (i = LUNE_CRIT; i < LUNE_LOG_LEVEL_NUM; i++) {
        if (s_log_level_char[i] == ch) {
            return i;
        }
    }

    return LUNE_INVALID_LOG_LEVEL;
}

static int log_print(FILE *fp, lune_log_level_en level, const char *log_buf)
{
    char datetime_buf[LOG_DATETIME_MAX_BUF_LEN];
    unsigned int len;

    if (0 == (len = utils_get_datetime(datetime_buf, LOG_DATETIME_MAX_BUF_LEN))) {
        fprintf(fp, "failed to get date and time: %s\n", strerror(errno));
        fprintf(fp, "%c \?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\? %s\n", s_log_level_char[level], log_buf);
        return ERR_SET_ERR(LUNE_ERR_LOG_ERR);
    }

    fprintf(fp, "%c %s %s\n", s_log_level_char[level], datetime_buf, log_buf);
    return 0;
}

int __lune_log(const char *file_name,
    int line_num, int squash, lune_log_level_en level, const char *fmt, ...)
{
    char log_buf[LOG_MAX_BUF_SIZE];
    int len;
    va_list args;

    if (!CORE_IS_RT_CORE()
        || !LOG_LOCAL_IS_INIT()) {
        lune_assert(NULL != s_log_nrt_log_fp);

        if (level > s_log_nrt_log_level) {
            return 0;
        }

        va_start(args, fmt);
        if (0 > (len = vsnprintf(log_buf, LOG_MAX_BUF_SIZE, fmt, args))) {
            if (stdout == s_log_nrt_log_fp) {
                return ERR_SET_ERR(LUNE_ERR_LOG_ERR);
            }

            fprintf(stderr, "failed to log %s: %s\n",
                s_log_nrt_log_file, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_LOG_ERR)));
            return ERR_GET_LAST_ERR();
        }
        va_end(args);

        return log_print(s_log_nrt_log_fp, level, log_buf);
    }

    if (level > s_log_rt_log_level) {
        return 0;
    }

    lune_assert(nrt_is_initialized());

    if (file_name == s_log_rt_cached_log_file_name
        && line_num == s_log_rt_cached_log_line_num) {
        lune_assert(squash);
        s_log_rt_cached_log_repeat_times++;
        return 0;
    }

    if (s_log_rt_cached_log_repeat_times > 0) {
        /* log cached repeated log */
        goto CACHED_LOG;
    }

LOG:
    va_start(args, fmt);

    if (0 > (len = vsnprintf(log_buf, LOG_MAX_BUF_SIZE, fmt, args))) {
        fprintf(stderr, "failed to log %s: %s\n",
            s_log_rt_log_file, ERR_GET_ERR_STR(ERR_SET_ERR(LUNE_ERR_LOG_ERR)));
        return ERR_GET_LAST_ERR();
    }
    va_end(args);

    if (squash) {
        lune_assert(!LUNE_TIMER_IS_ADDED(s_log_rt_cached_log_tmr));
        s_log_rt_cached_log_file_name = file_name;
        s_log_rt_cached_log_line_num = line_num;
        memcpy(s_log_rt_cached_log_buf, log_buf, len);
        s_log_rt_cached_log_len = len;
        s_log_rt_cached_log_level = level;
        s_log_rt_cached_log_repeat_times = 1;
        timer_add_timer(&s_log_rt_cached_log_tmr, LOG_CACHED_LOG_FLUSH_INTVL);
        return 0;
    }

    s_log_rt_cached_log_file_name = NULL;
    s_log_rt_cached_log_line_num = 0;
    s_log_rt_cached_log_len = 0;
    s_log_rt_cached_log_level = LUNE_INVALID_LOG_LEVEL;
    s_log_rt_cached_log_repeat_times = 0;

    (void)log_write_log(log_buf, len, level);
    return 0;

CACHED_LOG:
    lune_assert(s_log_rt_cached_log_repeat_times > 0);
    lune_assert(s_log_rt_cached_log_level != LUNE_INVALID_LOG_LEVEL);
    lune_assert(LUNE_TIMER_IS_ADDED(s_log_rt_cached_log_tmr));

    if (s_log_rt_cached_log_repeat_times > 1) {
        len = sprintf(s_log_rt_cached_log_buf + s_log_rt_cached_log_len,
            ": repeated times %d", s_log_rt_cached_log_repeat_times);
        s_log_rt_cached_log_len += len;
    }

    (void)log_write_log(s_log_rt_cached_log_buf, s_log_rt_cached_log_len, s_log_rt_cached_log_level);

    timer_del_timer(&s_log_rt_cached_log_tmr);

    goto LOG;
}

int log_process_nrt_msg(const unsigned char *msg, unsigned int msg_len __attribute__((unused)))
{
    lune_log_level_en level;
    unsigned char id;

    lune_assert(NULL != msg);

    id = msg[0];

    lune_assert(NULL != s_log_rt_log_file_array[id].fp);

    level = (lune_log_level_en)msg[1];

    return log_print(s_log_rt_log_file_array[id].fp, level, (const char *)&msg[2]);
}

void log_flush(void)
{
    unsigned char i;

    for (i = 0; i < NRT_RT_CONN_MAX_NUM; i++) {
        if (NULL != s_log_rt_log_file_array[i].fp) {
            fflush(s_log_rt_log_file_array[i].fp);
        }
    }
}
