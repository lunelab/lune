/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#include "lune/assert.h"
#include "lune/err.h"
#include "lune/os/linux.h"

#include "err/err.h"
#include "kernel/time.h"
#include "log/log.h"

#define ERR_MAX_ERR_NO_NUM   (256)

typedef struct _err_no {
    const char *file_name;
    int line_no;
    int err_no;
    lune_time_val_t tv;
} err_no_t;

static __thread int s_err_no_offset = -1;
static __thread int s_err_cnt = 0;
static __thread err_no_t s_err_no_array[ERR_MAX_ERR_NO_NUM] = {{0}};

static const char *s_err_str_array[] = {
    "no error",
    "invalid argument",
    "not exist",
    "already exist",
    "not started",
    "already started",
    "not set",
    "already set",
    "not bound",
    "already bound",
    "not closed",
    "already closed",
    "not ready",
    "not added",
    "already deleted",
    "out of memory",
    "out of cpu core",
    "system call error",
    "exceed system limits",
    "no resource",
    "packet buffer internal error",
    "not supported",
    "name too long",
    "failed to open",
    "failed to close",
    "id not found",
    "permission denied",
    "not initialized",
    "memory internal error",
    "memory overflow",
    "buffer full",
    "buffer empty",
    "active interface",
    "inactive interface",
    "failed to send via interface",
    "inconsistent mtu",
    "interface not found",
    "unexpected type",
    "unexpected connection type",
    "aggregated interface not enabled",
    "aggregated interface not disabled",
    "aggregated interface not added",
    "channel interface not enabled",
    "channel interface not disabled",
    "channel interface not deleted",
    "channel interface not added",
    "no packets",
    "interface type error",
    "interface type not supported",
    "interface not connected",
    "interface already connected",
    "interface internal error",
    "invalid mtu",
    "option not found",
    "packet oversized",
    "socket not connected",
    "socket connecting",
    "socket already connected",
    "unexpected arp packet received",
    "active local mac",
    "inactive local mac",
    "mac not set",
    "mac internal error",
    "ip type mismatch",
    "unexpected ipv4 fragment received",
    "ipv4 malform packet",
    "ipv4 not set",
    "ipv4 internal error",
    "unexpected ipv6 fragment received",
    "ipv6 malform packet",
    "ipv6 internal error",
    "unexpected tcp packet received",
    "tcp congestion window full",
    "tcp internal error",
    "ssl not set",
    "ssl certificate not set",
    "ssl type error",
    "ssl internal error",
    "hit maximum retries",
    "malformed argument",
    "system socket call error",
    "unexpected memory allocation",
    "log error",
    "core already occupied",
    "core not occupied",
    "core not running",
    "core already exit",
    "core type error",
    "core not bound with any coprocessor",
    "core internal error",
    "unknown type",
    "application internal error",
    "internal error",
};

static_assert(LUNE_ERR_MAX_ERR == (sizeof(s_err_str_array) / sizeof(const char *)),
    "error type and description unmatched");

int err_set_err_no(int err_no, const char *file_name, int line_no)
{
    s_err_cnt++;
    s_err_no_offset = (s_err_no_offset + 1) % ERR_MAX_ERR_NO_NUM;
    s_err_no_array[s_err_no_offset].file_name = file_name;
    s_err_no_array[s_err_no_offset].line_no = line_no;
    s_err_no_array[s_err_no_offset].err_no = err_no;
    if (TIME_IS_INIT()) {
        time_get_time_of_day(&s_err_no_array[s_err_no_offset].tv);
    } else {
        lune_assert(!gettimeofday(&s_err_no_array[s_err_no_offset].tv, NULL));
    }

    return -err_no;
}

int err_get_last_err_no(void)
{
    lune_assert(s_err_no_offset != -1);

    return -s_err_no_array[s_err_no_offset].err_no;
}

const char *err_get_err_str(int err_no)
{
    err_no = -err_no;

    lune_assert(LUNE_ERR_NO_ERR < err_no && err_no < LUNE_ERR_MAX_ERR);

    return s_err_str_array[err_no];
}

int lune_get_err_cnt(void)
{
    return s_err_cnt;
}

#define ERR_TIME_MAX_BUF_LEN    (256)

void lune_dump_err(lune_err_dump_type_en dump_type)
{
    int cnt = s_err_cnt;
    int offset = (cnt > ERR_MAX_ERR_NO_NUM) ? ((cnt - 1) % ERR_MAX_ERR_NO_NUM) : 0;
    char buf[ERR_TIME_MAX_BUF_LEN];

    if (dump_type < LUNE_ERR_DUMP_TO_STDERR || dump_type >= LUNE_ERR_DUMP_MAX_TYPE) {
        return;
    }

    if (cnt <= 0) {
        return;
    }

    if (LUNE_ERR_DUMP_TO_STDERR == dump_type) {
        fprintf(stderr, "-------- Dump error start --------\n");
        for (; cnt > 0; cnt--, offset = (offset + 1) % ERR_MAX_ERR_NO_NUM) {
            sprintf(buf, "%ld.%06ld", s_err_no_array[offset].tv.tv_sec, s_err_no_array[offset].tv.tv_usec);
            fprintf(stderr, "%s: Error(%d),File(%s),Line(%d)\n", buf, s_err_no_array[offset].err_no, 
                s_err_no_array[offset].file_name, s_err_no_array[offset].line_no);
        }
        fprintf(stderr, "-------- Dump error end   --------\n");
    } else {
        /* LUNE_ERR_DUMP_TO_LOG */
        lune_log_level_en log_level = log_get_level();
        lune_log(log_level, "-------- Dump error start --------");
        for (; cnt > 0; cnt--, offset = (offset + 1) % ERR_MAX_ERR_NO_NUM) {
            sprintf(buf, "%ld.%06ld", s_err_no_array[offset].tv.tv_sec, s_err_no_array[offset].tv.tv_usec);
            lune_log(log_level, "%s: Error(%d),File(%s),Line(%d)", buf, s_err_no_array[offset].err_no, 
                s_err_no_array[offset].file_name, s_err_no_array[offset].line_no);
        }
        lune_log(log_level, "-------- Dump error end   --------");
    }
}

void lune_empty_err(void)
{
    s_err_no_offset = -1;
    s_err_cnt = 0;
    memset(s_err_no_array, 0x00, sizeof(err_no_t) * ERR_MAX_ERR_NO_NUM);
}

int lune_get_err_no(void)
{
    return err_get_last_err_no();
}

int lune_set_err_no_x(int err_no, const char *file_name, int line_no)
{
    return err_set_err_no(err_no, file_name, line_no);
}

const char *lune_get_err_str(int err_no)
{
    if (unlikely(LUNE_ERR_NO_ERR >= -err_no || -err_no >= LUNE_ERR_MAX_ERR)) {
        return NULL;
    }

    return err_get_err_str(err_no);
}

const char *lune_get_last_err_str(void)
{
    return err_get_err_str(err_get_last_err_no());
}
