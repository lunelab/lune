/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __ERR_H__
#define __ERR_H__

#define ERR_SET_ERR(err_no)     err_set_err_no((err_no), __FILE__, __LINE__)
#define ERR_GET_LAST_ERR()      err_get_last_err_no()
#define ERR_GET_ERR_STR(err_no) err_get_err_str(err_no)
#define ERR_GET_LAST_ERR_STR()  err_get_err_str(err_get_last_err_no())

int err_set_err_no(int err_no, const char *file_name, int line_no);
int err_get_last_err_no(void);

const char *err_get_err_str(int err_no);

#endif