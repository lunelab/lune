/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __CSUM_H__
#define __CSUM_H__

unsigned int csum_partial(const unsigned char *buf, int len, unsigned int sum);

unsigned short csum_fold(unsigned int sum);

#endif