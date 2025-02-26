/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 * 
 * Lune Test Tcp Perf tool
 */

#ifndef __SSL_H__
#define __SSL_H__

unsigned int ttp_ssl_create_client_ssl(lune_ssl_version_en ver);
unsigned int ttp_ssl_create_server_ssl(lune_ssl_version_en ver);
int ttp_ssl_delete_client_ssl(unsigned int id);
int ttp_ssl_delete_server_ssl(unsigned int id);

int ttp_ssl_init(void);
void ttp_ssl_fini(void);

#endif