/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_SSL_H__
#define __LUNE_SSL_H__

#include "lune/socket.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _lune_ssl_version {
    /* SSLv3 */
    LUNE_SSL_VERSION_SSLV3 = 0,
    /*
        default method if unspecified, which either negotiates highest
        available SSL/TLS version or default to TLSV1, depending on ssl
        library version
    */
    LUNE_SSL_VERSION_TLS,
    /* TLSv1.0 */
    LUNE_SSL_VERSION_TLSV1,
    /* TLSv1.1 */
    LUNE_SSL_VERSION_TLSV1_1,
    /* TLSv1.2 */
    LUNE_SSL_VERSION_TLSV1_2,
    /* TLSv1.3 */
    LUNE_SSL_VERSION_TLSV1_3,
    LUNE_SSL_VERSION_MAX,
} lune_ssl_version_en;

typedef enum _lune_ssl_type {
    LUNE_SSL_CLIENT = 0,
    LUNE_SSL_SERVER,
    LUNE_SSL_MAX,
} lune_ssl_type_en;

typedef enum _lune_ssl_opt {
    /* get options */
    LUNE_SSL_OPT_GET_SESS_CACHE_MODE = 0,
    /* set options */
    LUNE_SSL_OPT_SET_CERT = 256,
    LUNE_SSL_OPT_SET_CIPHERS,
    LUNE_SSL_OPT_SET_SESS_CACHE_MODE,
    LUNE_SSL_OPT_SET_QUIET_CLOSE,
    LUNE_SSL_OPT_SET_NORMAL_CLOSE,
} lune_ssl_opt_en;

typedef enum _lune_ssl_cipher {
    LUNE_SSL_CIPHER_RSA_WITH_AES_128_CBC_SHA = 0,
    LUNE_SSL_CIPHER_RSA_WITH_AES_256_CBC_SHA,
    LUNE_SSL_CIPHER_SSL_RSA_WITH_NULL_MD5,
    LUNE_SSL_CIPHER_SSL_RSA_WITH_NULL_SHA,
    LUNE_SSL_CIPHER_TLS_RSA_WITH_IDEA_CBC_SHA,
    LUNE_SSL_CIPHER_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    LUNE_SSL_CIPHER_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    LUNE_SSL_CIPHER_TLS_DH_ANON_WITH_AES_256_CBC_SHA,
    LUNE_SSL_CIPHER_TLS_RSA_WITH_AES_128_CBC_SHA256,
    LUNE_SSL_CIPHER_TLS_RSA_WITH_AES_256_CBC_SHA256,
    LUNE_SSL_CIPHER_TLS_RSA_WITH_AES_128_GCM_SHA256,
    LUNE_SSL_CIPHER_TLS_RSA_WITH_AES_256_GCM_SHA384,
    LUNE_SSL_CIPHER_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    LUNE_SSL_CIPHER_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    LUNE_SSL_CIPHER_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    LUNE_SSL_CIPHER_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    LUNE_SSL_CIPHER_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    LUNE_SSL_CIPHER_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    LUNE_SSL_CIPHER_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    LUNE_SSL_CIPHER_MAX,
} lune_ssl_cipher_en;

typedef enum _lune_ssl_sess_cache_mode {
    LUNE_SSL_SESS_CACHE_OFF = 0,
    LUNE_SSL_SESS_CACHE_CLIENT,
    LUNE_SSL_SESS_CACHE_SERVER,
    LUNE_SSL_SESS_CACHE_MAX,
} lune_ssl_sess_cache_mode_en;

/* 1 - user data */
typedef void (*lune_ssl_socket_connect_callback_func_t)(void *);
/* 1 - fd, 2 - source ip & port, 3 - pointer to store user data */
typedef void (*lune_ssl_socket_accept_callback_func_t)(unsigned int, lune_socket_addr_t *, void **);
/* 1 - user data, 2 - buf, 3 - buflen */
typedef void (*lune_ssl_socket_recv_callback_func_t)(void *, const unsigned char *, unsigned int);
/* 1 - user data */
typedef void (*lune_ssl_socket_closewait_callback_func_t)(void *);
/* 1 - user data, 2 - error type */
typedef void (*lune_ssl_socket_error_callback_func_t)(void *, int);
/* 1 - user data */
typedef void (*lune_ssl_socket_close_callback_func_t)(void *, unsigned int);

typedef struct _lune_ssl_socket_callback {
    lune_ssl_socket_connect_callback_func_t connect;
    lune_ssl_socket_accept_callback_func_t accept;
    lune_ssl_socket_recv_callback_func_t recv;
    lune_ssl_socket_closewait_callback_func_t closewait;
    lune_ssl_socket_error_callback_func_t error;
/* normal close with close_notify message and tcp 4 handshakes */
#define LUNE_SSL_SOCKET_CLOSE_NORMAL                0
/* reset close, either send or receive tcp RST packet */
#define LUNE_SSL_SOCKET_CLOSE_RST                   1
/* simply close it without interaction */
#define LUNE_SSL_SOCKET_CLOSE_QUIET                 2
    lune_ssl_socket_close_callback_func_t close;
    void *data;
} lune_ssl_socket_callback_t;

typedef struct _lune_ssl_cert {
    char *cert_file;
    char *priv_key;
} lune_ssl_cert_t;

typedef struct _lune_ssl_ciphers {
#define LUNE_SSL_CIPHERS_MAX_NUM    (16)
    lune_ssl_cipher_en *array;
    unsigned int num;
} lune_ssl_ciphers_t;

unsigned int lune_add_ssl(lune_ssl_version_en ver, lune_ssl_type_en type);
int lune_del_ssl(unsigned int id);

int lune_get_ssl_opt(unsigned int id,
    lune_ssl_opt_en opt, unsigned char *opt_val, unsigned int opt_len);
int lune_set_ssl_opt(unsigned int id,
    lune_ssl_opt_en opt, const unsigned char *opt_val, unsigned int opt_len);

const char *lune_get_ssl_cipher_str(lune_ssl_cipher_en cipher);

#ifdef __cplusplus
}
#endif

#endif