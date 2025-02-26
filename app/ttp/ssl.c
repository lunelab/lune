/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 * 
 * Lune Test Tcp Perf tool
 */

#include "lune/assert.h"
#include "lune/err.h"
#include "lune/log.h"
#include "lune/os/linux.h"
#include "lune/ssl.h"

#include "ttp/ssl.h"

#define TTP_SSL_SOCKET_SSL_CERT_FILE    "/tmp/ssl_cert_file.XXXXXX"
#define TTP_SSL_SOCKET_SSL_PRIV_KEY     "/tmp/ssl_priv_key.XXXXXX"

/* leaf.pem from OpenSSL, only for test purpose */
static const char *s_ttp_ssl_cert_file_content =
"-----BEGIN CERTIFICATE-----\n"
"MIIDfjCCAmagAwIBAgIJAKRNsDKacUqNMA0GCSqGSIb3DQEBCwUAMFoxCzAJBgNV\n"
"BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX\n"
"aWRnaXRzIFB0eSBMdGQxEzARBgNVBAMTCnN1YmludGVyQ0EwHhcNMTUwNzAyMTMx\n"
"OTQ5WhcNMzUwNzAyMTMxOTQ5WjBUMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29t\n"
"ZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYD\n"
"VQQDEwRsZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv0Qo9WC/\n"
"BKA70LtQJdwVGSXqr9dut3cQmiFzTb/SaWldjOT1sRNDFxSzdTJjU/8cIDEZvaTI\n"
"wRxP/dtVQLjc+4jzrUwz93NuZYlsEWUEUg4Lrnfs0Nz50yHk4rJhVxWjb8Ii/wRB\n"
"ViWHFExP7CwTkXiTclC1bCqTuWkjxF3thTfTsttRyY7qNkz2JpNx0guD8v4otQoY\n"
"jA5AEZvK4IXLwOwxol5xBTMvIrvvff2kkh+c7OC2QVbUTow/oppjqIKCx2maNHCt\n"
"LFTJELf3fwtRJLJsy4fKGP0/6kpZc8Sp88WK4B4FauF9IV1CmoAJUC1vJxhagHIK\n"
"fVtFjUWs8GPobQIDAQABo00wSzAJBgNVHRMEAjAAMB0GA1UdDgQWBBQcHcT+8SVG\n"
"IRlN9YTuM9rlz7UZfzAfBgNVHSMEGDAWgBTpZ30QdMGarrhMPwk+HHAV3R8aTzAN\n"
"BgkqhkiG9w0BAQsFAAOCAQEAGjmSkF8is+v0/RLcnSRiCXENz+yNi4pFCAt6dOtT\n"
"6Gtpqa1tY5It9lVppfWb26JrygMIzOr/fB0r1Q7FtZ/7Ft3P6IXVdk3GDO0QsORD\n"
"2dRAejhYpc5c7joHxAw9oRfKrEqE+ihVPUTcfcIuBaalvuhkpQRmKP71ws5DVzOw\n"
"QhnMd0TtIrbKHaNQ4kNsmSY5fQolwB0LtNfTus7OEFdcZWhOXrWImKXN9jewPKdV\n"
"mSG34NfXOnA6qx0eQg06z+TkdrptH6j1Va2vS1/bL+h1GxjpTHlvTGaZYxaloIjw\n"
"y/EzY5jygRoABnR3eBm15CYZwwKL9izIq1H3OhymEi/Ycg==\n"
"-----END CERTIFICATE-----\n";

/* leaf.key from OpenSSL, only for test purpose */
static const char *s_ttp_ssl_priv_key_content =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEpAIBAAKCAQEAv0Qo9WC/BKA70LtQJdwVGSXqr9dut3cQmiFzTb/SaWldjOT1\n"
"sRNDFxSzdTJjU/8cIDEZvaTIwRxP/dtVQLjc+4jzrUwz93NuZYlsEWUEUg4Lrnfs\n"
"0Nz50yHk4rJhVxWjb8Ii/wRBViWHFExP7CwTkXiTclC1bCqTuWkjxF3thTfTsttR\n"
"yY7qNkz2JpNx0guD8v4otQoYjA5AEZvK4IXLwOwxol5xBTMvIrvvff2kkh+c7OC2\n"
"QVbUTow/oppjqIKCx2maNHCtLFTJELf3fwtRJLJsy4fKGP0/6kpZc8Sp88WK4B4F\n"
"auF9IV1CmoAJUC1vJxhagHIKfVtFjUWs8GPobQIDAQABAoIBAB1fCiskQDElqgnT\n"
"uesWcOb7u55lJstlrVb97Ab0fgtR8tvADTq0Colw1F4a7sXnVxpab+l/dJSzFFWX\n"
"aPAXc1ftH/5sxU4qm7lb8Qx6xr8TCRgxslwgkvypJ8zoN6p32DFBTr56mM3x1Vx4\n"
"m41Y92hPa9USL8n8f9LpImT1R5Q9ShI/RUCowPyzhC6OGkFSBJu72nyA3WK0znXn\n"
"q5TNsTRdJLOug7eoJJvhOPfy3neNQV0f2jQ+2wDKCYvn6i4j9FSLgYC/vorqofEd\n"
"vFBHxl374117F6DXdBChyD4CD5vsplB0zcExRUCT5+iBqf5uc8CbLHeyNk6vSaf5\n"
"BljHWsECgYEA93QnlKsVycgCQqHt2q8EIZ5p7ksGYRVfBEzgetsNdpxvSwrLyLQE\n"
"L5AKG3upndOofCeJnLuQF1j954FjCs5Y+8Sy2H1D1EPrHSBp4ig2F5aOxT3vYROd\n"
"v+/mF4ZUzlIlv3jNDz5IoLaxm9vhXTtLLUtQyTueGDmqwlht0Kr3/gcCgYEAxd86\n"
"Q23jT4DmJqUl+g0lWdc2dgej0jwFfJ2BEw/Q55vHjqj96oAX5QQZFOUhZU8Otd/D\n"
"lLzlsFn0pOaSW/RB4l5Kv8ab+ZpxfAV6Gq47nlfzmEGGx4wcoL0xkHufiXg0sqaG\n"
"UtEMSKFhxPQZhWojUimK/+YIF69molxA6G9miOsCgYEA8mICSytxwh55qE74rtXz\n"
"1AJZfKJcc0f9tDahQ3XBsEb29Kh0h/lciEIsxFLTB9dFF6easb0/HL98pQElxHXu\n"
"z14SWOAKSqbka7lOPcppgZ1l52oNSiduw4z28mAQPbBVbUGkiqPVfCa3vhUYoLvt\n"
"nUZCsXoGF3CVBJydpGFzXI0CgYEAtt3Jg72PoM8YZEimI0R462F4xHXlEYtE6tjJ\n"
"C+vG/fU65P4Kw+ijrJQv9d6YEX+RscXdg51bjLJl5OvuAStopCLOZBPR3Ei+bobF\n"
"RNkW4gyYZHLSc6JqZqbSopuNYkeENEKvyuPFvW3f5FxPJbxkbi9UdZCKlBEXAh/O\n"
"IMGregcCgYBC8bS7zk6KNDy8q2uC/m/g6LRMxpb8G4jsrcLoyuJs3zDckBjQuLJQ\n"
"IOMXcQBWN1h+DKekF2ecr3fJAJyEv4pU4Ct2r/ZTYFMdJTyAbjw0mqOjUR4nsdOh\n"
"t/vCbt0QW3HXYTcVdCnFqBtelKnI12KoC0jAO9EAJGZ6kE/NwG6dQg==\n"
"-----END RSA PRIVATE KEY-----\n";

static char s_ttp_ssl_cert_file[] = TTP_SSL_SOCKET_SSL_CERT_FILE;
static char s_ttp_ssl_priv_key[] = TTP_SSL_SOCKET_SSL_PRIV_KEY;

unsigned int ttp_ssl_create_client_ssl(lune_ssl_version_en ver)
{
    ;
    lune_ssl_ciphers_t ciphers;
    lune_ssl_cipher_en cipher_array[3];
    lune_ssl_cert_t cert;
    lune_ssl_sess_cache_mode_en mode;
    unsigned int id;
    int err;

    if (LUNE_INVALID_ID == (id = lune_add_ssl(ver, LUNE_SSL_CLIENT))) {
        lune_log(LUNE_DBG, "failed to create client ssl: %s", lune_get_last_err_str());
        goto ERR_1;
    }

    cipher_array[0] = LUNE_SSL_CIPHER_RSA_WITH_AES_256_CBC_SHA;
    cipher_array[1] = LUNE_SSL_CIPHER_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
    cipher_array[2] = LUNE_SSL_CIPHER_TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
    ciphers.array = cipher_array;
    ciphers.num = 3;
    if (0 != (err = lune_set_ssl_opt(id,
        LUNE_SSL_OPT_SET_CIPHERS, (unsigned char *)&ciphers, sizeof(ciphers)))) {
        lune_log(LUNE_DBG, "failed to set ciphers on client ssl: %s", lune_get_err_str(err));
        goto ERR_2;
    }

    cert.cert_file = s_ttp_ssl_cert_file;
    cert.priv_key = s_ttp_ssl_priv_key;
    if (0 != (err = lune_set_ssl_opt(id,
        LUNE_SSL_OPT_SET_CERT, (unsigned char *)&cert, sizeof(cert)))) {
        lune_log(LUNE_DBG, "failed to set certificate on client ssl: %s", lune_get_err_str(err));
        goto ERR_2;
    }

    mode = LUNE_SSL_SESS_CACHE_CLIENT;
    if (0 != (err = lune_set_ssl_opt(id,
        LUNE_SSL_OPT_SET_SESS_CACHE_MODE, (unsigned char *)&mode, sizeof(mode)))) {
        lune_log(LUNE_DBG, "failed to set session cache mode on client ssl: %s", lune_get_err_str(err));
        goto ERR_2;
    }

    return id;

ERR_2:
    lune_assert(!lune_del_ssl(id));

ERR_1:
    return LUNE_INVALID_ID;
}

unsigned int ttp_ssl_create_server_ssl(lune_ssl_version_en ver)
{
    lune_ssl_ciphers_t ciphers;
    lune_ssl_cipher_en cipher_array[3];
    lune_ssl_cert_t cert;
    unsigned int id;
    int err;

    if (LUNE_INVALID_ID == (id = lune_add_ssl(ver, LUNE_SSL_SERVER))) {
        lune_log(LUNE_DBG, "failed to create server ssl: %s", lune_get_last_err_str());
        goto ERR_1;
    }

    cipher_array[0] = LUNE_SSL_CIPHER_RSA_WITH_AES_256_CBC_SHA;
    cipher_array[1] = LUNE_SSL_CIPHER_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
    cipher_array[2] = LUNE_SSL_CIPHER_TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
    ciphers.array = cipher_array;
    ciphers.num = 3;
    if (0 != (err = lune_set_ssl_opt(id,
        LUNE_SSL_OPT_SET_CIPHERS, (unsigned char *)&ciphers, sizeof(ciphers)))) {
        lune_log(LUNE_DBG, "failed to set ciphers on server ssl: %s", lune_get_err_str(err));
        goto ERR_2;
    }

    cert.cert_file = s_ttp_ssl_cert_file;
    cert.priv_key = s_ttp_ssl_priv_key;
    if (0 != (err = lune_set_ssl_opt(id,
        LUNE_SSL_OPT_SET_CERT, (unsigned char *)&cert, sizeof(cert)))) {
        lune_log(LUNE_DBG, "failed to set certificate on server ssl: %s", lune_get_err_str(err));
        goto ERR_2;
    }

    return id;

ERR_2:
    lune_assert(!lune_del_ssl(id));

ERR_1:
    return LUNE_INVALID_ID;
}

int ttp_ssl_delete_client_ssl(unsigned int id)
{
    return lune_del_ssl(id);
}

int ttp_ssl_delete_server_ssl(unsigned int id)
{
    return lune_del_ssl(id);
}

static int ttp_ssl_create_ssl_files(void)
{
    int err;
    int cert_file_fd, priv_key_fd, cert_file_size, priv_key_size;

    strcpy(s_ttp_ssl_cert_file, TTP_SSL_SOCKET_SSL_CERT_FILE);
    if (-1 == (cert_file_fd = mkstemp((char *)s_ttp_ssl_cert_file))) {
        lune_log(LUNE_DBG, "failed to create tmp file %s: %s", strerror(errno));
        err = lune_set_err_no(LUNE_ERR_SYS_ERR);
        goto ERR_1;
    }

    cert_file_size = strlen(s_ttp_ssl_cert_file_content);
    if (cert_file_size != write(cert_file_fd, s_ttp_ssl_cert_file_content, cert_file_size)) {
        err = lune_set_err_no(LUNE_ERR_SYS_ERR);
        goto ERR_2;
    }

    strcpy(s_ttp_ssl_priv_key, TTP_SSL_SOCKET_SSL_PRIV_KEY);
    if (-1 == (priv_key_fd = mkstemp((char *)s_ttp_ssl_priv_key))) {
        err = lune_set_err_no(LUNE_ERR_SYS_ERR);
        goto ERR_2;
    }

    priv_key_size = strlen(s_ttp_ssl_priv_key_content);
    if (priv_key_size != write(priv_key_fd, s_ttp_ssl_priv_key_content, priv_key_size)) {
        err = lune_set_err_no(LUNE_ERR_SYS_ERR);
        goto ERR_3;
    }

    close(priv_key_fd);
    close(cert_file_fd);

    return 0;

ERR_3:
    unlink(s_ttp_ssl_priv_key);
    close(priv_key_fd);

ERR_2:
    unlink(s_ttp_ssl_cert_file);
    close(cert_file_fd);

ERR_1:
    return err;
}

static void ttp_ssl_delete_ssl_files(void)
{
    unlink(s_ttp_ssl_priv_key);
    unlink(s_ttp_ssl_cert_file);
}

int ttp_ssl_init(void)
{
    return ttp_ssl_create_ssl_files();
}

void ttp_ssl_fini(void)
{
    ttp_ssl_delete_ssl_files();
}
