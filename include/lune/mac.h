/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 */

#ifndef __LUNE_MAC_H__
#define __LUNE_MAC_H__

#include "lune/common.h"
#include "lune/id.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LUNE_ETH_TYPE_ARP       0x0806
#define LUNE_ETH_TYPE_IPV4      0x0800
#define LUNE_ETH_TYPE_IPV6      0x86dd
#define LUNE_ETH_TYPE_VLAN      0x8100

#define LUNE_MAC_TO_LL(mac, ll)                         \
    do {                                                \
        ll = ((unsigned long long)((mac)[0]) << 40)     \
            | ((unsigned long long)((mac)[1]) << 32)    \
            | ((unsigned long long)((mac)[2]) << 24)    \
            | ((unsigned long long)((mac)[3]) << 16)    \
            | ((unsigned long long)((mac)[4]) << 8)     \
            | (unsigned long long)((mac)[5]);           \
    } while (0)

#define LUNE_LL_TO_MAC(ll, mac)                         \
    do {                                                \
        (mac)[0] = ((ll) & 0xff0000000000) >> 40;       \
        (mac)[1] = ((ll) & 0xff00000000) >> 32;         \
        (mac)[2] = ((ll) & 0xff000000) >> 24;           \
        (mac)[3] = ((ll) & 0xff0000) >> 16;             \
        (mac)[4] = ((ll) & 0xff00) >> 8;                \
        (mac)[5] = ((ll) & 0xff);                       \
    } while (0)

#define LUNE_BROADCAST_MAC_LL   (0xffffffffffff)

#define LUNE_MAC_VID_NONE       (0)
#define LUNE_MAC_VID_RSVD       (0xfff)

#define LUNE_MAC_CMP(mac1, mac2)                                                \
    (!((*(const unsigned int *)(&((const unsigned char *)mac1)[0])              \
        == *(const unsigned int *)(&((const unsigned char *)mac2)[0]))          \
        && (*(const unsigned short *)(&((const unsigned char *)mac1)[4])        \
        == *(const unsigned short *)(&((const unsigned char *)mac2)[4]))))

#define LUNE_MAC_CPY(dst_mac, src_mac)                                          \
    do {                                                                        \
        *(unsigned int *)(&((unsigned char *)dst_mac)[0]) =                     \
            *(const unsigned int *)(&((const unsigned char *)src_mac)[0]);      \
        *(unsigned short *)(&((unsigned char *)dst_mac)[4]) =                   \
             *(const unsigned short *)(&((const unsigned char *)src_mac)[4]);   \
    } while (0)

#define LUNE_MAC_ADDR_STR_LEN   18
#define LUNE_MAC_ADDR_LEN       6
typedef unsigned char lune_mac_addr_t[LUNE_MAC_ADDR_LEN];

#define LUNE_ETH_HDR_LEN        (sizeof(lune_eth_hdr_t))
#define LUNE_MAX_ETH_HDR_LEN    22
#define LUNE_VLAN_FIELD_LEN     (sizeof(lune_vlan_field_t))
#define LUNE_QINQ_FIELD_LEN     (LUNE_VLAN_FIELD_LEN * 2)

typedef enum _lune_mac_opt {
    /* get options */
    LUNE_MAC_OPT_GET_MTU = 0,
    LUNE_MAC_OPT_GET_STATS,
    LUNE_MAC_OPT_GET_INFO,
    LUNE_MAC_OPT_GET_SUB_INFO,
    /* set options */
    LUNE_MAC_OPT_SET_MTU = 256,
} lune_mac_opt_en;

typedef struct _lune_mac_stats {
    unsigned long long pkt_in;
    unsigned long long pkt_out;
    unsigned long long byte_in;
    unsigned long long byte_out;
} lune_mac_stats_t;

#pragma pack(1)
typedef struct _lune_eth_hdr {
    lune_mac_addr_t dst_mac;
    lune_mac_addr_t src_mac;
    unsigned short type;
    unsigned char data[0];
} lune_eth_hdr_t;

typedef struct _lune_vlan_field {
    unsigned short type;
    unsigned short tci;
    unsigned char data[0];
} lune_vlan_field_t;
#pragma pack()

typedef struct _lune_mac_info {
    lune_mac_addr_t mac;
    unsigned short outer_vid;   /* vlan if not LUNE_MAC_VID_NONE */
    unsigned short inner_vid;   /* qinq if not LUNE_MAC_VID_NONE */
} lune_mac_info_t;

typedef struct _lune_mac_sub_info {
    unsigned int id;
    lune_id_type_en type;
} lune_mac_sub_info_t;

typedef struct _lune_mac_sendto_arg {
    unsigned short type;
} lune_mac_sendto_arg_t;

typedef void (*lune_mac_socket_recv_callback_func_t)(void *, const unsigned char *, unsigned int);
typedef struct _lune_mac_socket_callback {
    lune_mac_socket_recv_callback_func_t recv;
    void *data;
} lune_mac_socket_callback_t;

int lune_str_to_mac(const char *str, lune_mac_addr_t mac);
char *lune_mac_to_str(const lune_mac_addr_t mac, char *buf, int buf_size);

unsigned int lune_add_mac(const lune_mac_addr_t mac,
    lune_id_type_en sub_type, unsigned int sub_id);
unsigned int lune_add_mac_with_vlan(const lune_mac_addr_t mac,
    lune_id_type_en sub_type, unsigned int sub_id, unsigned short vid);
unsigned int lune_add_mac_with_qinq(const lune_mac_addr_t mac, lune_id_type_en sub_type,
    unsigned int sub_id, unsigned short outer_vid, unsigned short inner_vid);
int lune_del_mac(unsigned int id);

int lune_get_mac(const lune_mac_addr_t mac, lune_id_type_en sub_type,
    unsigned int sub_id, unsigned int *mac_id);
int lune_get_mac_with_vlan(const lune_mac_addr_t mac, lune_id_type_en sub_type,
    unsigned int sub_id, unsigned short vid, unsigned int *mac_id);
int lune_get_mac_with_qinq(const lune_mac_addr_t mac, lune_id_type_en sub_type,
    unsigned int sub_id, unsigned short outer_vid, unsigned short inner_vid, unsigned int *mac_id);

int lune_enable_mac(unsigned int id);
int lune_disable_mac(unsigned int id);

int lune_get_mac_opt(unsigned int id,
    lune_mac_opt_en opt, void *opt_val, unsigned int opt_len);
int lune_set_mac_opt(unsigned int id,
    lune_mac_opt_en opt, const void *opt_val, unsigned int opt_len);

#ifdef __cplusplus
}
#endif

#endif