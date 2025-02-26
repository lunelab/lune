/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 * 
 * Lune Test Interface Perf tool
 */

#include "lune/os/linux.h"

#include "tip/tip.h"

static struct option s_tip_opts[] =
{
    {"file", required_argument, 0, 'f'},
    {0, 0, 0, 0}
};

int main(int argc, char **argv)
{
    int c, flag = 0;
    const char *tip_conf_file = NULL;

    while (1) {
        int opt_index = 0;

        c = getopt_long(argc, argv, "f:", s_tip_opts, &opt_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'f':
            if (flag) {
                fprintf(stderr, "tip conf file already specified: %s", tip_conf_file);
                exit(EXIT_FAILURE);
            }

            tip_conf_file = optarg;
            flag = 1;
            break;
        default:
            fprintf(stderr, "invalid option: %c", (char)c);
            exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "invalid options: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(EXIT_FAILURE);
    }

    if (NULL == tip_conf_file) {
        fprintf(stderr, "no config file\n");
        exit(EXIT_FAILURE);
    }

    if (tip_parse_conf_file(tip_conf_file)) {
        exit(EXIT_FAILURE);
    }

    run_tip();

    return 0;
}
