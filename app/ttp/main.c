/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Lune Reseau, Inc.
 * 
 * Lune Test Tcp Perf tool
 */

#include "lune/os/linux.h"

#include "ttp/ttp.h"

static struct option s_ttp_opts[] =
{
    {"file", required_argument, 0, 'f'},
    {0, 0, 0, 0}
};

int main(int argc, char **argv)
{
    int c, flag = 0;
    const char *ttp_conf_file = NULL;

    while (1) {
        int opt_index = 0;

        c = getopt_long(argc, argv, "f:", s_ttp_opts, &opt_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'f':
            if (flag) {
                fprintf(stderr, "ttp conf file already specified: %s", ttp_conf_file);
                exit(EXIT_FAILURE);
            }

            ttp_conf_file = optarg;
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

    if (NULL == ttp_conf_file) {
        fprintf(stderr, "no config file\n");
        exit(EXIT_FAILURE);
    }

    if (ttp_parse_conf_file(ttp_conf_file)) {
        exit(EXIT_FAILURE);
    }

    run_ttp();

    return 0;
}
