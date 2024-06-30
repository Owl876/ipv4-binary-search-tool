#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "plugin_api.h"

static char *g_purpose = "Check if a file contains specified IPv4 address in binary form";
static char *g_author = "Dobretskov Dmitriy";

static struct plugin_option g_options[] = {
    {
        {"ipv4-addr-bin", required_argument, 0, 0},
        "IPv4 address to search for in binary form"
    }
};

static int g_options_len = sizeof(g_options) / sizeof(g_options[0]);

int plugin_get_info(struct plugin_info *ppi) {
    if (!ppi) {
        fprintf(stderr, "ERROR: Invalid argument\n");
        return -1;
    }

    ppi->plugin_purpose = g_purpose;
    ppi->plugin_author = g_author;
    ppi->sup_opts_len = g_options_len;
    ppi->sup_opts = g_options;

    return 0;
}

void convert_ip_to_binary(const char* ip, char* binary_ip) {
    unsigned char bytes[4];
    inet_pton(AF_INET, ip, bytes);

    char bin_part[9];
    for (int i = 0; i < 4; i++) {
        for (int j = 7; j >= 0; j--) {
            bin_part[7 - j] = ((bytes[i] >> j) & 1) ? '1' : '0';
        }
        bin_part[8] = '\0';
        strcat(binary_ip, bin_part);
        if (i < 3) {
            strcat(binary_ip, ".");
        }
    }
}

int plugin_process_file(const char *fname, struct option in_opts[], size_t in_opts_len) {
    if (!fname || !in_opts || !in_opts_len) {
        errno = EINVAL;
        return -1;
    }

    const char *ip = NULL;
    char binary_ip[36] = {0}; // 32 бита для IP + 3 точки + 1 символ конца строки

    for (size_t i = 0; i < in_opts_len; i++) {
        if (strcmp(in_opts[i].name, "ipv4-addr-bin") == 0) {
            ip = (char *) in_opts[i].flag;
        } else {
            errno = EINVAL;
            return -1;
        }
    }

    if (!ip) {
        errno = EINVAL;
        return -1;
    }

    // Конвертируем IP-адрес в бинарный вид
    convert_ip_to_binary(ip, binary_ip);

    FILE *f = fopen(fname, "rb");
    if (!f) {
        return -1;
    }

    char buf[37]; // 32 бита для IP + 3 точки + 1 символ конца строки
    size_t len_ip = strlen(ip);
    size_t len_bin_ip = strlen(binary_ip);

    // Поиск обычного формата IP-адреса
    while (fread(buf, sizeof(char), len_ip, f) == len_ip) {
        buf[len_ip] = '\0';
        if (strcmp(buf, ip) == 0) {
            fclose(f);
            return 0;
        }
        fseek(f, 1 - len_ip, SEEK_CUR);
    }

    // Сбросить указатель файла
    fseek(f, 0, SEEK_SET);

    // Поиск бинарного формата IP-адреса
    while (fread(buf, sizeof(char), len_bin_ip, f) == len_bin_ip) {
        buf[len_bin_ip] = '\0';
        if (strcmp(buf, binary_ip) == 0) {
            fclose(f);
            return 0;
        }
        fseek(f, 1 - len_bin_ip, SEEK_CUR);
    }

    fclose(f);
    return 1;
}
