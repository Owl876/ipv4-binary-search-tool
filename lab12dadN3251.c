#define _XOPEN_SOURCE 500
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ftw.h>
#include <sys/param.h>
#include <getopt.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include "plugin_api.h"
#define MAX_INDENT_LEVEL 128

// Функции для работы с плагинами и обработки директорий
int load_plugin(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
void initialize_plugins(const char *dir);
void parse_options(int argc, char *argv[]);
void traverse_directory(const char *dir);

typedef int (*process_file_func)(const char*, struct option*, size_t);
typedef int (*get_info_func)(struct plugin_info*);

// Структура для хранения данных плагина
typedef struct {
    void *lib_handle;
    struct plugin_info info;
    process_file_func process_file;
    struct option *plugin_options;
    size_t plugin_options_len;
    char *binary_ip; // Поле для хранения бинарного IP-адреса
} plugin;

plugin *loaded_plugins = NULL;
int plugin_count = 0;
int use_or = 0, use_not = 0;
int total_options = 0, specified_options = 0;

// Функция загрузки плагина
int load_plugin(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void) sb;
    (void) typeflag;
    (void) ftwbuf;

    if (!fpath) {
        fprintf(stderr, "Invalid file path\n");
        return 0;
    }

    if (typeflag == FTW_F && strstr(fpath, ".so") != NULL) {
        void *lib = dlopen(fpath, RTLD_LAZY);
        if (!lib) {
            fprintf(stderr, "dlopen() failed for %s: %s\n", fpath, dlerror());
            return 0;
        }

        get_info_func get_info = (get_info_func)dlsym(lib, "plugin_get_info");
        if (!get_info) {
            fprintf(stderr, "dlsym() failed for plugin_get_info: %s\n", dlerror());
            dlclose(lib);
            return 0;
        }

        process_file_func process_file = (process_file_func)dlsym(lib, "plugin_process_file");
        if (!process_file) {
            fprintf(stderr, "dlsym() failed for plugin_process_file: %s\n", dlerror());
            dlclose(lib);
            return 0;
        }

        struct plugin_info info = {0};
        if (get_info(&info) == -1) {
            fprintf(stderr, "Error in plugin_get_info\n");
            dlclose(lib);
            return 0;
        }

        loaded_plugins = realloc(loaded_plugins, sizeof(plugin) * (plugin_count + 1));
        loaded_plugins[plugin_count].info = info;
        loaded_plugins[plugin_count].process_file = process_file;
        loaded_plugins[plugin_count].lib_handle = lib;
        loaded_plugins[plugin_count].plugin_options = NULL;
        loaded_plugins[plugin_count].plugin_options_len = 0;
        loaded_plugins[plugin_count].binary_ip = NULL;
        plugin_count++;
        total_options += info.sup_opts_len;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    initialize_plugins("./");
    parse_options(argc, argv);

    if (specified_options == 0) {
        printf("No options found. Use -h for help\n");

        if (loaded_plugins) {
            for (int i = 0; i < plugin_count; i++) {
                if (loaded_plugins[i].plugin_options) free(loaded_plugins[i].plugin_options);
                if (loaded_plugins[i].binary_ip) free(loaded_plugins[i].binary_ip);
                dlclose(loaded_plugins[i].lib_handle);
            }
            free(loaded_plugins);
        }
        exit(EXIT_FAILURE);
    }

    traverse_directory(argv[argc-1]);

    if (loaded_plugins) {
        for (int i = 0; i < plugin_count; i++) {
            if (loaded_plugins[i].plugin_options) free(loaded_plugins[i].plugin_options);
            if (loaded_plugins[i].binary_ip) free(loaded_plugins[i].binary_ip);
            dlclose(loaded_plugins[i].lib_handle);
        }
        free(loaded_plugins);
    }

    return EXIT_SUCCESS;
}

// Инициализация плагинов из заданной директории
void initialize_plugins(const char *dir) {
    int res = nftw(dir, load_plugin, 10, FTW_PHYS);
    if (res < 0) {
        fprintf(stderr, "ntfw() failed: %s\n", strerror(errno));
    }
}

// Преобразование IPv4-адреса в бинарную строку
void convert_ipv4_to_binary(const char *ipv4_str, char *bin_str) {
    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, ipv4_str, &ipv4_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", ipv4_str);
        exit(EXIT_FAILURE);
    }

    unsigned char *bytes = (unsigned char *)&ipv4_addr.s_addr;
    for (int i = 0; i < 4; i++) {
        for (int j = 7; j >= 0; j--) {
            *bin_str++ = (bytes[i] & (1 << j)) ? '1' : '0';
        }
        if (i < 3) {
            *bin_str++ = '.';
        }
    }
    *bin_str = '\0';
}

// Парсинг опций командной строки и их распределение по плагинам
void parse_options(int argc, char *argv[]) {
    struct option *long_options = calloc(total_options + 2, sizeof(struct option));
    int copied = 0;

    for (int i = 0; i < plugin_count; i++) {
        for (size_t j = 0; j < loaded_plugins[i].info.sup_opts_len; j++) {
            long_options[copied] = loaded_plugins[i].info.sup_opts[j].opt;
            copied++;
        }
    }

    long_options[copied++] = (struct option){"ipv4-addr-bin", required_argument, 0, 0};

    int option_index = 0;
    int choice;

    char binary_ip[36];
    int binary_ip_set = 0;

    while ((choice = getopt_long(argc, argv, "vhP:OAN", long_options, &option_index)) != -1) {
        switch (choice) {
            case 0:
                for (int i = 0; i < plugin_count; i++) {
                    for (size_t j = 0; j < loaded_plugins[i].info.sup_opts_len; j++) {
                        if (strcmp(long_options[option_index].name, loaded_plugins[i].info.sup_opts[j].opt.name) == 0) {
                            loaded_plugins[i].plugin_options = realloc(loaded_plugins[i].plugin_options, (loaded_plugins[i].plugin_options_len + 1) * sizeof(struct option));
                            loaded_plugins[i].plugin_options[loaded_plugins[i].plugin_options_len] = long_options[option_index];
                            if (loaded_plugins[i].plugin_options[loaded_plugins[i].plugin_options_len].has_arg != 0) {
                                loaded_plugins[i].plugin_options[loaded_plugins[i].plugin_options_len].flag = (int *)optarg;
                            }
                            loaded_plugins[i].plugin_options_len++;
                            specified_options++;
                        }
                    }
                }
                if (strcmp(long_options[option_index].name, "ipv4-addr-bin") == 0) {
                    convert_ipv4_to_binary(optarg, binary_ip);
                    binary_ip_set = 1;
                }
                break;
            case 'h':
                printf("Usage: %s <plugin name> <options> <dir>\n", argv[0]);
                printf("Example: ./lab12dadN3251 --ipv4-addr-bin 192.168.8.1 <dir>\n");
                printf("<dir> - directory to search\n");
                printf("Available options: -P <dir> to change plugin, -h for help, -v for version info, -A for 'and', -O for 'or', -N for 'not'\n");

                for (int i = 0; i < plugin_count; i++) {
                    printf("Plugin purpose: %s\n", loaded_plugins[i].info.plugin_purpose);
                    for (size_t j = 0; j < loaded_plugins[i].info.sup_opts_len; j++)
                        printf("%s -- %s\n", loaded_plugins[i].info.sup_opts[j].opt.name, loaded_plugins[i].info.sup_opts[j].opt_descr);
                    printf("\n");
                }

                if (loaded_plugins) {
                    for (int i = 0; i < plugin_count; i++) {
                        if (loaded_plugins[i].plugin_options) free(loaded_plugins[i].plugin_options);
                        if (loaded_plugins[i].binary_ip) free(loaded_plugins[i].binary_ip);
                        dlclose(loaded_plugins[i].lib_handle);
                    }
                    free(loaded_plugins);
                }
                free(long_options);
                exit(EXIT_SUCCESS);
            case 'v':
                printf("Dobretskov Dmitriy N3251 Version 1.0\n");

                if (loaded_plugins) {
                    for (int i = 0; i < plugin_count; i++) {
                        if (loaded_plugins[i].plugin_options) free(loaded_plugins[i].plugin_options);
                        dlclose(loaded_plugins[i].lib_handle);
                    }
                    free(loaded_plugins);
                }
                free(long_options);
                exit(EXIT_SUCCESS);
            case 'P':
                if (specified_options > 0) {
                    fprintf(stderr, "-P must be before plugin opts!\n");
                    free(long_options);
                    specified_options = 0;
                    return;
                }

                for (int i = 0; i < plugin_count; i++) {
                    dlclose(loaded_plugins[i].lib_handle);
                }
                free(loaded_plugins);
                loaded_plugins = NULL;
                plugin_count = 0;
                total_options = 0;

                if (getenv("LAB1DEBUG") != NULL) fprintf(stderr, "New lib path: %s\n", optarg);
                free(long_options);
                initialize_plugins(optarg);
                long_options = calloc(total_options + 1, sizeof(struct option));
                copied = 0;
                for (int i = 0; i < plugin_count; i++) {
                    for (size_t j = 0; j < loaded_plugins[i].info.sup_opts_len; j++) {
                        long_options[copied] = loaded_plugins[i].info.sup_opts[j].opt;
                        copied++;
                    }
                }
                break;
            case 'O':
                use_or = 1;
                break;
            case 'A':
                use_or = 0;
                break;
            case 'N':
                use_not = 1;
                break;
            default:
                printf("Invalid option\n");
                break;
        }
    }

    if (binary_ip_set) {
        for (int i = 0; i < plugin_count; i++) {
            loaded_plugins[i].binary_ip = strdup(binary_ip);
        }
    }

    free(long_options);
}

// Функция отображения найденного файла
void display_entry(int level, int type, const char *path) {
    if (!strcmp(path, ".") || !strcmp(path, "..") || type != FTW_F)
        return;

    char indent[MAX_INDENT_LEVEL] = {0};
    memset(indent, ' ', MIN((size_t)level, MAX_INDENT_LEVEL));

    int match_count = 0;
    int total_success = 0;

    for (int i = 0; i < plugin_count; i++) {
        if (loaded_plugins[i].plugin_options_len > 0) {
            int result = loaded_plugins[i].process_file(path, loaded_plugins[i].plugin_options, loaded_plugins[i].plugin_options_len);
            if (result == -1) {
                fprintf(stderr, "Error in plugin! %s", strerror(errno));
                if (errno == EINVAL || errno == ERANGE)
                    loaded_plugins[i].plugin_options_len = 0;
            } else if (result == 0)
                match_count++;
            total_success++;
        }
    }

    if ((use_not && use_or && (match_count == 0)) || (use_not && !use_or && (match_count != total_success))) {
        printf("%sFound file: %s\n", indent, path);
    } else if ((!use_not && use_or && (match_count > 0)) || (!use_not && !use_or && (match_count == total_success))) {
        printf("%sFound file: %s\n", indent, path);
    }
}

// Callback-функция для nftw, вызывающая display_entry
int walk_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    if (!sb) return -1;
    display_entry(ftwbuf->level, typeflag, fpath);
    return 0;
}

// Функция для рекурсивного обхода директории
void traverse_directory(const char *dir) {
    int res = nftw(dir, walk_callback, 10, FTW_PHYS);
    if (res < 0) {
        fprintf(stderr, "ntfw() failed: %s\n", strerror(errno));
    }
}
