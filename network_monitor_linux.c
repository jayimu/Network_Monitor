#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <locale.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include <curl/curl.h>

#define MAX_PATH 4096
#define MAX_CMDLINE 4096
#define MAX_PROC_NAME 256
#define MAX_IPS 32
#define DEFAULT_NOTIFY_INTERVAL 300  // 默认通知间隔（秒）
#define MAX_MESSAGE_SIZE 8192
#define MAX_FD_PATH 4096
#define MAX_DIRENT_NAME 256
#define DNS_RESOLVE_INTERVAL 5       // 域名DNS刷新间隔（秒）
#define MAX_SEEN_IPS 2048            // 全局模式下记录的远程IP上限

typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[MAX_PROC_NAME];
    char path[MAX_PATH];
    char *cmdline;
    uid_t uid;
    char username[256];
} ProcessInfo;

typedef struct {
    char *data;
    size_t size;
} CurlBuffer;

typedef struct {
    int used;
    char remote_ip[INET_ADDRSTRLEN];
    char local_ip[INET_ADDRSTRLEN];
    unsigned short local_port;
    unsigned short remote_port;
    pid_t pid;
    char name[MAX_PROC_NAME];
    char path[MAX_PATH];
} SeenIpInfo;

volatile sig_atomic_t running = 1;
time_t last_notification = 0;
int notify_interval = DEFAULT_NOTIFY_INTERVAL;
char *webhook_url = NULL;
int silent_mode = 0;

SeenIpInfo seen_infos[MAX_SEEN_IPS] = {0};

void setup_locale() {
    setlocale(LC_ALL, "zh_CN.UTF-8");
    printf("\033[0m");
}

int check_root() {
    if (geteuid() != 0) {
        printf("需要root权限运行此程序\n");
        printf("请使用 sudo 运行\n");
        return 0;
    }
    return 1;
}

char* read_cmdline(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

    char *cmdline = malloc(MAX_CMDLINE);
    if (!cmdline) {
        fclose(fp);
        return NULL;
    }

    size_t len = fread(cmdline, 1, MAX_CMDLINE - 1, fp);
    fclose(fp);

    if (len <= 0) {
        free(cmdline);
        return NULL;
    }

    cmdline[len] = '\0';
    return cmdline;
}

void read_exe_path(pid_t pid, char *path, size_t size) {
    char link_path[MAX_PATH];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(link_path, path, size - 1);
    if (len > 0) {
        path[len] = '\0';
    } else {
        strncpy(path, "无法获取路径", size);
    }
}

void get_process_status(pid_t pid, ProcessInfo *info) {
    char path[MAX_PATH];
    char line[256];
    info->ppid = 0;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Name:", 5) == 0) {
                sscanf(line, "Name: %255s", info->name);
            } else if (strncmp(line, "PPid:", 5) == 0) {
                sscanf(line, "PPid: %d", &info->ppid);
            } else if (strncmp(line, "Uid:", 4) == 0) {
                sscanf(line, "Uid: %d", &info->uid);
            }
        }
        fclose(f);

        struct passwd *pw = getpwuid(info->uid);
        if (pw) {
            strncpy(info->username, pw->pw_name, sizeof(info->username) - 1);
        } else {
            snprintf(info->username, sizeof(info->username), "%d", info->uid);
        }
    }
}

void get_process_info(pid_t pid, ProcessInfo *info) {
    memset(info, 0, sizeof(*info));
    info->pid = pid;
    get_process_status(pid, info);
    read_exe_path(pid, info->path, sizeof(info->path));
    info->cmdline = read_cmdline(pid);
}

void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

void init_curl_buffer(CurlBuffer *buf) {
    buf->data = malloc(1);
    buf->size = 0;
    if (buf->data) buf->data[0] = '\0';
}

size_t curl_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    CurlBuffer *buf = (CurlBuffer *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) {
        printf("内存分配失败\n");
        return 0;
    }

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    return realsize;
}

void send_feishu_notification(const char *message) {
    if (!webhook_url || !message) return;

    time_t current_time = time(NULL);
    if (current_time - last_notification < notify_interval) return;

    CURL *curl = curl_easy_init();
    if (curl) {
        CurlBuffer buf;
        init_curl_buffer(&buf);

        char post_data[4096];
        snprintf(post_data, sizeof(post_data),
                 "{\"msg_type\":\"text\",\"content\":{\"text\":\"%s\"}}", message);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, webhook_url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&buf);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "发送飞书通知失败: %s\n", curl_easy_strerror(res));
        } else {
            last_notification = current_time;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(buf.data);
    }
}

int resolve_domain(const char *domain, char *ip_list[], int max_ips) {
    struct addrinfo hints, *result, *rp;
    int ip_count = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int s = getaddrinfo(domain, NULL, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "域名解析失败: %s\n", gai_strerror(s));
        return 0;
    }

    for (rp = result; rp != NULL && ip_count < max_ips; rp = rp->ai_next) {
        struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
        ip_list[ip_count] = strdup(inet_ntoa(addr->sin_addr));
        if (ip_list[ip_count]) {
            ip_count++;
        }
    }

    freeaddrinfo(result);
    return ip_count;
}

int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

/* 检查是否为 IPv4-mapped 或 IPv4-compatible 格式
 * 实际格式分析：
 * IPv4-mapped: 0000000000000000FFFF0000 + IPv4地址(8个十六进制字符)
 *              前16个字符全0，第17-20个字符为FFFF，第21-24个字符为0000，第25-32个字符为IPv4地址
 * IPv4-compatible: 000000000000000000000000 + IPv4地址(8个十六进制字符)
 *                  前24个字符全0，第25-32个字符为IPv4地址
 */
static int is_ipv4_mapped_format(const char *hex_addr) {
    if (!hex_addr || strlen(hex_addr) != 32) {
        return 0;
    }
    
    /* 检查前16个字符是否全为0 */
    int prefix_ok = 1;
    for (int i = 0; i < 16; i++) {
        if (hex_addr[i] != '0') {
            prefix_ok = 0;
            break;
        }
    }
    if (!prefix_ok) {
        return 0;
    }
    
    /* 检查是否为 IPv4-mapped 格式 (::ffff:xxxx) */
    /* 第17-20个字符（索引16-19）应该是 FFFF */
    int is_ffff = (hex_addr[16] == 'F' || hex_addr[16] == 'f') &&
                  (hex_addr[17] == 'F' || hex_addr[17] == 'f') &&
                  (hex_addr[18] == 'F' || hex_addr[18] == 'f') &&
                  (hex_addr[19] == 'F' || hex_addr[19] == 'f');
    
    if (is_ffff) {
        /* 第21-24个字符（索引20-23）应该是 0000 */
        int is_zero = (hex_addr[20] == '0') && (hex_addr[21] == '0') &&
                      (hex_addr[22] == '0') && (hex_addr[23] == '0');
        if (is_zero) {
            /* 第25-32个字符（索引24-31）是IPv4地址，不需要检查，直接返回1 */
            return 1;
        }
    }
    
    /* 检查是否为 IPv4-compatible 格式 (::xxxx) */
    /* 前24个字符全为0 */
    int all_zero = 1;
    for (int i = 0; i < 24; i++) {
        if (hex_addr[i] != '0') {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        /* 第25-32个字符（索引24-31）是IPv4地址 */
        return 1;
    }
    
    return 0;
}

/* 解析 /proc/net/tcp6 一行，提取 IPv4-mapped 或 IPv4-compatible 信息 */
int parse_tcp6_line(const char *line,
                   unsigned long *socket_inode,
                   char *local_ip, unsigned short *local_port,
                   char *remote_ip, unsigned short *remote_port) {
    if (!line || !socket_inode || !local_ip || !remote_ip ||
        !local_port || !remote_port) {
        return 0;
    }

    char local_hex[33], rem_hex[33];
    unsigned int local_port_hex = 0, remote_port_hex = 0;
    unsigned long inode = 0;

    int ret = sscanf(line,
                     "%*d: %32[0-9A-Fa-f]:%x %32[0-9A-Fa-f]:%x %*x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                     local_hex, &local_port_hex,
                     rem_hex, &remote_port_hex,
                     &inode);
    if (ret != 5) {
        return 0;
    }

    if (strlen(local_hex) != 32 || strlen(rem_hex) != 32) {
        return 0;
    }

    /* 检查本地和远程地址是否为 IPv4-mapped 或 IPv4-compatible 格式 */
    int local_is_v4 = is_ipv4_mapped_format(local_hex);
    int remote_is_v4 = is_ipv4_mapped_format(rem_hex);
    
    /* 如果都不符合，尝试更宽松的检查：前24个字符全为0或f/F */
    if (!local_is_v4) {
        int all_zero_or_f = 1;
        for (int i = 0; i < 24; i++) {
            char c = local_hex[i];
            if (!(c == '0' || c == 'f' || c == 'F')) {
                all_zero_or_f = 0;
                break;
            }
        }
        if (all_zero_or_f) {
            local_is_v4 = 1;
        }
    }
    
    if (!remote_is_v4) {
        int all_zero_or_f = 1;
        for (int i = 0; i < 24; i++) {
            char c = rem_hex[i];
            if (!(c == '0' || c == 'f' || c == 'F')) {
                all_zero_or_f = 0;
                break;
            }
        }
        if (all_zero_or_f) {
            remote_is_v4 = 1;
        }
    }

    /* 至少有一个地址是 IPv4 格式才处理 */
    if (!local_is_v4 && !remote_is_v4) {
        return 0;
    }

    /* 提取 IPv4 地址（后8个十六进制字符，索引24-31）
     * /proc/net/tcp6 中的 IPv4 地址格式：4877A8C0 表示 192.168.119.72
     * 这个十六进制字符串是网络字节序（大端）的字符串表示
     * 需要手动解析每个字节，然后组合成网络字节序的整数
     */
    unsigned char local_bytes[4] = {0}, remote_bytes[4] = {0};
    
    /* 如果本地地址是 IPv4 格式，解析它 */
    if (local_is_v4) {
        int ret = sscanf(local_hex + 24, "%2hhx%2hhx%2hhx%2hhx", 
                         &local_bytes[0], &local_bytes[1], &local_bytes[2], &local_bytes[3]);
        if (ret != 4) {
            return 0;
        }
    }
    
    /* 如果远程地址是 IPv4 格式，解析它 */
    if (remote_is_v4) {
        int ret = sscanf(rem_hex + 24, "%2hhx%2hhx%2hhx%2hhx", 
                         &remote_bytes[0], &remote_bytes[1], &remote_bytes[2], &remote_bytes[3]);
        if (ret != 4) {
            return 0;
        }
    }

    /* 组合成网络字节序的整数 */
    struct in_addr addr_local, addr_remote;
    if (local_is_v4) {
        addr_local.s_addr = (local_bytes[0] << 24) | (local_bytes[1] << 16) | 
                            (local_bytes[2] << 8) | local_bytes[3];
        strncpy(local_ip, inet_ntoa(addr_local), INET_ADDRSTRLEN - 1);
        local_ip[INET_ADDRSTRLEN - 1] = '\0';
    } else {
        /* 如果本地地址不是 IPv4，设置为 0.0.0.0 */
        strncpy(local_ip, "0.0.0.0", INET_ADDRSTRLEN - 1);
        local_ip[INET_ADDRSTRLEN - 1] = '\0';
    }
    
    if (remote_is_v4) {
        addr_remote.s_addr = (remote_bytes[0] << 24) | (remote_bytes[1] << 16) | 
                             (remote_bytes[2] << 8) | remote_bytes[3];
        strncpy(remote_ip, inet_ntoa(addr_remote), INET_ADDRSTRLEN - 1);
        remote_ip[INET_ADDRSTRLEN - 1] = '\0';
    } else {
        /* 如果远程地址不是 IPv4，设置为 0.0.0.0 */
        strncpy(remote_ip, "0.0.0.0", INET_ADDRSTRLEN - 1);
        remote_ip[INET_ADDRSTRLEN - 1] = '\0';
    }

    *local_port  = (unsigned short)local_port_hex;
    *remote_port = (unsigned short)remote_port_hex;
    *socket_inode = inode;
    return 1;
}

/* 通过 inode 从 /proc/net/tcp + /proc/net/tcp6 获取 IPv4 信息 */
int get_ipv4_from_inode(unsigned long inode,
                        char *local_ip, unsigned short *local_port,
                        char *remote_ip, unsigned short *remote_port) {
    // 1) /proc/net/tcp
    FILE *tcp = fopen("/proc/net/tcp", "r");
    if (tcp) {
        char line[1024];
        fgets(line, sizeof(line), tcp); // 跳标题
        while (fgets(line, sizeof(line), tcp)) {
            unsigned long socket_inode;
            unsigned int rem_addr, local_addr;
            unsigned int local_port_hex, remote_port_hex;
            int ret = sscanf(line,
                             "%*d: %x:%x %x:%x %*x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                             &local_addr, &local_port_hex,
                             &rem_addr, &remote_port_hex,
                             &socket_inode);
            if (ret == 5 && socket_inode == inode) {
                struct in_addr addr_local, addr_remote;
                addr_local.s_addr  = local_addr;
                addr_remote.s_addr = rem_addr;
                strncpy(local_ip, inet_ntoa(addr_local), INET_ADDRSTRLEN - 1);
                local_ip[INET_ADDRSTRLEN - 1] = '\0';
                strncpy(remote_ip, inet_ntoa(addr_remote), INET_ADDRSTRLEN - 1);
                remote_ip[INET_ADDRSTRLEN - 1] = '\0';
                *local_port  = (unsigned short)local_port_hex;
                *remote_port = (unsigned short)remote_port_hex;
                fclose(tcp);
                return 1;
            }
        }
        fclose(tcp);
    }

    // 2) /proc/net/tcp6 (IPv4-mapped)
    FILE *tcp6 = fopen("/proc/net/tcp6", "r");
    if (tcp6) {
        char line6[256];
        fgets(line6, sizeof(line6), tcp6); // 跳标题
        while (fgets(line6, sizeof(line6), tcp6)) {
            unsigned long socket_inode6 = 0;
            char lip[INET_ADDRSTRLEN], rip[INET_ADDRSTRLEN];
            unsigned short lp = 0, rp = 0;
            if (parse_tcp6_line(line6, &socket_inode6, lip, &lp, rip, &rp)) {
                if (socket_inode6 == inode) {
                    strncpy(local_ip, lip, INET_ADDRSTRLEN - 1);
                    local_ip[INET_ADDRSTRLEN - 1] = '\0';
                    strncpy(remote_ip, rip, INET_ADDRSTRLEN - 1);
                    remote_ip[INET_ADDRSTRLEN - 1] = '\0';
                    *local_port  = lp;
                    *remote_port = rp;
                    fclose(tcp6);
                    return 1;
                }
            }
        }
        fclose(tcp6);
    }

    return 0;
}

/* 记录首见远端IP的一条连接信息（全局模式）
 * 按远程IP+远程端口去重，而不是只按远程IP去重
 */
void add_seen_ip_info(const char *remote_ip,
                      const char *local_ip,
                      unsigned short local_port,
                      unsigned short remote_port,
                      pid_t pid,
                      const char *name,
                      const char *path) {
    if (!remote_ip || !local_ip || !name || !path) return;
    /* 过滤掉 LISTEN 状态和本地回环地址 */
    if (strcmp(remote_ip, "0.0.0.0") == 0 || strcmp(remote_ip, "127.0.0.1") == 0)
        return;

    /* 按远程IP+远程端口去重，而不是只按远程IP去重 */
    for (int i = 0; i < MAX_SEEN_IPS; i++) {
        if (seen_infos[i].used &&
            strcmp(seen_infos[i].remote_ip, remote_ip) == 0 &&
            seen_infos[i].remote_port == remote_port) {
            return;
        }
    }

    for (int i = 0; i < MAX_SEEN_IPS; i++) {
        if (!seen_infos[i].used) {
            SeenIpInfo *info = &seen_infos[i];
            info->used = 1;
            strncpy(info->remote_ip, remote_ip, sizeof(info->remote_ip) - 1);
            info->remote_ip[sizeof(info->remote_ip) - 1] = '\0';
            strncpy(info->local_ip, local_ip, sizeof(info->local_ip) - 1);
            info->local_ip[sizeof(info->local_ip) - 1] = '\0';
            info->local_port  = local_port;
            info->remote_port = remote_port;
            info->pid = pid;
            strncpy(info->name, name, sizeof(info->name) - 1);
            info->name[sizeof(info->name) - 1] = '\0';
            strncpy(info->path, path, sizeof(info->path) - 1);
            info->path[sizeof(info->path) - 1] = '\0';
            return;
        }
    }
}

void print_usage(const char *program_name) {
    printf("用法:\n");
    printf("监控 IP: %s -t <目标IP>\n", program_name);
    printf("监控域名: %s -d <域名>\n", program_name);
    printf("全局监控: %s -a <前台刷新间隔(秒)>\n", program_name);
    printf("\n可选参数:\n");
    printf("  -w <webhook_url>  设置飞书 webhook URL\n");
    printf("  -s <seconds>      设置通知间隔（秒），默认300秒\n");
    printf("  -q               静默模式，减少输出\n");
}

int main(int argc, char *argv[]) {
    setup_locale();

    if (!check_root()) return 1;

    int opt;
    char *target = NULL;
    int is_domain = 0;
    int monitor_all = 0;
    int print_interval = 5;
    char *ip_list[MAX_IPS] = {NULL};
    int ip_count = 0;

    while ((opt = getopt(argc, argv, "t:d:w:s:a:qh")) != -1) {
        switch (opt) {
            case 't':
                if (target) {
                    printf("错误: 不能同时使用 -t 和 -d 参数\n");
                    return 1;
                }
                target = optarg;
                is_domain = 0;
                break;
            case 'd':
                if (target) {
                    printf("错误: 不能同时使用 -t 和 -d 参数\n");
                    return 1;
                }
                if (is_valid_ip(optarg)) {
                    printf("错误: %s 是IP地址,请使用 -t 参数\n", optarg);
                    return 1;
                }
                target = optarg;
                is_domain = 1;
                break;
            case 'w':
                webhook_url = optarg;
                break;
            case 's':
                notify_interval = atoi(optarg);
                if (notify_interval <= 0) {
                    printf("错误: 通知间隔必须大于0\n");
                    return 1;
                }
                break;
            case 'a':
                if (target) {
                    printf("错误: -a 不能与 -t 或 -d 同时使用\n");
                    return 1;
                }
                monitor_all = 1;
                print_interval = atoi(optarg);
                if (print_interval <= 0) {
                    printf("错误: -a 后面的秒数必须大于0\n");
                    return 1;
                }
                break;
            case 'q':
                silent_mode = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!monitor_all) {
        if (!target) {
            printf("错误: 必须指定目标IP(-t)或域名(-d)，或使用 -a <秒> 进入全局模式\n");
            print_usage(argv[0]);
            return 1;
        }
    }

    // 目标模式：准备 IP 列表
    if (!monitor_all) {
        if (!is_domain) {
            if (!is_valid_ip(target)) {
                printf("错误: %s 不是有效的IP地址\n", target);
                return 1;
            }
            ip_list[0] = strdup(target);
            ip_count = 1;
        } else {
            ip_count = resolve_domain(target, ip_list, MAX_IPS);
            if (ip_count <= 0) {
                printf("错误: 无法解析域名 %s\n", target);
                return 1;
            }
            printf("域名 %s 解析结果:\n", target);
            for (int i = 0; i < ip_count; i++) {
                printf("- %s\n", ip_list[i]);
            }
        }
    }

    signal(SIGINT, handle_sigint);

    /* 全局模式：-a */
    if (monitor_all) {
        printf("\n实时统计本机所有 IPv4 连接状态（按远程IP去重，只打印首见连接信息）\n");
        time_t last_print = time(NULL);

        while (running) {
            DIR *proc_dir = opendir("/proc");
            if (!proc_dir) {
                usleep(100000);
                continue;
            }

            struct dirent *entry;
            while ((entry = readdir(proc_dir)) != NULL) {
                if (!isdigit(entry->d_name[0])) continue;

                pid_t pid = atoi(entry->d_name);
                char path[MAX_PATH];
                snprintf(path, sizeof(path), "/proc/%d/fd", pid);
                DIR *fd_dir = opendir(path);
                if (!fd_dir) continue;

                struct dirent *fd_entry;
                while ((fd_entry = readdir(fd_dir)) != NULL) {
                    if (!isdigit(fd_entry->d_name[0])) continue;

                    char fd_path[MAX_FD_PATH];
                    char sock_path[MAX_PATH];
                    snprintf(fd_path, sizeof(fd_path), "%s/%s", path, fd_entry->d_name);
                    ssize_t len = readlink(fd_path, sock_path, sizeof(sock_path) - 1);
                    if (len < 0) continue;
                    sock_path[len] = '\0';

                    if (strncmp(sock_path, "socket:", 7) == 0) {
                        unsigned long inode = 0;
                        sscanf(sock_path, "socket:[%lu]", &inode);

                        char local_ip[INET_ADDRSTRLEN];
                        char remote_ip[INET_ADDRSTRLEN];
                        unsigned short local_port = 0, remote_port = 0;

                        if (get_ipv4_from_inode(inode, local_ip, &local_port,
                                                remote_ip, &remote_port)) {
                            ProcessInfo info;
                            get_process_info(pid, &info);
                            add_seen_ip_info(remote_ip,
                                             local_ip,
                                             local_port,
                                             remote_port,
                                             pid,
                                             info.name,
                                             info.path);
                            if (info.cmdline) free(info.cmdline);
                        }
                    }
                }
                closedir(fd_dir);
            }
            closedir(proc_dir);

            time_t now = time(NULL);
            if (now - last_print >= print_interval) {
                printf("\r");
                printf("源地址           源端口 -> 目的地址         目的端口 PID    进程名称                    进程路径\n");
                printf("-----------------------------------------------------------------------------------------------------------\n");
                for (int i = 0; i < MAX_SEEN_IPS; i++) {
                    if (!seen_infos[i].used) continue;
                    printf("%-15s %-5u -> %-15s %-8u %-6d %-25s %-60s\n",
                           seen_infos[i].local_ip,
                           seen_infos[i].local_port,
                           seen_infos[i].remote_ip,
                           seen_infos[i].remote_port,
                           seen_infos[i].pid,
                           seen_infos[i].name,
                           seen_infos[i].path);
                }
                printf("\n按 Ctrl+C 停止监控...\n");
                last_print = now;
            }

            usleep(100000);
        }

        printf("\n停止监控\n");
        return 0;
    }

    /* 目标模式：按 IP/域名 */
    printf("\n开始监控以下IP地址:\n");
    for (int i = 0; i < ip_count; i++) {
        printf("- %s\n", ip_list[i]);
    }
    printf("\n使用Ctrl+C停止监控\n");
    printf("==========================================\n");

    time_t last_resolve = time(NULL);

    while (running) {
        if (is_domain) {
            time_t now = time(NULL);
            if (now - last_resolve >= DNS_RESOLVE_INTERVAL) {
                char *new_ip_list[MAX_IPS] = {NULL};
                int new_ip_count = resolve_domain(target, new_ip_list, MAX_IPS);
                if (new_ip_count > 0) {
                    for (int i = 0; i < ip_count; i++) {
                        free(ip_list[i]);
                        ip_list[i] = NULL;
                    }
                    ip_count = new_ip_count;
                    for (int i = 0; i < ip_count; i++) {
                        ip_list[i] = new_ip_list[i];
                    }
                    printf("\n域名 %s 解析结果已刷新:\n", target);
                    for (int i = 0; i < ip_count; i++) {
                        printf("- %s\n", ip_list[i]);
                    }
                    printf("==========================================\n");
                } else {
                    for (int i = 0; i < MAX_IPS; i++) free(new_ip_list[i]);
                }
                last_resolve = now;
            }
        }

        for (int i = 0; i < ip_count; i++) {
            DIR *proc_dir = opendir("/proc");
            if (!proc_dir) continue;

            struct dirent *entry;
            while ((entry = readdir(proc_dir)) != NULL) {
                if (!isdigit(entry->d_name[0])) continue;

                pid_t pid = atoi(entry->d_name);
                char path[MAX_PATH];
                snprintf(path, sizeof(path), "/proc/%d/fd", pid);
                DIR *fd_dir = opendir(path);
                if (!fd_dir) continue;

                struct dirent *fd_entry;
                while ((fd_entry = readdir(fd_dir)) != NULL) {
                    if (!isdigit(fd_entry->d_name[0])) continue;

                    char fd_path[MAX_FD_PATH];
                    char sock_path[MAX_PATH];
                    snprintf(fd_path, sizeof(fd_path), "%s/%s", path, fd_entry->d_name);
                    ssize_t len = readlink(fd_path, sock_path, sizeof(sock_path) - 1);
                    if (len < 0) continue;
                    sock_path[len] = '\0';

                    if (strncmp(sock_path, "socket:", 7) == 0) {
                        unsigned long inode = 0;
                        sscanf(sock_path, "socket:[%lu]", &inode);

                        char local_ip[INET_ADDRSTRLEN];
                        char remote_ip[INET_ADDRSTRLEN];
                        unsigned short local_port = 0, remote_port = 0;

                        if (get_ipv4_from_inode(inode, local_ip, &local_port,
                                                remote_ip, &remote_port)) {
                            if (strcmp(remote_ip, ip_list[i]) == 0) {
                                ProcessInfo info;
                                get_process_info(pid, &info);

                                time_t now = time(NULL);
                                char message[MAX_MESSAGE_SIZE];
                                snprintf(message, sizeof(message),
                                         "检测到与 %s 的连接\n进程信息:\nPID: %d\n进程名称: %s\n可执行文件: %s\n用户: %s",
                                         ip_list[i], info.pid, info.name, info.path, info.username);

                                if (!silent_mode) {
                                    printf("\n%s\n", message);
                                    printf("------------------------------------------\n");
                                }

                                if (webhook_url && (now - last_notification >= notify_interval)) {
                                    send_feishu_notification(message);
                                    last_notification = now;
                                }
                                if (info.cmdline) free(info.cmdline);
                            }
                        }
                    }
                }
                closedir(fd_dir);
            }
            closedir(proc_dir);
        }

        usleep(100000);
    }

    for (int i = 0; i < ip_count; i++) {
        free(ip_list[i]);
    }

    printf("\n停止监控\n");
    return 0;
}