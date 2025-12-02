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
#include <langinfo.h>
#include <time.h>
#include <curl/curl.h>

#define MAX_PATH 4096
#define MAX_CMDLINE 4096
#define MAX_PROC_NAME 256
#define MAX_IPS 10
#define DEFAULT_NOTIFY_INTERVAL 300  // 默认通知间隔（秒）
#define MAX_MESSAGE_SIZE 8192        // 最大消息大小
#define MAX_FD_PATH 4096            // 最大文件描述符路径长度
#define MAX_DIRENT_NAME 256         // 目录项名称最大长度

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

volatile sig_atomic_t running = 1;
time_t last_notification = 0;
int notify_interval = DEFAULT_NOTIFY_INTERVAL;
char *webhook_url = NULL;
int silent_mode = 0;
time_t last_output = 0;
#define OUTPUT_INTERVAL 60  // 输出间隔（秒）

// 设置终端编码为UTF-8
void setup_locale() {
    setlocale(LC_ALL, "zh_CN.UTF-8");
    printf("\033[0m"); // 重置终端颜色
}

// 检查是否具有root权限
int check_root() {
    if (geteuid() != 0) {
        printf("需要root权限运行此程序\n");
        printf("请使用 sudo 运行\n");
        return 0;
    }
    return 1;
}

// 读取进程命令行
char* read_cmdline(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

    char *cmdline = malloc(4096);
    if (!cmdline) {
        fclose(fp);
        return NULL;
    }

    size_t len = fread(cmdline, 1, 4095, fp);
    fclose(fp);

    if (len <= 0) {
        free(cmdline);
        return NULL;
    }

    cmdline[len] = '\0';
    return cmdline;
}

// 读取进程可执行文件路径
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

// 获取进程状态信息
void get_process_status(pid_t pid, ProcessInfo *info) {
    char path[MAX_PATH];
    char line[256];
    info->ppid = 0;
    
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Name:", 5) == 0) {
                sscanf(line, "Name: %s", info->name);
            } else if (strncmp(line, "PPid:", 5) == 0) {
                sscanf(line, "PPid: %d", &info->ppid);
            } else if (strncmp(line, "Uid:", 4) == 0) {
                sscanf(line, "Uid: %d", &info->uid);
            }
        }
        fclose(f);
        
        // 获取用户名
        struct passwd *pw = getpwuid(info->uid);
        if (pw) {
            strncpy(info->username, pw->pw_name, sizeof(info->username) - 1);
        } else {
            snprintf(info->username, sizeof(info->username), "%d", info->uid);
        }
    }
}

// 获取完整的进程信息
void get_process_info(pid_t pid, ProcessInfo *info) {
    info->pid = pid;
    
    // 获取进程状态信息（包括ppid和name）
    get_process_status(pid, info);
    
    // 获取可执行文件路径
    read_exe_path(pid, info->path, sizeof(info->path));
    
    // 获取完整命令行
    info->cmdline = read_cmdline(pid);
}

// 打印进程树信息
void print_process_tree(ProcessInfo *info) {
    printf("\n进程信息:\n");
    printf("PID: %d\n", info->pid);
    printf("进程名称: %s\n", info->name);
    printf("可执行文件: %s\n", info->path);
    if (info->cmdline) {
        printf("命令行: %s\n", info->cmdline);
        free(info->cmdline);
    } else {
        printf("命令行: 无法获取\n");
    }
    printf("用户: %s\n", info->username);
    
    if (info->ppid > 0) {
        ProcessInfo parent_info = {0};
        get_process_info(info->ppid, &parent_info);
        printf("\n父进程信息:\n");
        printf("父进程 PID: %d\n", parent_info.pid);
        printf("父进程名称: %s\n", parent_info.name);
        printf("父进程路径: %s\n", parent_info.path);
        if (parent_info.cmdline) {
            printf("父进程命令行: %s\n", parent_info.cmdline);
            free(parent_info.cmdline);
        } else {
            printf("父进程命令行: 无法获取\n");
        }
        printf("父进程用户: %s\n", parent_info.username);
    }
}

// 处理 Ctrl+C
void handle_sigint(int sig) {
    running = 0;
}

// 初始化CURL缓冲区
void init_curl_buffer(CurlBuffer *buf) {
    buf->data = malloc(1);
    buf->size = 0;
    if (buf->data) {
        buf->data[0] = '\0';
    }
}

// CURL写回调函数
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

// 发送飞书通知
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

// 解析域名
int resolve_domain(const char *domain, char *ip_list[], int max_ips) {
    struct addrinfo hints, *result, *rp;
    int ip_count = 0;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;    // 只获取IPv4地址
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

// 检查IP地址格式是否有效
int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

// 检查是否为公网IP
int is_public_ip(const char *ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }
    
    uint32_t ip_long = ntohl(addr.s_addr);
    
    // 检查私有IP范围
    if ((ip_long >= 0x0A000000 && ip_long <= 0x0AFFFFFF) ||  // 10.0.0.0/8
        (ip_long >= 0xAC100000 && ip_long <= 0xAC1FFFFF) ||  // 172.16.0.0/12
        (ip_long >= 0xC0A80000 && ip_long <= 0xC0A8FFFF) ||  // 192.168.0.0/16
        (ip_long >= 0x7F000000 && ip_long <= 0x7FFFFFFF)) {  // 127.0.0.0/8
        return 0;
    }
    
    return 1;
}

void print_usage(const char *program_name) {
    printf("用法:\n");
    printf("监控 IP: %s -t <目标IP>\n", program_name);
    printf("监控域名: %s -d <域名>\n", program_name);
    printf("\n可选参数:\n");
    printf("  -w <webhook_url>  设置飞书 webhook URL\n");
    printf("  -s <seconds>      设置通知间隔（秒），默认300秒\n");
    printf("  -q               静默模式，减少输出\n");
}

int main(int argc, char *argv[]) {
    // 设置UTF-8编码
    setup_locale();
    
    // 检查root权限
    if (!check_root()) {
        return 1;
    }
    
    // 解析命令行参数
    int opt;
    char *target = NULL;
    int is_domain = 0;
    char *ip_list[MAX_IPS] = {NULL};
    int ip_count = 0;
    
    while ((opt = getopt(argc, argv, "t:d:w:s:qh")) != -1) {
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
            case 'q':
                silent_mode = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (!target) {
        printf("错误: 必须指定目标IP(-t)或域名(-d)\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // 处理目标
    if (!is_domain) {
        // 检查IP地址格式
        if (!is_valid_ip(target)) {
            printf("错误: %s 不是有效的IP地址\n", target);
            return 1;
        }
        if (!is_public_ip(target)) {
            printf("错误: %s 不是有效的公网IP地址\n", target);
            return 1;
        }
        ip_list[0] = strdup(target);
        ip_count = 1;
    } else {
        // 解析域名
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
    
    // 设置信号处理
    signal(SIGINT, handle_sigint);
    
    // 开始监控
    printf("\n开始监控以下IP地址:\n");
    for (int i = 0; i < ip_count; i++) {
        printf("- %s\n", ip_list[i]);
    }
    printf("\n使用Ctrl+C停止监控\n");
    printf("==========================================\n");
    
    // 主循环
    while (running) {
        for (int i = 0; i < ip_count; i++) {
            DIR *proc_dir = opendir("/proc");
            if (!proc_dir) {
                continue;
            }
            
            struct dirent *entry;
            while ((entry = readdir(proc_dir)) != NULL) {
                // 只处理数字目录（进程ID）
                if (!isdigit(entry->d_name[0])) {
                    continue;
                }
                
                pid_t pid = atoi(entry->d_name);
                char path[MAX_PATH];
                int path_len = snprintf(path, sizeof(path), "/proc/%d/fd", pid);
                if (path_len < 0 || path_len >= sizeof(path)) {
                    continue;  // 路径太长，跳过此进程
                }
                
                DIR *fd_dir = opendir(path);
                if (!fd_dir) {
                    continue;
                }
                
                struct dirent *fd_entry;
                while ((fd_entry = readdir(fd_dir)) != NULL) {
                    if (!isdigit(fd_entry->d_name[0])) {
                        continue;
                    }
                    
                    // 检查目录项名称长度
                    size_t name_len = strlen(fd_entry->d_name);
                    if (name_len >= MAX_DIRENT_NAME) {
                        continue;  // 名称太长，跳过此文件描述符
                    }
                    
                    char fd_path[MAX_FD_PATH];
                    char sock_path[MAX_PATH];
                    
                    // 安全地构建文件描述符路径
                    int fd_path_len = snprintf(fd_path, sizeof(fd_path), "%s/%s", path, fd_entry->d_name);
                    if (fd_path_len < 0 || fd_path_len >= sizeof(fd_path)) {
                        continue;  // 路径太长，跳过此文件描述符
                    }
                    
                    ssize_t len = readlink(fd_path, sock_path, sizeof(sock_path) - 1);
                    if (len < 0) {
                        continue;
                    }
                    sock_path[len] = '\0';
                    
                    if (strncmp(sock_path, "socket:", 7) == 0) {
                        // 获取socket的inode
                        unsigned long inode;
                        sscanf(sock_path, "socket:[%lu]", &inode);
                        
                        // 检查TCP连接
                        FILE *tcp = fopen("/proc/net/tcp", "r");
                        if (!tcp) {
                            continue;
                        }
                        
                        char line[1024];
                        fgets(line, sizeof(line), tcp); // 跳过标题行
                        
                        while (fgets(line, sizeof(line), tcp)) {
                            unsigned long socket_inode;
                            unsigned int rem_addr;
                            int ret = sscanf(line, "%*d: %*x:%*x %x:%*x %*x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                                           &rem_addr, &socket_inode);
                            
                            if (ret == 2 && socket_inode == inode) {
                                struct in_addr addr = {.s_addr = rem_addr};
                                char *remote_ip = inet_ntoa(addr);
                                
                                if (strcmp(remote_ip, ip_list[i]) == 0) {
                                    ProcessInfo info = {0};
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
                                }
                            }
                        }
                        fclose(tcp);
                    }
                }
                closedir(fd_dir);
            }
            closedir(proc_dir);
        }
        
        usleep(100000); // 休眠0.1秒
    }
    
    // 清理
    for (int i = 0; i < ip_count; i++) {
        free(ip_list[i]);
    }
    
    printf("\n停止监控\n");
    return 0;
}