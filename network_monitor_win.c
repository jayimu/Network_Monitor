#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winhttp.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "winhttp.lib")

#define MAX_PROCESS_NAME 260
#define MAX_PROCESS_PATH 260
#define MAX_IPS 10
#define MAX_WEBHOOK_URL 1024
#define POLL_INTERVAL_MS 200   // 轮询 TCP 连接表的时间间隔（毫秒）
#define SUMMARY_INTERVAL_MS 30000 // 目标IP模式控制台统计输出时间间隔（毫秒）
#define PRINT_INTERVAL_MS 5000    // 全局模式界面刷新时间间隔（毫秒）
#define MAX_SEEN_IPS 1024      // 记录历史出现过的远程IP数量上限

typedef struct {
    DWORD parentPID;
    char name[MAX_PROCESS_NAME];
    char path[MAX_PROCESS_PATH];
} ProcessInfo;

typedef struct {
    BOOL valid;
    DWORD pid;
    char name[MAX_PROCESS_NAME];
    char path[MAX_PROCESS_PATH];
    char local_ip[16];
    unsigned short local_port;
    char remote_ip[16];
    unsigned short remote_port;
    SYSTEMTIME time;
} LastConnectionInfo;

// 全局模式下记录首个连接详情（按远程IP去重）
typedef struct {
    BOOL used;
    char remote_ip[INET_ADDRSTRLEN];
    char local_ip[INET_ADDRSTRLEN];
    unsigned short local_port;
    unsigned short remote_port;
    DWORD pid;
    char name[MAX_PROCESS_NAME];
    char path[MAX_PROCESS_PATH];
} SeenIpInfo;

// 规范化进程名称（例如只保留 "Cursor Helper (Plugin)"）
void NormalizeProcessName(char* name) {
    const char* key = "Cursor Helper (Plugin)";
    if (!name) return;
    char* pos = strstr(name, key);
    if (pos) {
        // 将名称截断为固定字符串
        strncpy(name, key, MAX_PROCESS_NAME - 1);
        name[MAX_PROCESS_NAME - 1] = '\0';
    }
}

// 全局变量
char g_webhook_url[MAX_WEBHOOK_URL] = {0};
BOOL g_first_no_connection = TRUE;
LastConnectionInfo g_last_connection = {0};
DWORD g_last_summary_tick = 0;
DWORD g_match_count_30s = 0;
char g_seen_ips[MAX_SEEN_IPS][INET_ADDRSTRLEN] = {0};
int g_seen_ip_count = 0;
SeenIpInfo g_seen_infos[MAX_SEEN_IPS] = {0};

// 设置控制台编码为 UTF-8
void SetupConsole() {
    // 设置控制台代码页为 UTF-8
    SetConsoleOutputCP(65001);
    
    // 获取标准输出句柄
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        return;
    }

    // 设置控制台字体
    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof(cfi);
    cfi.nFont = 0;
    cfi.dwFontSize.X = 0;
    cfi.dwFontSize.Y = 16;
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy(cfi.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(hOut, FALSE, &cfi);

    // 设置控制台模式
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

// 获取父进程ID
DWORD GetParentProcessId(DWORD pid) {
    DWORD parentPID = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == pid) {
                    parentPID = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    return parentPID;
}

// 获取进程信息（包括父进程）
void GetProcessInfo(DWORD pid, ProcessInfo* info) {
    // 初始化结构体
    info->parentPID = GetParentProcessId(pid);
    strncpy(info->name, "未知进程", MAX_PROCESS_NAME);
    strncpy(info->path, "无法获取路径", MAX_PROCESS_PATH);

    // 获取进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return;
    }

    // 获取进程名称
    WCHAR wname[MAX_PROCESS_NAME];
    if (GetProcessImageFileNameW(hProcess, wname, MAX_PROCESS_NAME) > 0) {
        // 提取文件名
        WCHAR* lastBackslash = wcsrchr(wname, L'\\');
        if (lastBackslash != NULL) {
            WideCharToMultiByte(CP_UTF8, 0, lastBackslash + 1, -1, info->name, MAX_PROCESS_NAME, NULL, NULL);
        }
    }

    // 获取进程完整路径
    WCHAR wpath[MAX_PROCESS_PATH];
    DWORD size = MAX_PROCESS_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, wpath, &size)) {
        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, info->path, MAX_PROCESS_PATH, NULL, NULL);
    }

    CloseHandle(hProcess);
}

// 打印进程树信息
void PrintProcessTreeInfo(ProcessInfo* info, DWORD pid) {
    printf("进程ID: %lu\n", pid);
    printf("进程名称: %s\n", info->name);
    printf("进程路径: %s\n", info->path);
    
    if (info->parentPID != 0) {
        ProcessInfo parentInfo;
        GetProcessInfo(info->parentPID, &parentInfo);
        printf("父进程ID: %lu\n", info->parentPID);
        printf("父进程名称: %s\n", parentInfo.name);
        printf("父进程路径: %s\n", parentInfo.path);
    }
}

// 检查管理员权限
BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            fRet = elevation.TokenIsElevated;
        }
    }

    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

// 发送飞书通知
void SendFeishuNotification(const char* message) {
    if (strlen(g_webhook_url) == 0) {
        return;
    }

    // 解析 URL
    URL_COMPONENTS urlComp = {0};
    WCHAR host[256] = {0};
    WCHAR path[1024] = {0};
    
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = sizeof(host) / sizeof(WCHAR);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = sizeof(path) / sizeof(WCHAR);

    // 转换 URL 到宽字符
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, g_webhook_url, -1, NULL, 0);
    WCHAR* wurl = (WCHAR*)malloc(size_needed * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, g_webhook_url, -1, wurl, size_needed);

    if (!WinHttpCrackUrl(wurl, 0, 0, &urlComp)) {
        free(wurl);
        return;
    }
    free(wurl);

    // 创建会话
    HINTERNET hSession = WinHttpOpen(L"Network Monitor",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS,
                                   0);
    if (!hSession) return;

    // 连接到服务器
    HINTERNET hConnect = WinHttpConnect(hSession,
                                      host,
                                      urlComp.nPort,
                                      0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return;
    }

    // 创建请求
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
                                          L"POST",
                                          path,
                                          NULL,
                                          WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    // 构建 JSON 数据
    char json[2048];
    snprintf(json, sizeof(json),
             "{\"msg_type\":\"text\",\"content\":{\"text\":\"%s\"}}",
             message);

    // 发送请求
    BOOL result = WinHttpSendRequest(hRequest,
                                   L"Content-Type: application/json\r\n",
                                   -1,
                                   json,
                                   strlen(json),
                                   strlen(json),
                                   0);
    if (result) {
        WinHttpReceiveResponse(hRequest, NULL);
    }

    // 清理
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

// 解析域名获取多个 IPv4 地址（最多 MAX_IPS 个）
BOOL ResolveDomainMulti(const char* domain, char ips[][INET_ADDRSTRLEN], int* ip_count) {
    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET; // 只获取 IPv4 地址
    hints.ai_socktype = SOCK_STREAM;

    *ip_count = 0;

    int ret = getaddrinfo(domain, NULL, &hints, &result);
    if (ret != 0) {
        return FALSE;
    }

    // 获取所有 IPv4 地址，去重后写入数组
    for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        if (ptr->ai_family == AF_INET) {
            struct sockaddr_in* addr = (struct sockaddr_in*)ptr->ai_addr;
            char ip_buf[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &(addr->sin_addr), ip_buf, INET_ADDRSTRLEN);

            // 去重检查
            BOOL exists = FALSE;
            for (int i = 0; i < *ip_count; i++) {
                if (strcmp(ips[i], ip_buf) == 0) {
                    exists = TRUE;
                    break;
                }
            }
            if (!exists && *ip_count < MAX_IPS) {
                strncpy(ips[*ip_count], ip_buf, INET_ADDRSTRLEN - 1);
                ips[*ip_count][INET_ADDRSTRLEN - 1] = '\0';
                (*ip_count)++;
            }
        }
    }

    freeaddrinfo(result);
    return *ip_count > 0;
}

// 原先的单 IP 解析函数，保留作为回退手段
BOOL ResolveDomain(const char* domain, char* ip_out) {
    char tmp_ips[MAX_IPS][INET_ADDRSTRLEN] = {0};
    int count = 0;
    if (!ResolveDomainMulti(domain, tmp_ips, &count)) {
        return FALSE;
    }
    // 兼容老逻辑：只取第一个 IP
    strncpy(ip_out, tmp_ips[0], INET_ADDRSTRLEN - 1);
    ip_out[INET_ADDRSTRLEN - 1] = '\0';
    return TRUE;
}

// 检查IP地址格式是否有效
BOOL is_valid_ip(const char* ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

// 检查是否为公网IP
BOOL is_public_ip(const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return FALSE;
    }
    
    unsigned long ip_long = ntohl(addr.s_addr);
    
    // 检查私有IP范围
    if ((ip_long >= 0x0A000000 && ip_long <= 0x0AFFFFFF) ||  // 10.0.0.0/8
        (ip_long >= 0xAC100000 && ip_long <= 0xAC1FFFFF) ||  // 172.16.0.0/12
        (ip_long >= 0xC0A80000 && ip_long <= 0xC0A8FFFF) ||  // 192.168.0.0/16
        (ip_long >= 0x7F000000 && ip_long <= 0x7FFFFFFF)) {  // 127.0.0.0/8
        return FALSE;
    }
    
    return TRUE;
}

// 在全局模式中为新出现的远程IP记录一条详情（只记录首个连接）
BOOL AddSeenIpInfo(const char* remote_ip,
                   const char* local_ip,
                   unsigned short local_port,
                   unsigned short remote_port,
                   DWORD pid,
                   const char* name,
                   const char* path) {
    if (!remote_ip || !local_ip || !name || !path) return FALSE;
    if (strcmp(remote_ip, "0.0.0.0") == 0 || strcmp(remote_ip, "127.0.0.1") == 0) {
        return FALSE;
    }

    // 查找是否已存在
    for (int i = 0; i < MAX_SEEN_IPS; i++) {
        if (g_seen_infos[i].used &&
            strcmp(g_seen_infos[i].remote_ip, remote_ip) == 0) {
            return FALSE; // 已记录
        }
    }

    // 找一个空位
    for (int i = 0; i < MAX_SEEN_IPS; i++) {
        if (!g_seen_infos[i].used) {
            SeenIpInfo* info = &g_seen_infos[i];
            info->used = TRUE;
            strncpy(info->remote_ip, remote_ip, INET_ADDRSTRLEN - 1);
            info->remote_ip[INET_ADDRSTRLEN - 1] = '\0';
            strncpy(info->local_ip, local_ip, INET_ADDRSTRLEN - 1);
            info->local_ip[INET_ADDRSTRLEN - 1] = '\0';
            info->local_port = local_port;
            info->remote_port = remote_port;
            info->pid = pid;
            strncpy(info->name, name, MAX_PROCESS_NAME - 1);
            info->name[MAX_PROCESS_NAME - 1] = '\0';
            strncpy(info->path, path, MAX_PROCESS_PATH - 1);
            info->path[MAX_PROCESS_PATH - 1] = '\0';

            return TRUE;
        }
    }
    return FALSE;
}

// 将TCP状态码转换为字符串
const char* TcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:      return "CLOSED";
        case MIB_TCP_STATE_LISTEN:      return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:     return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
        default:                        return "UNKNOWN";
    }
}

// 实时统计本机所有IPv4连接状态（全局模式，无 -t/-d）
void PrintAllIPv4Connections() {
    PMIB_TCPTABLE2 pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    // 获取TCP连接表所需大小
    dwRetVal = GetTcpTable2(NULL, &dwSize, TRUE);
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE2)malloc(dwSize);
        if (pTcpTable == NULL) {
            return;
        }
    } else {
        return;
    }

    // 获取TCP连接表
    dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE);
    if (dwRetVal != NO_ERROR) {
        free(pTcpTable);
        return;
    }

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        struct in_addr IpAddr;
        char local_ip[16];
        char remote_ip[16];

        // 本地地址
        IpAddr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
        strcpy(local_ip, inet_ntoa(IpAddr));

        // 远程地址
        IpAddr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
        strcpy(remote_ip, inet_ntoa(IpAddr));

        // 过滤无效/本地环回地址
        if (strcmp(remote_ip, "0.0.0.0") == 0 || strcmp(remote_ip, "127.0.0.1") == 0) {
            continue;
        }

        DWORD pid = pTcpTable->table[i].dwOwningPid;
        ProcessInfo procInfo = {0};
        GetProcessInfo(pid, &procInfo);

        // 仅在首见该远程IP时记录一条完整信息
        AddSeenIpInfo(remote_ip,
                      local_ip,
                      ntohs((u_short)pTcpTable->table[i].dwLocalPort),
                      ntohs((u_short)pTcpTable->table[i].dwRemotePort),
                      pid,
                      procInfo.name,
                      procInfo.path);
    }

    free(pTcpTable);
}

int main(int argc, char* argv[]) {
    // 设置控制台编码
    SetupConsole();

    // 命令行用法说明（当既没有目标IP/域名且不希望进入全局模式时可参考）
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("用法:\n");
        printf("监控 IP: %s -t <目标IP>\n", argv[0]);
        printf("监控域名: %s -d <域名>\n", argv[0]);
        printf("直接执行(无参数): 实时统计本机所有IPv4连接\n");
        printf("可选参数:\n");
        printf("  -w <webhook_url>  设置飞书 webhook URL\n");
        return 0;
    }

    // 检查管理员权限
    if (!IsElevated()) {
        printf("需要管理员权限运行此程序\n");
        printf("请右键点击命令提示符，选择'以管理员身份运行'\n");
        return 1;
    }

    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup失败\n");
        return 1;
    }
    
    // 解析命令行参数
    char target_ip[INET_ADDRSTRLEN] = {0};
    BOOL is_domain = FALSE;
    char target_domain[256] = {0};
    char target_ips[MAX_IPS][INET_ADDRSTRLEN] = {0};
    int target_ip_count = 0;
    BOOL all_mode = FALSE; // 无 -t/-d 参数时统计所有IPv4连接

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            if (!is_valid_ip(argv[i + 1])) {
                printf("错误: %s 不是有效的IP地址\n", argv[i + 1]);
                WSACleanup();
                return 1;
            }
            strncpy(target_ip, argv[i + 1], INET_ADDRSTRLEN - 1);
            // 目标为单个 IP
            memset(target_ips, 0, sizeof(target_ips));
            strncpy(target_ips[0], target_ip, INET_ADDRSTRLEN - 1);
            target_ip_count = 1;
            i++;
        }
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            if (is_valid_ip(argv[i + 1])) {
                printf("错误: %s 是IP地址,请使用 -t 参数\n", argv[i + 1]);
                WSACleanup();
                return 1;
            }
            is_domain = TRUE;
            strncpy(target_domain, argv[i + 1], sizeof(target_domain) - 1);
            // 启动时先尝试多 IP 解析
            if (!ResolveDomainMulti(target_domain, target_ips, &target_ip_count)) {
                // 多 IP 解析失败则回退到旧逻辑（单 IP）
                if (!ResolveDomain(target_domain, target_ip)) {
                    printf("错误: 无法解析域名 %s\n", argv[i + 1]);
                    WSACleanup();
                    return 1;
                }
                memset(target_ips, 0, sizeof(target_ips));
                strncpy(target_ips[0], target_ip, INET_ADDRSTRLEN - 1);
                target_ip_count = 1;
                printf("域名 %s 解析到 IP: %s\n", argv[i + 1], target_ip);
            } else {
                // 兼容原有打印，选第一个 IP 作为展示
                strncpy(target_ip, target_ips[0], INET_ADDRSTRLEN - 1);
                printf("域名 %s 解析到以下 IPv4 地址:\n", target_domain);
                for (int j = 0; j < target_ip_count; j++) {
                    printf("  - %s\n", target_ips[j]);
                }
            }
            i++;
        }
        else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            strncpy(g_webhook_url, argv[i + 1], MAX_WEBHOOK_URL - 1);
            i++;
        }
    }

    // 如果既没有 -t 也没有 -d，则进入全局IPv4统计模式
    if (target_ip_count == 0 && !is_domain) {
        all_mode = TRUE;
    }

    if (all_mode) {
        DWORD lastPrintTick = GetTickCount();
        while (1) {
            PrintAllIPv4Connections();

            // 打印已记录的首见连接信息（按远程IP去重）
            DWORD now = GetTickCount();
            if (now - lastPrintTick >= PRINT_INTERVAL_MS) {
                printf("\r"); // 简单回车，方便在控制台反复刷新表格
                printf("源地址           源端口 -> 目的地址         目的端口 PID    进程名称                    进程路径\n");
                printf("-----------------------------------------------------------------------------------------------------------\n");
                for (int i = 0; i < MAX_SEEN_IPS; i++) {
                    if (!g_seen_infos[i].used) continue;
                    printf("%-15s %-5u -> %-15s %-8u %-6lu %-25s %-60s\n",
                           g_seen_infos[i].local_ip,
                           g_seen_infos[i].local_port,
                           g_seen_infos[i].remote_ip,
                           g_seen_infos[i].remote_port,
                           g_seen_infos[i].pid,
                           g_seen_infos[i].name,
                           g_seen_infos[i].path);
                }
                printf("\n按 Ctrl+C 停止监控...\n");
                lastPrintTick = now;
            }

            Sleep(POLL_INTERVAL_MS); // 200ms 刷新一次快照
        }
    }

    printf("开始监控以下 IPv4 地址的网络连接...\n");
    for (int i = 0; i < target_ip_count; i++) {
        printf("  - %s\n", target_ips[i]);
    }
    printf("使用Ctrl+C停止监控\n");
    printf("==========================================\n");

    // 发送开始监控通知
    char start_msg[512];
    snprintf(start_msg, sizeof(start_msg), "开始监控以下 IPv4 地址:\n");
    for (int i = 0; i < target_ip_count; i++) {
        char line[64];
        snprintf(line, sizeof(line), "- %s\n", target_ips[i]);
        strncat(start_msg, line, sizeof(start_msg) - strlen(start_msg) - 1);
    }
    SendFeishuNotification(start_msg);

    // 初始化统计时间
    g_last_summary_tick = GetTickCount();

    // 域名监控时定期重新解析 DNS，跟踪 IP 变化
    DWORD lastResolveTick = GetTickCount();
    const DWORD RESOLVE_INTERVAL_MS = 5000; // 每 5 秒刷新一次域名解析结果

    while (1) {
        // 如果是域名模式，周期性刷新 IP 列表
        if (is_domain) {
            DWORD now = GetTickCount();
            if (now - lastResolveTick >= RESOLVE_INTERVAL_MS) {
                char new_ips[MAX_IPS][INET_ADDRSTRLEN] = {0};
                int new_count = 0;
                if (ResolveDomainMulti(target_domain, new_ips, &new_count) && new_count > 0) {
                    // 更新目标 IP 列表
                    memset(target_ips, 0, sizeof(target_ips));
                    for (int i = 0; i < new_count && i < MAX_IPS; i++) {
                        strncpy(target_ips[i], new_ips[i], INET_ADDRSTRLEN - 1);
                    }
                    target_ip_count = new_count;
                }
                lastResolveTick = now;
            }
        }

        PMIB_TCPTABLE2 pTcpTable = NULL;
        DWORD dwSize = 0;
        DWORD dwRetVal = 0;

        // 获取TCP连接表所需大小
        dwRetVal = GetTcpTable2(NULL, &dwSize, TRUE);
        if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
            pTcpTable = (PMIB_TCPTABLE2)malloc(dwSize);
            if (pTcpTable == NULL) {
                Sleep(1000);
                continue;
            }
        }

        // 获取TCP连接表
        dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE);
        if (dwRetVal == NO_ERROR) {
            BOOL found = FALSE;
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                struct in_addr IpAddr;
                IpAddr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
                char remote_ip[16];
                strcpy(remote_ip, inet_ntoa(IpAddr));
                
                // 检查远程 IP 是否在目标 IP 列表中
                BOOL match = FALSE;
                for (int j = 0; j < target_ip_count; j++) {
                    if (strcmp(remote_ip, target_ips[j]) == 0) {
                        match = TRUE;
                        break;
                    }
                }

                if (match) {
                    found = TRUE;
                    g_first_no_connection = TRUE;
                    DWORD pid = pTcpTable->table[i].dwOwningPid;
                    ProcessInfo procInfo;
                    GetProcessInfo(pid, &procInfo);

                    // 获取本地地址
                    IpAddr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
                    char local_ip[16];
                    strcpy(local_ip, inet_ntoa(IpAddr));

                    // 获取当前时间
                    SYSTEMTIME st;
                    GetLocalTime(&st);

                    // 更新统计信息，仅记录，在30秒聚合时统一输出和告警
                    g_match_count_30s++;
                    g_last_connection.valid = TRUE;
                    g_last_connection.pid = pid;
                    strncpy(g_last_connection.name, procInfo.name, MAX_PROCESS_NAME - 1);
                    g_last_connection.name[MAX_PROCESS_NAME - 1] = '\0';
                    strncpy(g_last_connection.path, procInfo.path, MAX_PROCESS_PATH - 1);
                    g_last_connection.path[MAX_PROCESS_PATH - 1] = '\0';
                    strncpy(g_last_connection.local_ip, local_ip, sizeof(g_last_connection.local_ip) - 1);
                    g_last_connection.local_ip[sizeof(g_last_connection.local_ip) - 1] = '\0';
                    strncpy(g_last_connection.remote_ip, remote_ip, sizeof(g_last_connection.remote_ip) - 1);
                    g_last_connection.remote_ip[sizeof(g_last_connection.remote_ip) - 1] = '\0';
                    g_last_connection.local_port = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
                    g_last_connection.remote_port = ntohs((u_short)pTcpTable->table[i].dwRemotePort);
                    g_last_connection.time = st;
                }
            }
            if (!found && g_first_no_connection) {
                printf("等待检测到与 %s 的连接...\n", target_ip);
                g_first_no_connection = FALSE;
            }
        }

        if (pTcpTable) {
            free(pTcpTable);
        }

        // 每 SUMMARY_INTERVAL_MS 输出一次统计信息，并进行飞书聚合告警，避免刷屏
        DWORD now_tick = GetTickCount();
        if (now_tick - g_last_summary_tick >= SUMMARY_INTERVAL_MS) {
            if (g_match_count_30s > 0 && g_last_connection.valid) {
                printf("\n最近 30 秒内共检测到 %lu 次与目标地址的连接\n", g_match_count_30s);
                printf("最近一次连接信息:\n");
                printf("时间: %04d-%02d-%02d %02d:%02d:%02d\n",
                       g_last_connection.time.wYear, g_last_connection.time.wMonth, g_last_connection.time.wDay,
                       g_last_connection.time.wHour, g_last_connection.time.wMinute, g_last_connection.time.wSecond);
                printf("进程ID: %lu\n", g_last_connection.pid);
                printf("进程名称: %s\n", g_last_connection.name);
                printf("进程路径: %s\n", g_last_connection.path);
                printf("本地地址: %s:%u\n", g_last_connection.local_ip, g_last_connection.local_port);
                printf("远程地址: %s:%u\n", g_last_connection.remote_ip, g_last_connection.remote_port);

                // 构造飞书聚合消息：30秒内总次数 + 最近一次详细信息
                char summary_msg[2048];
                snprintf(summary_msg, sizeof(summary_msg),
                         "最近 30 秒内共检测到 %lu 次与目标地址的连接\n"
                         "最近一次连接信息:\n"
                         "时间: %04d-%02d-%02d %02d:%02d:%02d\n"
                         "进程ID: %lu\n"
                         "进程名称: %s\n"
                         "进程路径: %s\n"
                         "本地地址: %s:%u\n"
                         "远程地址: %s:%u\n",
                         g_match_count_30s,
                         g_last_connection.time.wYear, g_last_connection.time.wMonth, g_last_connection.time.wDay,
                         g_last_connection.time.wHour, g_last_connection.time.wMinute, g_last_connection.time.wSecond,
                         g_last_connection.pid,
                         g_last_connection.name,
                         g_last_connection.path,
                         g_last_connection.local_ip, g_last_connection.local_port,
                         g_last_connection.remote_ip, g_last_connection.remote_port);

                SendFeishuNotification(summary_msg);
            } else {
                printf("\n最近 30 秒内未检测到与目标地址的连接\n");
            }
            printf("==========================================\n");
            g_match_count_30s = 0;
            g_last_connection.valid = FALSE;
            g_last_summary_tick = now_tick;
        }

        Sleep(POLL_INTERVAL_MS); // 缩短轮询间隔，减少瞬时连接漏检
    }

    WSACleanup();
    return 0;
}