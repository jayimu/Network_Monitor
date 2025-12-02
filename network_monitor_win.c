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

typedef struct {
    DWORD parentPID;
    char name[MAX_PROCESS_NAME];
    char path[MAX_PROCESS_PATH];
} ProcessInfo;

// 全局变量
char g_webhook_url[MAX_WEBHOOK_URL] = {0};
BOOL g_first_no_connection = TRUE;

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

// 解析域名获取 IPv4 地址
BOOL ResolveDomain(const char* domain, char* ip_out) {
    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET; // 只获取 IPv4 地址
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(domain, NULL, &hints, &result);
    if (ret != 0) {
        return FALSE;
    }

    // 获取第一个 IPv4 地址
    for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        if (ptr->ai_family == AF_INET) {
            struct sockaddr_in* addr = (struct sockaddr_in*)ptr->ai_addr;
            inet_ntop(AF_INET, &(addr->sin_addr), ip_out, INET_ADDRSTRLEN);
            freeaddrinfo(result);
            return TRUE;
        }
    }

    freeaddrinfo(result);
    return FALSE;
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

int main(int argc, char* argv[]) {
    // 设置控制台编码
    SetupConsole();

    // 检查命令行参数
    if (argc < 3) {
        printf("用法:\n");
        printf("监控 IP: %s -t <目标IP>\n", argv[0]);
        printf("监控域名: %s -d <域名>\n", argv[0]);
        printf("可选参数:\n");
        printf("  -w <webhook_url>  设置飞书 webhook URL\n");
        return 1;
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

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            if (!is_valid_ip(argv[i + 1])) {
                printf("错误: %s 不是有效的IP地址\n", argv[i + 1]);
                WSACleanup();
                return 1;
            }
            if (!is_public_ip(argv[i + 1])) {
                printf("错误: %s 不是有效的公网IP地址\n", argv[i + 1]);
                WSACleanup();
                return 1;
            }
            strncpy(target_ip, argv[i + 1], INET_ADDRSTRLEN - 1);
            i++;
        }
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            if (is_valid_ip(argv[i + 1])) {
                printf("错误: %s 是IP地址,请使用 -t 参数\n", argv[i + 1]);
                WSACleanup();
                return 1;
            }
            is_domain = TRUE;
            if (!ResolveDomain(argv[i + 1], target_ip)) {
                printf("错误: 无法解析域名 %s\n", argv[i + 1]);
                WSACleanup();
                return 1;
            }
            printf("域名 %s 解析到 IP: %s\n", argv[i + 1], target_ip);
            i++;
        }
        else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            strncpy(g_webhook_url, argv[i + 1], MAX_WEBHOOK_URL - 1);
            i++;
        }
    }

    if (strlen(target_ip) == 0) {
        printf("未指定目标 IP 或域名\n");
        WSACleanup();
        return 1;
    }

    printf("开始监控与 %s 的网络连接...\n", target_ip);
    printf("使用Ctrl+C停止监控\n");
    printf("==========================================\n");

    // 发送开始监控通知
    char start_msg[512];
    snprintf(start_msg, sizeof(start_msg), "开始监控 IP: %s", target_ip);
    SendFeishuNotification(start_msg);

    while (1) {
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

                if (strcmp(remote_ip, target_ip) == 0) {
                    found = TRUE;
                    g_first_no_connection = TRUE;
                    DWORD pid = pTcpTable->table[i].dwOwningPid;
                    ProcessInfo procInfo;
                    GetProcessInfo(pid, &procInfo);

                    // 获取本地地址
                    IpAddr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
                    char local_ip[16];
                    strcpy(local_ip, inet_ntoa(IpAddr));

                    // 输出连接信息
                    SYSTEMTIME st;
                    GetLocalTime(&st);
                    
                    char connection_info[1024];
                    snprintf(connection_info, sizeof(connection_info),
                            "\n时间: %04d-%02d-%02d %02d:%02d:%02d\n"
                            "进程ID: %lu\n"
                            "进程名称: %s\n"
                            "本地地址: %s:%u\n"
                            "远程地址: %s:%u\n",
                            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                            pid, procInfo.name,
                            local_ip, ntohs((u_short)pTcpTable->table[i].dwLocalPort),
                            remote_ip, ntohs((u_short)pTcpTable->table[i].dwRemotePort));

                    printf("%s", connection_info);
                    printf("------------------------------------------\n");

                    // 发送飞书通知
                    SendFeishuNotification(connection_info);
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

        Sleep(1000); // 每秒检查一次
    }

    WSACleanup();
    return 0;
}