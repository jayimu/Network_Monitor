# 恶意程序网络行为监控与应急处理工具

针对恶意程序的网络连接行为监控工具，特别适用于应急响应场景。通过监控特定 IP/域名的网络连接，快速定位潜伏的恶意程序，协助应急处理人员及时发现和清除威胁。

## 应用场景

### 应急处理
- 已知恶意 IP/域名的程序定位
- 发现潜伏期的恶意程序（如等待特定时间才激活的后门）
- 快速确定受感染主机上的恶意进程

### 持续监控
- 监控可疑程序的对外连接行为
- 记录程序异常网络行为
- 通过飞书实时推送告警信息

### TODO

1. **挖矿程序检测**：
   - 监控已知矿池地址
   - 发现异常网络连接及其关联进程

2. **后门程序检测**：
   - 监控可疑的对外连接
   - 识别定时回连的隐藏程序

## Windows 编译运行

```bash
# 编译
gcc -o network_monitor.exe network_monitor_win.c -lws2_32 -liphlpapi -lwinhttp

# 运行 (管理员权限)
network_monitor.exe -t 恶意IP
network_monitor.exe -d 恶意域名
network_monitor.exe -t 恶意IP -w 飞书webhook地址 -s 发送飞书间隔
```

## Linux 编译运行

```bash
# 编译
sudo apt update
sudo apt install -y gcc libpcap-dev libcurl4-openssl-dev
gcc -o network_monitor network_monitor_linux.c -lpcap -lcurl

# 运行
sudo ./network_monitor -t 恶意IP
sudo ./network_monitor -d 恶意域名
sudo ./network_monitor -t 恶意IP -w 飞书webhook地址
```

## Python 版本

```bash
# 安装依赖
pip install -r requirements.txt

# Windows运行(管理员权限)
python Network_Monitoring.py -t 恶意IP

# Linux运行
sudo python3 Network_Monitoring.py -t 恶意IP
```

## 参数说明
- `-t <IP>`: 监控指定恶意 IP
- `-d <域名>`: 监控指定恶意域名
- `-w <webhook_url>`: 飞书告警地址
- `-s <time>`:  飞书告警时间间隔

## 应急处理流程建议

### 1. 前期准备
- 部署监控工具到可疑主机
- 配置飞书告警，确保远程及时获取信息
- 收集已知的恶意 IP/域名列表

### 2. 监控阶段
- 持续监控可疑的网络连接
- 记录所有尝试连接恶意地址的进程信息
- 通过飞书接收实时告警

### 3. 发现异常
- 立即记录可疑进程信息（PID、路径、命令行等）
- 保存进程相关文件，用于后续分析
- 必要时立即终止可疑进程

### 4. 后续处理
- 分析可疑程序的启动方式和持久化机制
- 检查系统中类似程序或文件
- 清理相关的启动项和计划任务
