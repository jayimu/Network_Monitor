# 恶意程序网络行为监控与应急处理工具

面向应急响应场景的一体化轻量工具，实时捕获本机 IPv4 连接并按「远程 IP+端口」去重，支持对指定恶意 IP/域名进行秒级定位，可迅速锁定潜伏后门、时间触发式木马或任何可疑进程；同时持续记录异常外联日志，并通过飞书实时推送告警，帮助一线人员完成从发现、取证到清除的闭环处置。



## Windows 编译运行

```bash
# 编译
gcc -o network_monitor.exe network_monitor_win.c -lws2_32 -liphlpapi -lwinhttp

# 运行 (管理员权限)
network_monitor.exe -t 恶意IP            # 支持通配符，如 '115.*.*.134'
network_monitor.exe -d 恶意域名
network_monitor.exe -a 5                #全局监控
network_monitor.exe -t 恶意IP -w 飞书webhook地址
network_monitor.exe -t 115.*.*.* -w 飞书webhook地址
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
sudo ./network_monitor -a 5
sudo ./network_monitor -t 恶意IP -w 飞书webhook地址
```

## Python 版本

```bash
# 安装依赖
pip install -r requirements.txt

python Network_Monitoring.py -t 恶意IP

```

## 参数说明

### 主要参数（三选一，不能同时使用）

#### `-t <IP地址>` - 监控指定IP（支持通配符）
监控与指定IP地址的所有网络连接，当检测到连接时立即显示进程信息。支持通配符 IPv4（如 `115.*.*.134` 或 `115.*.*.*`），匹配任意段。

**功能特点：**
- 实时检测与目标IP的连接
- 立即显示进程信息（PID、进程名、路径、用户等）
- 支持飞书告警推送

**使用示例：**
```bash
# 监控特定恶意IP
sudo ./network_monitor -t 115.120.245.134

# 监控通配符IP（需要引号，避免被 shell 展开）
sudo ./network_monitor -t '115.*.*.134'

# 配合飞书告警
sudo ./network_monitor -t 115.120.245.134 -w https://open.feishu.cn/open-apis/bot/v2/hook/xxx
```


#### `-d <域名>` - 监控指定域名
监控与指定域名的所有网络连接，自动解析域名获取IP列表，并定期刷新DNS解析结果。

**功能特点：**
- 自动解析域名获取所有IP地址
- 每5秒自动刷新DNS解析结果（适应动态IP）
- 监控域名下的所有IP连接
- 支持飞书告警推送

**使用示例：**
```bash
# 监控可疑域名
sudo ./network_monitor -d malicious-domain.com

# 配合飞书告警
sudo ./network_monitor -d malicious-domain.com -w https://open.feishu.cn/open-apis/bot/v2/hook/xxx
```


#### `-a <刷新间隔秒数>` - 全局监控模式
实时统计本机所有 IPv4 网络连接状态，按远程IP+端口去重显示。

**功能特点：**
- 显示本机所有活跃的IPv4连接
- 按远程IP+端口去重，避免重复显示
- 自动过滤LISTEN状态和本地回环地址
- 定期刷新显示（默认5秒，可自定义）
- 显示完整的连接信息：源地址、源端口、目的地址、目的端口、PID、进程名、进程路径

**使用示例：**
```bash
# 每5秒刷新一次显示
sudo ./network_monitor -a 5

# 每10秒刷新一次显示
sudo ./network_monitor -a 10
```


### 可选参数

#### `-w <webhook_url>` - 飞书告警地址
设置飞书机器人 webhook 地址，当检测到目标连接时自动推送告警信息。

**使用示例：**
```bash
sudo ./network_monitor -t 115.120.245.134 -w https://open.feishu.cn/open-apis/bot/v2/hook/your-webhook-url
```

#### `-s <秒数>` - 通知间隔
设置飞书告警的发送间隔（秒），默认30秒。避免短时间内重复发送相同告警；命中时会立即推送一次，后续按间隔节流。

**使用示例：**
```bash
# 设置告警间隔为60秒
sudo ./network_monitor -t 115.120.245.134 -w webhook_url -s 60
```
