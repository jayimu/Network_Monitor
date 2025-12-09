# 恶意程序网络行为监控与应急处理工具

面向应急响应场景的一体化轻量工具，实时捕获本机 IPv4 连接并按「远程 IP+端口」去重，支持对指定恶意 IP/域名进行秒级定位，可迅速锁定潜伏后门、时间触发式木马或任何可疑进程；同时持续记录异常外联日志，并通过飞书实时推送告警，帮助一线人员完成从发现、取证到清除的闭环处置。



## Windows 编译运行

# 编译
gcc -o network_monitor.exe network_monitor_win.c -lws2_32 -liphlpapi -lwinhttp


## Linux 编译运行
# 编译
sudo apt update
sudo apt install -y gcc libpcap-dev libcurl4-openssl-dev
gcc -o network_monitor network_monitor_linux.c -lpcap -lcurl



## Python 版本

```bash
# 安装依赖
pip install -r requirements.txt

python Network_Monitoring.py -t 恶意IP

```
# 运行 (管理员权限)
network_monitor.exe -t 恶意IP            # 支持IPV4地址,支持通配符，如 '115.*.*.134'
network_monitor.exe -d 恶意域名
network_monitor.exe -a 5                #全局监控
network_monitor.exe -t 恶意IP -w 飞书webhook地址 -s 10  #不带-s 参数默认 30s

## 快速用法（精简版）

- 监控 IP（含通配符）：`sudo ./network_monitor -t '115.*.*.134' [-w webhook] [-s 30]`
- 监控域名：`sudo ./network_monitor -d example.com [-w webhook] [-s 30]`（解析出的全部 IPv4 自动加入监控并周期刷新）
- 全局模式：`sudo ./network_monitor -a 5`（去重显示所有 IPv4 连接）
- `-w` 飞书 webhook：命中立即推送一条，后续按 `-s` 秒汇总（默认 30）
- Windows / Linux / Python 版本参数一致；使用通配符请加引号
