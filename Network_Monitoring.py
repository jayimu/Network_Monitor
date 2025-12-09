import psutil
import time
import socket
import argparse
import requests
import platform
import sys
import os
import dns.resolver
from datetime import datetime
import ipaddress
from typing import Set, Tuple

def check_permissions():
    system = platform.system().lower()
    if system == 'darwin':
        print("检测到MacOS系统，需要root权限运行")
        if os.geteuid() != 0:
            print("请使用sudo重新运行此脚本")
            print("命令示例: sudo python3 Network_Monitoring.py -t <目标IP> 或 -d <域名>")
            sys.exit(1)
    elif system == 'linux':
        if os.geteuid() != 0:
            print("在Linux系统下需要root权限运行")
            print("请使用sudo重新运行此脚本")
            sys.exit(1)
    elif system == 'windows':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("在Windows系统下需要管理员权限运行")
            print("请右键点击命令提示符，选择'以管理员身份运行'")
            sys.exit(1)

def is_valid_ip(ip: str) -> bool:
    """只接受合法的 IPv4 地址"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4
    except ValueError:
        return False

def is_public_ipv4(ip: str) -> bool:
    """
    检查是否为公网IPv4地址
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version != 4:
            return False
        return not (ip_obj.is_private or ip_obj.is_loopback or 
                   ip_obj.is_link_local or ip_obj.is_multicast or 
                   ip_obj.is_reserved)
    except ValueError:
        return False

def is_wildcard_ip(pattern: str) -> bool:
    """检查通配符 IPv4（如 115.*.*.134 或 115.*.*.*），必须四段且至少一段为 *"""
    if not pattern:
        return False
    parts = pattern.split('.')
    if len(parts) != 4:
        return False
    has_wildcard = False
    for part in parts:
        if part == '*':
            has_wildcard = True
        elif part.isdigit():
            num = int(part)
            if num < 0 or num > 255:
                return False
        else:
            return False
    return has_wildcard

def match_wildcard_ip(pattern: str, ip: str) -> bool:
    """检查 IP 是否匹配通配符模式"""
    if not pattern or not ip or not is_valid_ip(ip):
        return False
    p_parts = pattern.split('.')
    ip_parts = ip.split('.')
    if len(p_parts) != 4 or len(ip_parts) != 4:
        return False
    for i in range(4):
        if p_parts[i] != '*' and p_parts[i] != ip_parts[i]:
            return False
    return True

def resolve_domain(domain: str) -> Set[str]:
    """
    解析域名获取所有IPv4地址
    """
    ipv4_addresses = set()
    
    # 首先检查域名格式
    if not domain or '.' not in domain:
        print(f"无效的域名格式: {domain}")
        return ipv4_addresses

    try:
        # 尝试使用系统默认DNS解析
        try:
            ip = socket.gethostbyname(domain)
            if is_valid_ip(ip):
                ipv4_addresses.add(ip)
        except socket.gaierror:
            pass

        # 使用dnspython进行更详细的解析
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        # 解析A记录（IPv4）
        try:
            a_records = resolver.resolve(domain, 'A')
            for record in a_records:
                ip = str(record)
                if is_valid_ip(ip):
                    ipv4_addresses.add(ip)
        except Exception as e:
            print(f"A记录解析失败: {e}")

        # 解析CNAME记录
        try:
            cname_records = resolver.resolve(domain, 'CNAME')
            for record in cname_records:
                cname = str(record.target).rstrip('.')
                cname_ips = resolve_domain(cname)
                ipv4_addresses.update(cname_ips)
        except Exception:
            pass

    except Exception as e:
        print(f"域名解析错误: {e}")

    return ipv4_addresses

def normalize_process_name(name: str) -> str:
    key = "Cursor Helper (Plugin)"
    if name and key in name:
        return key
    return name


def get_process_tree(pid):
    try:
        process = psutil.Process(pid)
        parent = process.parent()
        parent_info = f"父进程: {parent.pid} ({parent.name()})" if parent else "无父进程"
        children = process.children(recursive=True)
        children_info = [f"子进程: {child.pid} ({child.name()})" for child in children]
        return [parent_info] + children_info
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ["无法获取进程树信息"]

def send_to_feishu(webhook_url, message):
    """发送飞书通知，打印状态码/返回体便于排查"""
    if not webhook_url:
        return
    headers = {"Content-Type": "application/json"}
    data = {
        "msg_type": "text",
        "content": {"text": message}
    }
    try:
        response = requests.post(webhook_url, json=data, headers=headers, timeout=5)
        if response.status_code != 200:
            print(f"发送飞书通知失败: HTTP {response.status_code}, 响应: {response.text}")
        else:
            # 可根据需要打印简短成功提示，这里保持静默
            pass
    except Exception as e:
        print(f"发送飞书通知失败: {e}")

def monitor_connection(target_ip: str, webhook_url: str = None, 
                      last_send_time: float = None, 
                      send_interval: int = None,
                      is_wildcard: bool = False) -> Tuple[bool, float]:
    """
    监控与特定IP的连接
    """
    connections = psutil.net_connections(kind='all')
    found = False
    current_time = time.time()
    
    for conn in connections:
        try:
            if conn.raddr:
                # 获取远程IP地址
                if isinstance(conn.raddr, tuple):
                    raddr_ip = conn.raddr[0]  # 元组形式 (ip, port)
                elif hasattr(conn.raddr, 'ip'):
                    raddr_ip = conn.raddr.ip  # 对象形式
                elif isinstance(conn.raddr, str):
                    raddr_ip = conn.raddr.split(':')[0]  # 字符串形式 "ip:port"
                else:
                    continue
                
                matched = False
                if is_wildcard:
                    matched = match_wildcard_ip(target_ip, raddr_ip)
                else:
                    matched = (raddr_ip == target_ip)
                if matched:
                    found = True
                    try:
                        process = psutil.Process(conn.pid)
                        name = normalize_process_name(process.name())
                        
                        info = [
                            f"进程名称: {name}",
                            f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                            f"目标IP: {target_ip}",
                            f"进程ID: {conn.pid}",
                            f"进程路径: {process.exe()}",
                            f"进程命令行: {' '.join(process.cmdline())}",
                            f"本地地址: {conn.laddr[0] if isinstance(conn.laddr, tuple) else conn.laddr.ip}:{conn.laddr[1] if isinstance(conn.laddr, tuple) else conn.laddr.port}",
                            f"远程地址: {raddr_ip}:{conn.raddr[1] if isinstance(conn.raddr, tuple) else conn.raddr.port}"
                        ]
                        
                        process_tree = get_process_tree(conn.pid)
                        info.extend(process_tree)
                        
                        print("\n".join(info))
                        print("-" * 50)
                        
                        if webhook_url and (last_send_time is None or 
                            (send_interval and current_time - last_send_time >= send_interval)):
                            send_to_feishu(webhook_url, "\n".join(info))
                            return True, current_time
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return found, last_send_time

def monitor_all_ips(targets: Set[str], webhook_url: str = None, 
                   send_interval: int = None,
                   domain: str = None,
                   wildcard_pattern: str = None):
    """
    监控所有目标IP地址
    """
    print("\n正在监控以下IP地址的连接:")
    if wildcard_pattern:
        print(f"- {wildcard_pattern} (通配符模式)")
    else:
        for ip in sorted(targets):
            print(f"- {ip}")
    print("\n按Ctrl+C停止监控")
    print("=" * 50)

    last_send_time = None
    last_resolve_time = time.time()
    DNS_RESOLVE_INTERVAL = 5      # 域名DNS刷新间隔（秒）
    POLL_INTERVAL = 0.2           # 监控轮询间隔（秒）
    while True:
        # 周期性刷新域名解析结果
        if domain:
            now = time.time()
            if now - last_resolve_time >= DNS_RESOLVE_INTERVAL:
                resolved_ips = resolve_domain(domain)
                if resolved_ips:
                    targets.clear()
                    targets.update(resolved_ips)
                    print(f"\n域名 {domain} 解析结果已刷新:")
                    for ip in sorted(targets):
                        print(f"- {ip}")
                    print("=" * 50)
                last_resolve_time = now

        # 遍历当前目标IP集合或通配符模式
        if wildcard_pattern:
            found, new_send_time = monitor_connection(wildcard_pattern, webhook_url, last_send_time, send_interval, is_wildcard=True)
            if found and new_send_time:
                last_send_time = new_send_time
        else:
            for ip in list(targets):
                found, new_send_time = monitor_connection(ip, webhook_url, last_send_time, send_interval)
                if found and new_send_time:
                    last_send_time = new_send_time
        # 控制轮询间隔
        time.sleep(POLL_INTERVAL)

def monitor_all_connections(webhook_url: str = None, print_interval: int = 5):
    """全局IPv4连接监控模式（无 -t/-d 参数时使用）

    :param webhook_url: 预留参数，目前全局模式不发飞书，仅本地显示
    :param print_interval: 前台表格刷新间隔（秒）
    """
    POLL_INTERVAL = 0.2               # 抓取间隔（秒，毫秒级）
    PRINT_INTERVAL = float(print_interval)  # 界面刷新间隔（秒）
    # ip -> (local_ip, local_port, remote_port, pid, name, path)
    seen_infos = {}
    header_printed = False
    last_print_time = time.time()
    while True:
        connections = psutil.net_connections(kind='all')
        for conn in connections:
            try:
                if not conn.raddr:
                    continue
                # 只处理IPv4
                if isinstance(conn.raddr, tuple):
                    raddr_ip, raddr_port = conn.raddr[0], conn.raddr[1]
                else:
                    continue
                if not is_valid_ip(raddr_ip):
                    continue
                # 过滤 0.0.0.0 和 127.0.0.1
                if raddr_ip in ("0.0.0.0", "127.0.0.1"):
                    continue

                laddr_ip, laddr_port = (conn.laddr[0], conn.laddr[1]) if isinstance(conn.laddr, tuple) else (None, None)
                if not laddr_ip or not is_valid_ip(laddr_ip):
                    continue

                # 只记录首见该远程IP的一条连接信息
                if raddr_ip in seen_infos:
                    continue

                pid = conn.pid or 0
                try:
                    process = psutil.Process(pid) if pid else None
                    name = normalize_process_name(process.name()) if process else "未知进程"
                    path = process.exe() if process else "无法获取路径"
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    name = "未知进程"
                    path = "无法获取路径"

                seen_infos[raddr_ip] = (laddr_ip, laddr_port, raddr_port, pid, name, path)
            except Exception:
                continue

        # 每 PRINT_INTERVAL 秒刷新一次输出表格
        now = time.time()
        if now - last_print_time >= PRINT_INTERVAL:
            if not header_printed:
                print("\n实时统计本机所有 IPv4 连接状态（按远程IP去重，只打印首见连接信息）")
                header_printed = True
            print("\r", end="")
            print("源地址           源端口 -> 目的地址         目的端口 PID    进程名称                    进程路径")
            print("-----------------------------------------------------------------------------------------------------------")
            for ip, (laddr_ip, laddr_port, raddr_port, pid, name, path) in seen_infos.items():
                print(f"{laddr_ip:<15} {laddr_port:<5} -> {ip:<15} {raddr_port:<8} {pid:<6} {name:<25} {path:<60}")
            print("\n按 Ctrl+C 停止监控...", end="")
            last_print_time = now

        time.sleep(POLL_INTERVAL)


def main():
    HELP_TEXT = '''参数:
  -t <IP地址>       监控指定IPv4，可用通配符(如 115.*.*.134)
  -d <域名>         监控指定域名
  -a <秒>           全局模式：刷新间隔
  -w <webhook_url>  飞书 webhook
  -s <秒>           通知节流间隔，默认30
  -h                显示此帮助
'''

    parser = argparse.ArgumentParser(
        description='网络连接监控工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-t', '--target', help='要监控的目标IP地址（支持通配符）')
    group.add_argument('-d', '--domain', help='要监控的目标域名')
    parser.add_argument('-w', '--webhook', help='飞书webhook URL')
    parser.add_argument('-s', '--send-interval', type=int, default=30,
                      help='飞书通知发送间隔(秒)，默认30')
    parser.add_argument('-a', '--all', type=int,
                      help='全局IPv4统计模式，前台刷新间隔(秒)，例如 -a 5')
    parser.add_argument('-h', '--help', action='store_true', help=argparse.SUPPRESS)
    
    args = parser.parse_args()

    if args.help:
        print(HELP_TEXT)
        sys.exit(0)
    
    # 检查权限
    check_permissions()
    
    targets = set()
    
    # 处理 -a 全局模式（与 -t/-d 互斥）
    if args.all is not None:
        if args.target or args.domain:
            print("错误: -a 不能与 -t 或 -d 同时使用")
            sys.exit(1)
        try:
            monitor_all_connections(args.webhook, print_interval=args.all)
        except KeyboardInterrupt:
            print("\n停止监控")
            sys.exit(0)
        return

    # 若既没有target也没有domain也没有-a，则提示用法
    if not args.target and not args.domain:
        parser.print_help()
        sys.exit(1)

    # 处理目标IP
    wildcard_pattern = None
    if args.target:
        if is_wildcard_ip(args.target):
            wildcard_pattern = args.target
            print(f"使用通配符IP模式: {args.target}")
        elif not is_valid_ip(args.target):
            print(f"错误: {args.target} 不是有效的IP地址或通配符IP格式")
            print("示例: 115.*.*.134 或 115.*.*.*")
            sys.exit(1)
        else:
            targets.add(args.target)
    
    # 处理域名
    if args.domain:
        if is_valid_ip(args.domain):
            print(f"错误: {args.domain} 是IP地址,请使用 -t 参数")
            sys.exit(1)
        resolved_ips = resolve_domain(args.domain)
        if not resolved_ips:
            print(f"错误: 无法解析域名 {args.domain}")
            sys.exit(1)
        targets.update(resolved_ips)
    
    # 开始监控
    try:
        # 如果是域名模式，传入域名；IP模式则不需要
        domain = args.domain if args.domain else None
        monitor_all_ips(targets, args.webhook, args.send_interval,
                        domain=domain, wildcard_pattern=wildcard_pattern)
    except KeyboardInterrupt:
        print("\n停止监控")
        sys.exit(0)

if __name__ == '__main__':
    main()