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
    """
    检查是否为有效的IP地址格式
    """
    try:
        ipaddress.ip_address(ip)
        return True
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
    if not webhook_url:
        return
    headers = {"Content-Type": "application/json"}
    data = {
        "msg_type": "text",
        "content": {"text": message}
    }
    try:
        response = requests.post(webhook_url, json=data, headers=headers)
        response.raise_for_status()
    except Exception as e:
        print(f"发送飞书通知失败: {e}")

def monitor_connection(target_ip: str, webhook_url: str = None, 
                      last_send_time: float = None, 
                      send_interval: int = None) -> Tuple[bool, float]:
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
                
                if raddr_ip == target_ip:
                    found = True
                    try:
                        process = psutil.Process(conn.pid)
                        
                        info = [
                            f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                            f"目标IP: {target_ip}",
                            f"进程ID: {conn.pid}",
                            f"进程名称: {process.name()}",
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
                   send_interval: int = None):
    """
    监控所有目标IP地址
    """
    print("\n正在监控以下IP地址的连接:")
    for ip in sorted(targets):
        print(f"- {ip}")
    print("\n按Ctrl+C停止监控")
    print("=" * 50)

    last_send_time = None
    while True:
        for ip in targets:
            found, new_send_time = monitor_connection(ip, webhook_url, last_send_time, send_interval)
            if found and new_send_time:
                last_send_time = new_send_time
        time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description='网络连接监控工具')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', help='要监控的目标IP地址')
    group.add_argument('-d', '--domain', help='要监控的目标域名')
    parser.add_argument('-w', '--webhook', help='飞书webhook URL')
    parser.add_argument('-s', '--send-interval', type=int, default=300,
                      help='飞书通知发送间隔(秒)')
    
    args = parser.parse_args()
    
    # 检查权限
    check_permissions()
    
    targets = set()
    
    # 处理目标IP
    if args.target:
        if not is_valid_ip(args.target):
            print(f"错误: {args.target} 不是有效的IP地址")
            sys.exit(1)
        if not is_public_ipv4(args.target):
            print(f"错误: {args.target} 不是有效的公网IPv4地址")
            sys.exit(1)
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
        monitor_all_ips(targets, args.webhook, args.send_interval)
    except KeyboardInterrupt:
        print("\n停止监控")
        sys.exit(0)

if __name__ == '__main__':
    main()