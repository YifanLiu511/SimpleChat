import warnings
import datetime

# 抑制所有警告，包括libpng警告
warnings.filterwarnings("ignore")

import socket
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import time
import os

# 日志辅助函数
def get_timestamp():
    """获取当前时间戳"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# 日志级别
LOG_LEVEL = "DEBUG"  # 可选值: DEBUG, INFO, WARNING, ERROR

def log_message(level, message):
    """记录日志消息"""
    if level == "DEBUG" and LOG_LEVEL != "DEBUG":
        return
    if level == "INFO" and LOG_LEVEL not in ["DEBUG", "INFO"]:
        return
    print(f"[{get_timestamp()}] [{level}] {message}")

# 常量定义
BROADCAST_PORT = 5000
MESSAGE_PORT = 5001
FILE_PORT = 5002
BROADCAST_KEYWORD = "CHAT_GROUP_DISCOVERY"
BUFFER_SIZE = 1024
FILE_CHUNK_SIZE = 4096

class ChatClient:
    def __init__(self):
        self.username = socket.gethostname()
        self.ip = self.get_local_ip()
        self.members = {}
        self.is_running = True
        self.root = tk.Tk()
        self.root.title(f"简易聊天工具 - {self.username}")
        self.setup_gui()
        
        # 初始化网络组件
        self.init_network()
        
    def get_local_ip(self):
        """获取本地IP地址（默认路由IP）"""
        try:
            # 方法1：通过UDP连接获取默认路由IP，这是最可靠的方法
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)  # 设置超时时间，防止阻塞
            # 连接到外部服务器，但不会发送任何数据
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            log_message("DEBUG", f"通过UDP连接获取到本地IP: {ip}")
            return ip
        except Exception as e:
            log_message("DEBUG", f"通过UDP连接获取IP失败: {e}")
            
            # 方法2：使用socket.gethostbyname_ex获取所有IP，然后选择合适的IP
            try:
                hostname = socket.gethostname()
                _, _, addrs = socket.gethostbyname_ex(hostname)
                log_message("DEBUG", f"gethostbyname_ex返回IP列表: {addrs}")
                
                # 优先选择192.168.x.x网段的IP
                for ip in addrs:
                    if ip.startswith('192.168.') and ip != '127.0.0.1':
                        log_message("DEBUG", f"从gethostbyname_ex选择IP: {ip}")
                        return ip
                
                # 其次选择172.16.x.x到172.31.x.x网段的IP
                for ip in addrs:
                    parts = ip.split('.')
                    if len(parts) >= 2 and parts[0] == '172' and 16 <= int(parts[1]) <= 31:
                        log_message("DEBUG", f"从gethostbyname_ex选择IP: {ip}")
                        return ip
                
                # 然后选择10.x.x.x网段的IP
                for ip in addrs:
                    if ip.startswith('10.') and ip != '127.0.0.1':
                        log_message("DEBUG", f"从gethostbyname_ex选择IP: {ip}")
                        return ip
                
                # 最后选择第一个非回环IP
                for ip in addrs:
                    if ip != '127.0.0.1':
                        log_message("DEBUG", f"从gethostbyname_ex选择IP: {ip}")
                        return ip
            except Exception as e2:
                log_message("DEBUG", f"通过gethostbyname_ex获取IP失败: {e2}")
                
                # 方法3：使用socket.getaddrinfo获取IP
                try:
                    for addr in socket.getaddrinfo(socket.gethostname(), None):
                        if addr[0] == socket.AF_INET and addr[4][0] != '127.0.0.1':
                            ip = addr[4][0]
                            log_message("DEBUG", f"从getaddrinfo获取到本地IP: {ip}")
                            return ip
                except Exception as e3:
                    log_message("DEBUG", f"通过getaddrinfo获取IP失败: {e3}")
            
            # 最终 fallback：使用127.0.0.1
            log_message("DEBUG", f"所有方法获取IP失败，使用默认IP: 127.0.0.1")
            return '127.0.0.1'
        finally:
            try:
                s.close()
            except:
                pass
    
    def get_all_local_ips(self):
        """获取所有本地网络接口的IP地址，兼容不同系统，过滤虚拟网络适配器"""
        ips = []
        try:
            log_message("DEBUG", "开始获取所有本地IP地址")
            
            # 获取默认路由IP
            default_ip = self.get_local_ip()
            log_message("DEBUG", f"默认路由IP: {default_ip}")
            
            # 获取所有IP地址
            all_addrs = []
            
            # 方法1：使用socket.getaddrinfo获取IP地址
            log_message("DEBUG", "方法1 - 使用socket.getaddrinfo获取IP地址")
            addrinfo_results = socket.getaddrinfo(socket.gethostname(), None)
            log_message("DEBUG", f"getaddrinfo返回 {len(addrinfo_results)} 个结果")
            
            for addr in addrinfo_results:
                if addr[0] == socket.AF_INET and addr[4][0] != '127.0.0.1':
                    ip = addr[4][0]
                    if ip not in all_addrs:
                        all_addrs.append(ip)
            
            # 方法2：使用socket.gethostbyname_ex获取IP地址
            log_message("DEBUG", "方法2 - 使用socket.gethostbyname_ex获取IP地址")
            hostname = socket.gethostname()
            log_message("DEBUG", f"主机名: {hostname}")
            
            _, _, addrs = socket.gethostbyname_ex(hostname)
            log_message("DEBUG", f"gethostbyname_ex返回 {len(addrs)} 个IP: {addrs}")
            
            for ip in addrs:
                if ip != '127.0.0.1' and ip not in all_addrs:
                    all_addrs.append(ip)
            
            log_message("DEBUG", f"所有获取到的IP: {all_addrs}")
            
            # 过滤IP地址
            filtered_ips = []
            for ip in all_addrs:
                # 过滤已知的虚拟网络适配器IP范围（仅过滤特定的VMware和VirtualBox网段）
                if ip.startswith('192.168.189.') or ip.startswith('192.168.48.'):
                    log_message("DEBUG", f"过滤虚拟网络适配器IP: {ip}")
                    continue
                # 直接添加所有其他IP（包括无线IP）
                filtered_ips.append(ip)
                log_message("DEBUG", f"添加IP: {ip}")
            
            # 如果过滤后没有IP，添加默认IP
            if not filtered_ips:
                filtered_ips.append(default_ip)
                log_message("DEBUG", f"过滤后没有IP，添加默认IP: {default_ip}")
            
            # 确保默认IP在列表中
            if default_ip not in filtered_ips:
                filtered_ips.append(default_ip)
                log_message("DEBUG", f"添加默认IP: {default_ip}")
            
            ips = filtered_ips
            
        except Exception as e:
            # 出错时使用默认IP
            log_message("ERROR", f"获取本地IP时出错: {e}")
            default_ip = self.get_local_ip()
            ips.append(default_ip)
            log_message("DEBUG", f"出错时使用默认IP: {default_ip}")
        
        log_message("DEBUG", f"最终获取到的IP列表: {ips}")
        return ips
    
    def get_subnet_broadcast(self, ip):
        """计算给定IP地址对应的子网广播地址"""
        try:
            log_message("DEBUG", f"正在为IP {ip} 计算子网广播地址")
            
            ip_parts = list(map(int, ip.split('.')))
            
            # 针对不同IP类型使用更精确的广播地址计算
            if ip_parts[0] == 10:  # A类私有IP
                # 10.0.0.0/8 网段，广播地址为 10.255.255.255
                broadcast_parts = [10, 255, 255, 255]
                log_message("DEBUG", f"A类IP，使用/8子网掩码")
            elif ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:  # B类私有IP
                # 172.16.0.0/12 网段，广播地址为 172.31.255.255
                broadcast_parts = [172, 31, 255, 255]
                log_message("DEBUG", f"B类IP，使用/12子网掩码")
            elif ip_parts[0] == 192 and ip_parts[1] == 168:  # C类私有IP（包括无线）
                # 无线网络通常使用/24子网掩码，所以广播地址为 192.168.x.255
                broadcast_parts = [192, 168, ip_parts[2], 255]
                log_message("DEBUG", f"C类/无线IP，使用/24子网掩码，计算出的广播地址: {'.'.join(map(str, broadcast_parts))}")
            else:
                # 其他情况，默认使用255.255.255.255
                broadcast_parts = [255, 255, 255, 255]
                log_message("DEBUG", f"其他IP类型，使用255.255.255.255")
            
            broadcast_addr = '.'.join(map(str, broadcast_parts))
            log_message("DEBUG", f"计算出的广播地址: {broadcast_addr}")
            return broadcast_addr
        except Exception as e:
            # 出错时返回默认广播地址并记录错误
            log_message("ERROR", f"计算子网广播地址时出错: {e}")
            return '255.255.255.255'
    
    def init_network(self):
        """初始化网络组件"""
        # UDP广播接收器
        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.broadcast_socket.bind(('', BROADCAST_PORT))
        
        # 消息接收套接字
        self.message_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.message_socket.bind(('', MESSAGE_PORT))
        
        # 文件传输套接字
        self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.file_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.file_socket.bind(('', FILE_PORT))
        self.file_socket.listen(5)
        
        # 启动线程
        threading.Thread(target=self.receive_broadcast, daemon=True).start()
        threading.Thread(target=self.receive_message, daemon=True).start()
        threading.Thread(target=self.receive_file, daemon=True).start()
        threading.Thread(target=self.cleanup_members, daemon=True).start()
    
    def setup_gui(self):
        """设置GUI界面"""
        # 主框架
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 左侧成员列表
        self.member_frame = ttk.LabelFrame(self.main_frame, text="在线成员", padding="5")
        self.member_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.W, tk.E), padx=(0, 10))
        
        self.member_list = tk.Listbox(self.member_frame, height=20)
        self.member_list.pack(fill=tk.BOTH, expand=True)
        
        self.refresh_btn = ttk.Button(self.member_frame, text="刷新成员", command=self.refresh_members)
        self.refresh_btn.pack(fill=tk.X, pady=5)
        
        # 右侧聊天区域
        self.chat_frame = ttk.LabelFrame(self.main_frame, text="聊天窗口", padding="5")
        self.chat_frame.grid(row=0, column=1, sticky=(tk.N, tk.S, tk.W, tk.E))
        
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, height=20, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 消息输入区域
        self.input_frame = ttk.Frame(self.chat_frame)
        self.input_frame.pack(fill=tk.X)
        
        self.message_input = ttk.Entry(self.input_frame)
        self.message_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_input.bind("<Return>", lambda event: self.send_message())
        
        self.send_btn = ttk.Button(self.input_frame, text="发送", command=self.send_message)
        self.send_btn.pack(side=tk.LEFT)
        
        self.broadcast_btn = ttk.Button(self.input_frame, text="广播", command=self.send_broadcast_message)
        self.broadcast_btn.pack(side=tk.LEFT, padx=5)
        
        self.file_btn = ttk.Button(self.input_frame, text="发送文件", command=self.send_file)
        self.file_btn.pack(side=tk.LEFT)
        
        # 文件传输进度条
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="文件传输", padding="5")
        self.progress_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X)
        
        self.progress_label = ttk.Label(self.progress_frame, text="准备就绪")
        self.progress_label.pack()
        
        # 配置网格权重
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1)
    
    def refresh_members(self):
        """刷新成员列表"""
        self.append_message("正在刷新成员列表...")
        self.send_broadcast()
    
    def receive_broadcast(self):
        """接收广播消息"""
        while self.is_running:
            try:
                data, addr = self.broadcast_socket.recvfrom(BUFFER_SIZE)
                message = data.decode('utf-8')
                
                log_message("DEBUG", f"接收到广播消息: {message} 来自 {addr}")
                
                # 解析消息，获取真实的发送者IP
                sender_real_ip = addr[0]
                if message.startswith(BROADCAST_KEYWORD):
                    parts = message.split(',')
                    if len(parts) >= 3:
                        sender_real_ip = parts[1]
                
                # 忽略自己发送的广播
                if sender_real_ip == self.ip:
                    log_message("DEBUG", f"忽略自己发送的广播消息")
                    continue
                
                # 首先处理响应消息
                if message.startswith(f"{BROADCAST_KEYWORD},RESPONSE"):
                    parts = message.split(',')
                    if len(parts) >= 4:
                        _, _, member_ip, member_name = parts[0], parts[1], parts[2], parts[3]
                        if member_ip != self.ip:
                            # 检查是否已经存在该成员
                            if member_ip in self.members:
                                log_message("DEBUG", f"成员 {member_name} ({member_ip}) 已存在，更新信息")
                                old_name = self.members[member_ip]
                                if old_name != member_name:
                                    self.members[member_ip] = member_name
                                    self.update_member_list()
                                    self.append_message(f"{old_name} 已更名为 {member_name}")
                            else:
                                # 新成员，添加到列表
                                self.members[member_ip] = member_name
                                self.update_member_list()
                                self.append_message(f"{member_name} ({member_ip}) 加入了聊天组")
                                log_message("DEBUG", f"添加成员: {member_name} ({member_ip})")
                
                # 然后处理普通广播消息
                elif message.startswith(BROADCAST_KEYWORD):
                    # 解析广播消息
                    parts = message.split(',')
                    if len(parts) >= 3:
                        keyword, sender_ip, sender_port = parts[0], parts[1], parts[2]
                        
                        # 如果不是自己发送的广播
                        if sender_ip != self.ip:
                            # 返回自己的信息
                            response = f"{BROADCAST_KEYWORD},RESPONSE,{self.ip},{self.username}"
                            
                            # 向发送方IP发送响应，重试3次
                            success = False
                            for i in range(3):
                                try:
                                    log_message("DEBUG", f"向 {sender_ip}:{sender_port} 发送响应: {response} (尝试 {i+1}/3)")
                                    self.broadcast_socket.sendto(response.encode('utf-8'), (sender_ip, int(sender_port)))
                                    success = True
                                    break
                                except Exception as e:
                                    log_message("DEBUG", f"向 {sender_ip}:{sender_port} 发送响应失败 (尝试 {i+1}/3): {e}")
                                    if i < 2:
                                        time.sleep(0.1)
                            
                            # 如果直接发送失败，尝试向发送方的子网广播地址发送响应
                            if not success:
                                log_message("DEBUG", f"向 {sender_ip} 直接发送响应失败，尝试向其子网广播地址发送")
                                # 计算发送方IP的子网广播地址
                                sender_broadcast = self.get_subnet_broadcast(sender_ip)
                                try:
                                    self.broadcast_socket.sendto(response.encode('utf-8'), (sender_broadcast, int(sender_port)))
                                    log_message("DEBUG", f"向 {sender_ip} 的子网广播地址 {sender_broadcast} 发送响应成功")
                                except Exception as e:
                                    log_message("DEBUG", f"向 {sender_broadcast} 发送响应失败: {e}")
                            
                            # 同时向所有本地子网广播地址发送响应，确保在复杂网络环境下能被正确接收
                            all_ips = self.get_all_local_ips()
                            for ip in all_ips:
                                broadcast_addr = self.get_subnet_broadcast(ip)
                                try:
                                    log_message("DEBUG", f"向本地子网广播地址 {broadcast_addr}:{sender_port} 发送响应: {response}")
                                    self.broadcast_socket.sendto(response.encode('utf-8'), (broadcast_addr, int(sender_port)))
                                except Exception as e:
                                    log_message("DEBUG", f"向 {broadcast_addr} 发送响应失败: {e}")
            except Exception as e:
                if self.is_running:
                    log_message("ERROR", f"广播接收错误: {e}")
                    time.sleep(1)
    
    def send_broadcast(self):
        """发送广播消息到所有本地网络接口的子网"""
        message = f"{BROADCAST_KEYWORD},{self.ip},{BROADCAST_PORT}"
        try:
            log_message("DEBUG", f"开始发送广播消息: {message}")
            
            # 获取所有本地IP地址
            all_ips = self.get_all_local_ips()
            log_message("DEBUG", f"找到 {len(all_ips)} 个本地IP地址: {all_ips}")
            
            # 向每个IP对应的子网广播地址发送消息
            broadcast_addresses = set()
            sent_count = 0
            
            # 为每个IP地址计算子网广播地址并发送广播
            for ip in all_ips:
                # 计算当前IP的子网广播地址
                broadcast_addr = self.get_subnet_broadcast(ip)
                broadcast_addresses.add(broadcast_addr)
                
                # 向子网广播地址发送广播，重试3次
                for i in range(3):
                    try:
                        log_message("DEBUG", f"向IP {ip} 的子网广播地址 {broadcast_addr} 发送广播 (尝试 {i+1}/3)")
                        self.broadcast_socket.sendto(message.encode('utf-8'), (broadcast_addr, BROADCAST_PORT))
                        sent_count += 1
                        break  # 发送成功，退出重试
                    except Exception as e:
                        log_message("DEBUG", f"向 {broadcast_addr} 发送广播失败 (尝试 {i+1}/3): {e}")
                        if i < 2:  # 不是最后一次尝试，等待100ms后重试
                            time.sleep(0.1)
            
            # 同时发送到255.255.255.255确保兼容性
            broadcast_addresses.add('255.255.255.255')
            for i in range(3):
                try:
                    log_message("DEBUG", f"向全局广播地址 255.255.255.255 发送广播 (尝试 {i+1}/3)")
                    self.broadcast_socket.sendto(message.encode('utf-8'), ('255.255.255.255', BROADCAST_PORT))
                    sent_count += 1
                    break
                except Exception as e:
                    log_message("DEBUG", f"向 255.255.255.255 发送广播失败 (尝试 {i+1}/3): {e}")
                    if i < 2:
                        time.sleep(0.1)
            
            # 额外的兼容性处理：向所有已知子网发送广播，特别是无线常见子网
            # 无线网络常见的子网段
            extra_broadcasts = ['192.168.0.255', '192.168.1.255', '192.168.2.255', '192.168.3.255', 
                               '192.168.10.255', '192.168.100.255', '192.168.200.255']
            for bcast in extra_broadcasts:
                if bcast not in broadcast_addresses:
                    broadcast_addresses.add(bcast)
                    for i in range(3):
                        try:
                            log_message("DEBUG", f"向额外广播地址 {bcast} 发送广播 (尝试 {i+1}/3)")
                            self.broadcast_socket.sendto(message.encode('utf-8'), (bcast, BROADCAST_PORT))
                            sent_count += 1
                            break
                        except Exception as e:
                            log_message("DEBUG", f"向 {bcast} 发送广播失败 (尝试 {i+1}/3): {e}")
                            if i < 2:
                                time.sleep(0.1)
            
            # 特别为无线设备添加广播：向当前IP所在的/24子网直接发送广播
            for ip in all_ips:
                if ip.startswith('192.168.'):
                    ip_parts = list(map(int, ip.split('.')))
                    wireless_bcast = f"192.168.{ip_parts[2]}.255"
                    if wireless_bcast not in broadcast_addresses:
                        broadcast_addresses.add(wireless_bcast)
                        for i in range(3):
                            try:
                                log_message("DEBUG", f"向无线子网广播地址 {wireless_bcast} 发送广播 (尝试 {i+1}/3)")
                                self.broadcast_socket.sendto(message.encode('utf-8'), (wireless_bcast, BROADCAST_PORT))
                                sent_count += 1
                                break
                            except Exception as e:
                                log_message("DEBUG", f"向 {wireless_bcast} 发送广播失败 (尝试 {i+1}/3): {e}")
                                if i < 2:
                                    time.sleep(0.1)
            
            log_message("DEBUG", f"广播发送完成，共发送 {sent_count} 次，覆盖 {len(broadcast_addresses)} 个不同的广播地址: {broadcast_addresses}")
        except Exception as e:
            log_message("ERROR", f"广播发送错误: {e}")
    
    def update_member_list(self):
        """更新成员列表显示"""
        self.member_list.delete(0, tk.END)
        # 添加自己到列表
        self.member_list.insert(tk.END, f"{self.username} (我) - {self.ip}")
        # 添加其他成员
        for ip, name in self.members.items():
            self.member_list.insert(tk.END, f"{name} - {ip}")
    
    def receive_message(self):
        """接收消息"""
        while self.is_running:
            try:
                data, addr = self.message_socket.recvfrom(BUFFER_SIZE)
                message = data.decode('utf-8')
                
                # 处理特殊消息类型
                if message.startswith("HEARTBEAT|"):
                    # 心跳包，无需响应
                    continue
                    
                elif message.startswith("EXIT|"):
                    # 退出通知
                    parts = message.split('|')
                    if len(parts) >= 3:
                        _, sender_ip, sender_name = parts[0], parts[1], parts[2]
                        if sender_ip in self.members:
                            del self.members[sender_ip]
                            self.append_message(f"{sender_name} ({sender_ip}) 已退出聊天组")
                            self.update_member_list()
                            
                # 普通消息
                elif '|' in message:
                    sender_ip, sender_name, content = message.split('|', 2)
                    self.append_message(f"[{sender_name} ({sender_ip})] {content}")
                    
            except Exception as e:
                if self.is_running:
                    log_message("ERROR", f"消息接收错误: {e}")
                    time.sleep(1)
    
    def send_message(self):
        """发送消息"""
        content = self.message_input.get().strip()
        if not content:
            return
            
        # 获取选中的成员
        selected_index = self.member_list.curselection()
        if not selected_index:
            self.append_message("请先选择一个聊天对象")
            return
            
        selected_item = self.member_list.get(selected_index[0])
        
        # 如果选择的是自己，不发送
        if "(我)" in selected_item:
            self.append_message("不能向自己发送消息")
            return
            
        # 提取对方IP
        try:
            # 格式: 用户名 - IP地址
            parts = selected_item.split(" - ")
            if len(parts) < 2:
                self.append_message("无法解析选中成员的信息")
                return
            
            target_ip = parts[1]
            target_name = parts[0]
            
            # 发送消息
            message = f"{self.ip}|{self.username}|{content}"
            self.message_socket.sendto(message.encode('utf-8'), (target_ip, MESSAGE_PORT))
            
            # 在自己的聊天窗口显示
            self.append_message(f"[我 -> {target_name} ({target_ip})] {content}")
            
            # 清空输入框
            self.message_input.delete(0, tk.END)
            
        except Exception as e:
            self.append_message(f"发送消息失败: {e}")
            log_message("ERROR", f"发送消息错误: {e}")
    
    def send_broadcast_message(self):
        """发送广播消息"""
        content = self.message_input.get().strip()
        if not content:
            return
            
        # 发送给所有在线成员
        message = f"{self.ip}|{self.username}|{content}"
        for target_ip in self.members:
            try:
                self.message_socket.sendto(message.encode('utf-8'), (target_ip, MESSAGE_PORT))
            except Exception as e:
                log_message("ERROR", f"向 {target_ip} 广播消息失败: {e}")
        
        # 在自己的聊天窗口显示
        self.append_message(f"[广播 - 我] {content}")
        
        # 清空输入框
        self.message_input.delete(0, tk.END)
    
    def send_file(self):
        """发送文件"""
        # 获取选中的成员
        selected_index = self.member_list.curselection()
        if not selected_index:
            self.append_message("请先选择一个接收文件的对象")
            return
            
        selected_item = self.member_list.get(selected_index[0])
        
        # 如果选择的是自己，不发送
        if "(我)" in selected_item:
            self.append_message("不能向自己发送文件")
            return
            
        # 提取对方IP
        try:
            parts = selected_item.split(" - ")
            if len(parts) < 2:
                self.append_message("无法解析选中成员的信息")
                return
            
            target_ip = parts[1]
            target_name = parts[0]
            
            # 选择要发送的文件
            file_path = filedialog.askopenfilename(title="选择要发送的文件")
            if not file_path:
                return
                
            # 获取文件名和文件大小
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            self.append_message(f"准备发送文件: {file_name} (大小: {file_size} 字节)")
            
            # 创建TCP连接
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            
            try:
                client_socket.connect((target_ip, FILE_PORT))
                
                # 发送文件信息
                file_info = f"{file_name}|{file_size}|{self.username}"
                client_socket.send(file_info.encode('utf-8'))
                
                # 等待接收方确认
                ack = client_socket.recv(BUFFER_SIZE).decode('utf-8')
                if ack != "READY":
                    self.append_message("接收方拒绝接收文件")
                    return
                    
                # 发送文件内容
                sent_bytes = 0
                with open(file_path, 'rb') as f:
                    while True:
                        data = f.read(FILE_CHUNK_SIZE)
                        if not data:
                            break
                        
                        client_socket.send(data)
                        sent_bytes += len(data)
                        
                        # 更新进度条
                        progress = (sent_bytes / file_size) * 100
                        self.progress_var.set(progress)
                        self.progress_label.config(text=f"正在发送: {sent_bytes}/{file_size} 字节 ({progress:.1f}%)")
                        self.root.update_idletasks()  # 更新界面
                
                self.append_message(f"文件发送完成: {file_name}")
                self.progress_var.set(0)
                self.progress_label.config(text="准备就绪")
                
            except socket.timeout:
                self.append_message("连接超时，文件发送失败")
            except ConnectionRefusedError:
                self.append_message("连接被拒绝，接收方可能不在线")
            except Exception as e:
                self.append_message(f"文件发送失败: {e}")
                log_message("ERROR", f"发送文件错误: {e}")
            finally:
                client_socket.close()
                
        except Exception as e:
            self.append_message(f"发送文件失败: {e}")
            log_message("ERROR", f"发送文件错误: {e}")
    
    def receive_file(self):
        """接收文件"""
        while self.is_running:
            conn = None
            try:
                conn, addr = self.file_socket.accept()
                sender_ip = addr[0]
                
                # 接收文件信息
                file_info = conn.recv(BUFFER_SIZE).decode('utf-8')
                if not file_info:
                    continue
                    
                # 解析文件信息
                parts = file_info.split('|')
                if len(parts) < 3:
                    conn.close()
                    continue
                    
                file_name, file_size, sender_name = parts[0], int(parts[1]), parts[2]
                
                # 显示接收文件提示
                self.append_message(f"收到来自 {sender_name} ({sender_ip}) 的文件: {file_name} (大小: {file_size} 字节)")
                
                # 确认接收
                conn.send("READY".encode('utf-8'))
                
                # 选择保存文件的位置
                save_path = filedialog.asksaveasfilename(
                    title="保存文件",
                    defaultextension=os.path.splitext(file_name)[1],
                    initialfile=file_name
                )
                
                if not save_path:
                    conn.send("CANCEL".encode('utf-8'))
                    conn.close()
                    self.append_message("文件接收已取消")
                    continue
                
                # 接收文件内容
                received_bytes = 0
                with open(save_path, 'wb') as f:
                    while received_bytes < file_size:
                        data = conn.recv(FILE_CHUNK_SIZE)
                        if not data:
                            break
                            
                        f.write(data)
                        received_bytes += len(data)
                        
                        # 更新进度条
                        progress = (received_bytes / file_size) * 100
                        self.progress_var.set(progress)
                        self.progress_label.config(text=f"正在接收: {received_bytes}/{file_size} 字节 ({progress:.1f}%)")
                        self.root.update_idletasks()  # 更新界面
                
                if received_bytes == file_size:
                    self.append_message(f"文件接收完成: {save_path}")
                else:
                    self.append_message(f"文件接收不完整，可能发生错误")
                    if os.path.exists(save_path):
                        os.remove(save_path)
                
                self.progress_var.set(0)
                self.progress_label.config(text="准备就绪")
                
            except Exception as e:
                if self.is_running:
                    self.append_message(f"接收文件错误: {e}")
                    log_message("ERROR", f"接收文件错误: {e}")
                    self.progress_var.set(0)
                    self.progress_label.config(text="准备就绪")
            finally:
                if conn is not None:
                    conn.close()
    
    def cleanup_members(self):
        """定期清理离线成员"""
        while self.is_running:
            time.sleep(30)  # 每30秒清理一次
            if not self.members:
                continue
                
            log_message("DEBUG", f"开始清理离线成员，当前成员数: {len(self.members)}")
            
            # 尝试向所有成员发送心跳包并检测在线状态
            offline_members = []
            for member_ip in list(self.members.keys()):  # 使用list创建副本，避免迭代时修改
                member_name = self.members[member_ip]
                is_online = False
                
                # 方法1：尝试UDP心跳包，重试2次
                for i in range(2):
                    try:
                        log_message("DEBUG", f"向 {member_name} ({member_ip}) 发送UDP心跳包 (尝试 {i+1}/2)")
                        heartbeat = f"HEARTBEAT|{self.ip}|{self.username}"
                        self.message_socket.sendto(heartbeat.encode('utf-8'), (member_ip, MESSAGE_PORT))
                        # UDP发送成功，但不能确定对方是否收到
                        is_online = True  # 暂时标记为在线
                        break
                    except Exception as e:
                        log_message("DEBUG", f"向 {member_name} ({member_ip}) 发送UDP心跳包失败 (尝试 {i+1}/2): {e}")
                        if i < 1:  # 不是最后一次尝试，等待100ms后重试
                            time.sleep(0.1)
                
                # 方法2：尝试TCP连接，更可靠的在线检测
                if is_online:  # 只有UDP成功时才尝试TCP，减少网络负担
                    tcp_success = False
                    for i in range(2):
                        try:
                            log_message("DEBUG", f"向 {member_name} ({member_ip}) 尝试TCP连接 (尝试 {i+1}/2)")
                            # 尝试连接到对方的文件传输端口，5秒超时
                            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            test_socket.settimeout(5)
                            test_socket.connect((member_ip, FILE_PORT))
                            test_socket.close()
                            tcp_success = True
                            break
                        except Exception as e:
                            log_message("DEBUG", f"向 {member_name} ({member_ip}) 尝试TCP连接失败 (尝试 {i+1}/2): {e}")
                            if i < 1:  # 不是最后一次尝试，等待100ms后重试
                                time.sleep(0.1)
                        finally:
                            try:
                                test_socket.close()
                            except:
                                pass
                    
                    # 如果TCP连接失败，标记为离线
                    if not tcp_success:
                        log_message("DEBUG", f"{member_name} ({member_ip}) TCP连接失败，标记为离线")
                        is_online = False
                
                # 如果最终检测为离线，添加到离线列表
                if not is_online:
                    offline_members.append(member_ip)
                else:
                    log_message("DEBUG", f"{member_name} ({member_ip}) 在线")
                    
            # 移除离线成员
            if offline_members:
                log_message("DEBUG", f"检测到 {len(offline_members)} 个离线成员: {offline_members}")
                for member_ip in offline_members:
                    member_name = self.members.pop(member_ip, "未知")
                    self.append_message(f"{member_name} ({member_ip}) 已离线")
                    log_message("DEBUG", f"移除离线成员: {member_name} ({member_ip})")
                # 批量更新成员列表，减少GUI更新次数
                self.update_member_list()
            else:
                log_message("DEBUG", f"所有成员都在线，无需清理")
                
    def on_closing(self):
        """程序关闭时的处理"""
        self.is_running = False
        
        # 发送退出通知
        exit_message = f"EXIT|{self.ip}|{self.username}"
        for member_ip in self.members:
            try:
                self.message_socket.sendto(exit_message.encode('utf-8'), (member_ip, MESSAGE_PORT))
            except:
                pass
        
        # 关闭所有套接字
        try:
            self.broadcast_socket.close()
            self.message_socket.close()
            self.file_socket.close()
        except:
            pass
        
        # 关闭GUI
        self.root.destroy()
    
    def append_message(self, message):
        """在聊天窗口添加消息"""
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def run(self):
        """运行客户端"""
        # 设置窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        try:
            self.send_broadcast()
            self.root.mainloop()
        finally:
            if self.is_running:
                self.on_closing()

if __name__ == "__main__":
    client = ChatClient()
    client.run()