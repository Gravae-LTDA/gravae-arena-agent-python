#!/usr/bin/env python3
"""
Gravae Arena Agent v${AGENT_VERSION}
Runs on Raspberry Pi to provide system monitoring, Shinobi setup,
Cloudflare tunnel control, terminal access, and self-update capabilities.
"""

import os
import sys
import json
import socket
import subprocess
import time
import re
import pty
import select
import signal
import fcntl
import struct
import termios
import uuid
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request

PORT = 8888
VERSION = "${AGENT_VERSION}"
CORS_ORIGIN = "*"
CONFIG_PATH = "/etc/gravae/device.json"
BUTTON_DAEMON_PATH = "/home/Gravae/Documents/Gravae/button-daemon.js"
AGENT_PATH = "/opt/gravae-agent"
GITHUB_REPO = "Gravae-LTDA/gravae-arena-agent-python"
GITHUB_RAW_URL = "https://raw.githubusercontent.com/Gravae-LTDA/gravae-arena-agent-python/main"

# Terminal session storage
terminal_sessions = {}
SESSION_TIMEOUT = 30 * 60  # 30 minutes

def load_config():
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_config():
    """Save CONFIG to file"""
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(CONFIG, f, indent=2)
        return True
    except Exception as e:
        print(f"[Config] Failed to save config: {e}")
        return False

CONFIG = load_config()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_gateway():
    try:
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        parts = result.stdout.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except:
        pass
    return None

def get_hostname():
    return socket.gethostname()

def get_device_serial():
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if line.startswith("Serial"):
                    return line.split(":")[1].strip()
    except:
        pass
    return None

def get_device_model():
    try:
        with open("/proc/device-tree/model", "r") as f:
            return f.read().strip().replace('\\x00', '')
    except:
        pass
    return "Unknown"

def get_os_info():
    info = {"name": "Unknown", "version": "Unknown", "version_codename": "unknown"}
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    value = value.strip('"')
                    if key == 'NAME': info['name'] = value
                    elif key == 'VERSION': info['version'] = value
                    elif key == 'VERSION_CODENAME': info['version_codename'] = value
    except:
        pass
    return info

def get_gpio_info():
    model = get_device_model().lower()
    os_info = get_os_info()
    codename = os_info.get('version_codename', '').lower()

    is_pi5 = 'pi 5' in model
    is_bookworm = codename == 'bookworm'
    is_trixie = codename == 'trixie'

    if is_pi5:
        recommended = "onoff"
        pigpio_works = False
    elif is_trixie or is_bookworm:
        recommended = "pigpio"
        pigpio_works = True
    else:
        recommended = "pigpio"
        pigpio_works = True

    return {
        "model": get_device_model(),
        "is_pi5": is_pi5,
        "os_codename": codename,
        "recommended_lib": recommended,
        "pigpio_compatible": pigpio_works
    }

def get_memory_info():
    try:
        with open("/proc/meminfo", "r") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
            total = meminfo.get("MemTotal", 0)
            free = meminfo.get("MemFree", 0) + meminfo.get("Buffers", 0) + meminfo.get("Cached", 0)
            used = total - free
            return {"total_mb": round(total/1024), "used_mb": round(used/1024), "free_mb": round(free/1024), "percent": round((used/total)*100, 1) if total else 0}
    except Exception as e:
        return {"error": str(e)}

def get_cpu_info():
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
        vals1 = [int(x) for x in line.split()[1:5]]
        time.sleep(0.1)
        with open("/proc/stat", "r") as f:
            line = f.readline()
        vals2 = [int(x) for x in line.split()[1:5]]
        diff = [vals2[i] - vals1[i] for i in range(4)]
        total = sum(diff)
        idle = diff[3]
        percent = round(((total - idle) / total) * 100, 1) if total else 0

        temp = None
        try:
            with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
                temp = round(int(f.read().strip()) / 1000, 1)
        except:
            pass
        return {"percent": percent, "cores": os.cpu_count() or 1, "temperature": temp}
    except Exception as e:
        return {"error": str(e)}

def get_disk_info():
    try:
        st = os.statvfs("/")
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        used = total - free
        return {"total_gb": round(total/(1024**3), 1), "used_gb": round(used/(1024**3), 1), "free_gb": round(free/(1024**3), 1), "percent": round((used/total)*100, 1) if total else 0}
    except Exception as e:
        return {"error": str(e)}

def get_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            secs = float(f.read().split()[0])
        d, h, m = int(secs//86400), int((secs%86400)//3600), int((secs%3600)//60)
        return {"seconds": int(secs), "formatted": f"{d}d {h}h {m}m"}
    except Exception as e:
        return {"error": str(e)}

def get_button_daemon_status():
    try:
        result = subprocess.run(['systemctl', 'is-active', 'gravae-buttons'], capture_output=True, text=True)
        return {"running": result.stdout.strip() == 'active', "service": "gravae-buttons"}
    except:
        return {"running": False}

def get_full_system_info():
    return {
        "timestamp": datetime.now().isoformat(),
        "deviceId": CONFIG.get("deviceId") or get_device_serial(),
        "deviceSerial": get_device_serial(),
        "deviceModel": get_device_model(),
        "localIp": get_local_ip(),
        "gateway": get_gateway(),
        "hostname": get_hostname(),
        "os": get_os_info(),
        "gpio": get_gpio_info(),
        "uptime": get_uptime(),
        "memory": get_memory_info(),
        "cpu": get_cpu_info(),
        "disk": get_disk_info(),
        "buttonDaemon": get_button_daemon_status(),
        "version": VERSION
    }

# === Network Management ===
def get_network_manager_type():
    """Detect which network manager is being used.
    - Bullseye: dhcpcd
    - Bookworm/Trixie: NetworkManager
    """
    os_info = get_os_info()
    codename = os_info.get('version_codename', '').lower()

    # Check if NetworkManager is active (Bookworm/Trixie default)
    try:
        result = subprocess.run(['systemctl', 'is-active', 'NetworkManager'],
                                capture_output=True, text=True, timeout=5)
        if result.stdout.strip() == 'active':
            return {'type': 'networkmanager', 'codename': codename, 'service': 'NetworkManager'}
    except:
        pass

    # Check if dhcpcd is active (Bullseye default)
    try:
        result = subprocess.run(['systemctl', 'is-active', 'dhcpcd'],
                                capture_output=True, text=True, timeout=5)
        if result.stdout.strip() == 'active':
            return {'type': 'dhcpcd', 'codename': codename, 'service': 'dhcpcd'}
    except:
        pass

    # Fallback: guess based on codename
    if codename in ['bookworm', 'trixie']:
        return {'type': 'networkmanager', 'codename': codename, 'service': 'NetworkManager'}
    return {'type': 'dhcpcd', 'codename': codename, 'service': 'dhcpcd'}

def get_network_interfaces():
    """Get all network interfaces with their configuration."""
    interfaces = []

    try:
        # Get all interfaces
        result = subprocess.run(['ip', '-j', 'addr'], capture_output=True, text=True, timeout=10)
        ip_data = json.loads(result.stdout) if result.stdout else []

        for iface in ip_data:
            ifname = iface.get('ifname', '')
            if ifname == 'lo':  # Skip loopback
                continue

            info = {
                'name': ifname,
                'mac': iface.get('address', ''),
                'state': iface.get('operstate', 'unknown'),
                'addresses': [],
                'is_dhcp': False
            }

            # Get IPv4 addresses
            for addr_info in iface.get('addr_info', []):
                if addr_info.get('family') == 'inet':
                    info['addresses'].append({
                        'ip': addr_info.get('local', ''),
                        'prefix': addr_info.get('prefixlen', 24),
                        'label': addr_info.get('label', ifname)
                    })

            interfaces.append(info)

        # Get default gateway
        gateway_result = subprocess.run(['ip', '-j', 'route', 'show', 'default'],
                                         capture_output=True, text=True, timeout=5)
        gateway_data = json.loads(gateway_result.stdout) if gateway_result.stdout else []

        default_gateway = None
        default_dev = None
        if gateway_data:
            default_gateway = gateway_data[0].get('gateway')
            default_dev = gateway_data[0].get('dev')

        # Get DNS servers
        dns_servers = []
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
        except:
            pass

        # Check DHCP status for interfaces
        net_manager = get_network_manager_type()

        if net_manager['type'] == 'networkmanager':
            # Use nmcli to check DHCP status
            for iface in interfaces:
                try:
                    result = subprocess.run(['nmcli', '-t', '-f', 'IP4.METHOD', 'device', 'show', iface['name']],
                                           capture_output=True, text=True, timeout=5)
                    if 'auto' in result.stdout.lower():
                        iface['is_dhcp'] = True
                except:
                    pass
        else:
            # Check dhcpcd.conf for static config
            try:
                with open('/etc/dhcpcd.conf', 'r') as f:
                    content = f.read()
                    for iface in interfaces:
                        if f'interface {iface["name"]}' in content and 'static ip_address' in content:
                            iface['is_dhcp'] = False
                        else:
                            iface['is_dhcp'] = True
            except:
                pass

        return {
            'interfaces': interfaces,
            'default_gateway': default_gateway,
            'default_device': default_dev,
            'dns_servers': dns_servers,
            'network_manager': net_manager
        }
    except Exception as e:
        return {'error': str(e), 'interfaces': [], 'network_manager': get_network_manager_type()}

def configure_network_static(interface, ip, prefix, gateway, dns=None):
    """Configure static IP on an interface.
    Works with both NetworkManager (Bookworm+) and dhcpcd (Bullseye).
    """
    net_manager = get_network_manager_type()

    try:
        if net_manager['type'] == 'networkmanager':
            # Use nmcli for NetworkManager
            commands = [
                ['sudo', 'nmcli', 'connection', 'modify', interface, 'ipv4.method', 'manual'],
                ['sudo', 'nmcli', 'connection', 'modify', interface, 'ipv4.addresses', f'{ip}/{prefix}'],
                ['sudo', 'nmcli', 'connection', 'modify', interface, 'ipv4.gateway', gateway],
            ]

            if dns:
                dns_str = ','.join(dns) if isinstance(dns, list) else dns
                commands.append(['sudo', 'nmcli', 'connection', 'modify', interface, 'ipv4.dns', dns_str])

            for cmd in commands:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    return {'success': False, 'error': f'nmcli error: {result.stderr}'}

            # Apply changes
            subprocess.run(['sudo', 'nmcli', 'connection', 'down', interface],
                          capture_output=True, text=True, timeout=10)
            subprocess.run(['sudo', 'nmcli', 'connection', 'up', interface],
                          capture_output=True, text=True, timeout=10)

            return {'success': True, 'method': 'networkmanager', 'message': 'Static IP configured'}

        else:
            # Use dhcpcd.conf for older systems (Bullseye)
            config_path = '/etc/dhcpcd.conf'

            # Read current config
            try:
                with open(config_path, 'r') as f:
                    lines = f.readlines()
            except:
                lines = []

            # Remove existing config for this interface
            new_lines = []
            skip_until_next_interface = False
            for line in lines:
                if line.strip().startswith('interface '):
                    skip_until_next_interface = interface in line
                    if not skip_until_next_interface:
                        new_lines.append(line)
                elif skip_until_next_interface and line.strip().startswith('interface '):
                    skip_until_next_interface = False
                    new_lines.append(line)
                elif not skip_until_next_interface:
                    new_lines.append(line)

            # Add new static config
            new_lines.append(f'\\ninterface {interface}\\n')
            new_lines.append(f'static ip_address={ip}/{prefix}\\n')
            new_lines.append(f'static routers={gateway}\\n')
            if dns:
                dns_str = ' '.join(dns) if isinstance(dns, list) else dns
                new_lines.append(f'static domain_name_servers={dns_str}\\n')

            # Write config
            with open('/tmp/dhcpcd.conf.new', 'w') as f:
                f.writelines(new_lines)

            subprocess.run(['sudo', 'mv', '/tmp/dhcpcd.conf.new', config_path], check=True, timeout=5)
            subprocess.run(['sudo', 'systemctl', 'restart', 'dhcpcd'], capture_output=True, timeout=30)

            return {'success': True, 'method': 'dhcpcd', 'message': 'Static IP configured, dhcpcd restarted'}

    except Exception as e:
        return {'success': False, 'error': str(e)}

def configure_network_dhcp(interface):
    """Configure interface to use DHCP."""
    net_manager = get_network_manager_type()

    try:
        if net_manager['type'] == 'networkmanager':
            # Use nmcli for NetworkManager
            commands = [
                ['sudo', 'nmcli', 'connection', 'modify', interface, 'ipv4.method', 'auto'],
                ['sudo', 'nmcli', 'connection', 'modify', interface, 'ipv4.addresses', ''],
                ['sudo', 'nmcli', 'connection', 'modify', interface, 'ipv4.gateway', ''],
                ['sudo', 'nmcli', 'connection', 'modify', interface, 'ipv4.dns', ''],
            ]

            for cmd in commands:
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            # Apply changes
            subprocess.run(['sudo', 'nmcli', 'connection', 'down', interface],
                          capture_output=True, text=True, timeout=10)
            subprocess.run(['sudo', 'nmcli', 'connection', 'up', interface],
                          capture_output=True, text=True, timeout=10)

            return {'success': True, 'method': 'networkmanager', 'message': 'DHCP enabled'}

        else:
            # Remove static config from dhcpcd.conf
            config_path = '/etc/dhcpcd.conf'

            try:
                with open(config_path, 'r') as f:
                    lines = f.readlines()
            except:
                return {'success': True, 'method': 'dhcpcd', 'message': 'No config to remove'}

            # Remove config for this interface
            new_lines = []
            skip_until_next_interface = False
            for line in lines:
                if line.strip().startswith('interface '):
                    skip_until_next_interface = interface in line
                    if not skip_until_next_interface:
                        new_lines.append(line)
                elif skip_until_next_interface and line.strip().startswith('interface '):
                    skip_until_next_interface = False
                    new_lines.append(line)
                elif not skip_until_next_interface:
                    new_lines.append(line)

            with open('/tmp/dhcpcd.conf.new', 'w') as f:
                f.writelines(new_lines)

            subprocess.run(['sudo', 'mv', '/tmp/dhcpcd.conf.new', config_path], check=True, timeout=5)
            subprocess.run(['sudo', 'systemctl', 'restart', 'dhcpcd'], capture_output=True, timeout=30)

            return {'success': True, 'method': 'dhcpcd', 'message': 'DHCP enabled, dhcpcd restarted'}

    except Exception as e:
        return {'success': False, 'error': str(e)}

def add_network_alias(interface, ip, prefix, label=None):
    """Add an IP alias to an interface (like eth0:1).
    This adds a secondary IP address to access another subnet.
    Example: sudo ip addr add 192.168.0.1/24 dev eth0 label eth0:1
    """
    try:
        # Determine label
        if not label:
            # Find next available label (eth0:1, eth0:2, etc.)
            result = subprocess.run(['ip', '-j', 'addr', 'show', interface],
                                   capture_output=True, text=True, timeout=5)
            addr_data = json.loads(result.stdout) if result.stdout else []

            existing_labels = []
            for iface in addr_data:
                for addr in iface.get('addr_info', []):
                    if addr.get('label'):
                        existing_labels.append(addr['label'])

            # Find next available number
            num = 1
            while f'{interface}:{num}' in existing_labels:
                num += 1
            label = f'{interface}:{num}'

        # Add the IP alias
        cmd = ['sudo', 'ip', 'addr', 'add', f'{ip}/{prefix}', 'dev', interface, 'label', label]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            if 'RTNETLINK answers: File exists' in result.stderr:
                return {'success': False, 'error': 'This IP address is already configured'}
            return {'success': False, 'error': result.stderr}

        # Make it persistent based on network manager type
        net_manager = get_network_manager_type()
        persistent_note = ""

        if net_manager['type'] == 'networkmanager':
            # For NetworkManager, we could add a secondary IP, but manual ip addr is simpler
            persistent_note = "Note: This alias is temporary. To make it permanent, add it via nmcli or /etc/network/interfaces.d/"
        else:
            # For dhcpcd, add to config
            config_path = '/etc/dhcpcd.conf'
            try:
                with open(config_path, 'a') as f:
                    f.write(f'\\n# IP alias for {label}\\n')
                    f.write(f'interface {interface}\\n')
                    f.write(f'static ip_address={ip}/{prefix}\\n')
                persistent_note = "Alias added to dhcpcd.conf for persistence"
            except:
                persistent_note = "Note: Could not make alias persistent in dhcpcd.conf"

        return {
            'success': True,
            'label': label,
            'ip': ip,
            'prefix': prefix,
            'message': f'IP alias {label} added with address {ip}/{prefix}',
            'persistent_note': persistent_note
        }

    except Exception as e:
        return {'success': False, 'error': str(e)}

def remove_network_alias(interface, ip, prefix):
    """Remove an IP alias from an interface."""
    try:
        cmd = ['sudo', 'ip', 'addr', 'del', f'{ip}/{prefix}', 'dev', interface]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            return {'success': False, 'error': result.stderr}

        return {'success': True, 'message': f'IP alias {ip}/{prefix} removed from {interface}'}

    except Exception as e:
        return {'success': False, 'error': str(e)}

# === Terminal Management ===
class TerminalSession:
    def __init__(self, session_id):
        self.session_id = session_id
        self.master_fd = None
        self.slave_fd = None
        self.pid = None
        self.output_buffer = []
        self.created_at = time.time()
        self.last_activity = time.time()
        self.lock = threading.Lock()
        self.running = False

    def start(self):
        self.pid, self.master_fd = pty.fork()
        if self.pid == 0:
            os.environ['TERM'] = 'xterm-256color'
            os.environ['HOME'] = os.path.expanduser('~')
            shell = os.environ.get('SHELL', '/bin/bash')
            os.execvp(shell, [shell])
        else:
            self.running = True
            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self.reader_thread.start()

    def _read_output(self):
        while self.running:
            try:
                if self.pid:
                    try:
                        pid, status = os.waitpid(self.pid, os.WNOHANG)
                        if pid != 0:
                            print(f"[Terminal] Shell exited with status {status}")
                            self.running = False
                            break
                    except ChildProcessError:
                        self.running = False
                        break

                r, _, _ = select.select([self.master_fd], [], [], 0.1)
                if r:
                    data = os.read(self.master_fd, 4096)
                    if data:
                        with self.lock:
                            self.output_buffer.append(data.decode('utf-8', errors='replace'))
                            self.last_activity = time.time()
                            if len(self.output_buffer) > 100:
                                self.output_buffer = self.output_buffer[-50:]
                    else:
                        print("[Terminal] EOF, shell closed")
                        self.running = False
                        break
            except OSError as e:
                print(f"[Terminal] OSError: {e}")
                self.running = False
                break
            except Exception as e:
                print(f"[Terminal] Error: {e}")
                self.running = False
                break

    def write(self, data):
        if self.master_fd and self.running:
            try:
                os.write(self.master_fd, data.encode('utf-8'))
                self.last_activity = time.time()
                return True
            except:
                pass
        return False

    def resize(self, cols, rows):
        if self.master_fd and self.running:
            try:
                winsize = struct.pack('HHHH', rows, cols, 0, 0)
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
                self.last_activity = time.time()
                return True
            except:
                pass
        return False

    def get_output(self):
        with self.lock:
            output = ''.join(self.output_buffer)
            self.output_buffer = []
            self.last_activity = time.time()
            return output

    def close(self):
        self.running = False
        if self.master_fd:
            try:
                os.close(self.master_fd)
            except:
                pass
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except:
                pass

def create_terminal_session():
    session_id = f"term_{uuid.uuid4().hex[:8]}"
    session = TerminalSession(session_id)
    session.start()
    terminal_sessions[session_id] = session
    return session_id

def get_terminal_session(session_id):
    session = terminal_sessions.get(session_id)
    if session and time.time() - session.last_activity > SESSION_TIMEOUT:
        session.close()
        del terminal_sessions[session_id]
        return None
    return session

def close_terminal_session(session_id):
    session = terminal_sessions.get(session_id)
    if session:
        session.close()
        del terminal_sessions[session_id]
        return True
    return False

def cleanup_old_sessions():
    now = time.time()
    to_delete = []
    for sid, session in terminal_sessions.items():
        if now - session.last_activity > SESSION_TIMEOUT:
            to_delete.append(sid)
    for sid in to_delete:
        close_terminal_session(sid)

# === Update Management ===
update_status = {"status": "idle", "progress": 0, "message": "", "error": None}

def get_current_version():
    return VERSION

def check_for_updates():
    current = VERSION
    return {"currentVersion": current, "latestVersion": current, "updateAvailable": False}

def perform_update():
    """Perform update - tries git pull first, falls back to direct download from GitHub"""
    global update_status
    try:
        update_status = {"status": "downloading", "progress": 10, "message": "Verificando repositorio...", "error": None}
        if os.path.exists(os.path.join(AGENT_PATH, '.git')):
            update_status = {"status": "downloading", "progress": 30, "message": "Git pull...", "error": None}
            subprocess.run(['git', 'fetch', 'origin'], cwd=AGENT_PATH, capture_output=True)
            subprocess.run(['git', 'pull', 'origin', 'main'], cwd=AGENT_PATH, capture_output=True)
            return _restart_services()
        else:
            return _perform_update_direct()
    except Exception as e:
        update_status = {"status": "error", "progress": 0, "message": "Erro", "error": str(e)}

def _perform_update_direct():
    """Download files directly from GitHub raw"""
    global update_status
    try:
        import tempfile

        files_to_update = [
            ("gravae_agent.py", f"{GITHUB_RAW_URL}/gravae_agent.py"),
            ("phoenix_daemon.py", f"{GITHUB_RAW_URL}/phoenix_daemon.py"),
        ]

        update_status = {"status": "downloading", "progress": 20, "message": "Baixando do GitHub...", "error": None}

        for i, (filename, url) in enumerate(files_to_update):
            progress = 20 + (i + 1) * 25
            update_status = {"status": "downloading", "progress": progress, "message": f"Baixando {filename}...", "error": None}

            try:
                target_path = os.path.join(AGENT_PATH, filename)

                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Gravae-Agent-Updater')
                response = urllib.request.urlopen(req, timeout=30)
                content = response.read()

                if not content.startswith(b'#!/usr/bin/env python3') and not content.startswith(b'#'):
                    raise Exception(f"Invalid content for {filename}")

                with tempfile.NamedTemporaryFile(mode='wb', suffix=f'_{filename}', delete=False) as f:
                    temp_path = f.name
                    f.write(content)

                subprocess.run(['sudo', 'cp', temp_path, target_path], check=True)
                subprocess.run(['sudo', 'chmod', '+x', target_path], check=True)

                try:
                    os.unlink(temp_path)
                except:
                    pass

                print(f"[Update] Downloaded and installed {filename}")

            except Exception as e:
                update_status = {"status": "error", "progress": 0, "message": f"Falha ao baixar {filename}", "error": str(e)}
                return

        return _restart_services()

    except Exception as e:
        update_status = {"status": "error", "progress": 0, "message": "Erro no download", "error": str(e)}

def _restart_services():
    """Restart agent and phoenix services, creating systemd services if needed"""
    global update_status

    update_status = {"status": "installing", "progress": 60, "message": "Configurando Agent service...", "error": None}
    _ensure_agent_service()
    subprocess.run(['sudo', 'systemctl', 'daemon-reload'], capture_output=True)
    subprocess.run(['sudo', 'systemctl', 'enable', 'gravae-agent'], capture_output=True)
    subprocess.run(['sudo', 'systemctl', 'restart', 'gravae-agent'], capture_output=True)

    update_status = {"status": "installing", "progress": 80, "message": "Configurando Phoenix service...", "error": None}
    _ensure_phoenix_service()
    subprocess.run(['sudo', 'systemctl', 'daemon-reload'], capture_output=True)
    subprocess.run(['sudo', 'systemctl', 'enable', 'gravae-phoenix'], capture_output=True)
    subprocess.run(['sudo', 'systemctl', 'restart', 'gravae-phoenix'], capture_output=True)

    update_status = {"status": "completed", "progress": 100, "message": "Concluido!", "error": None}

def _ensure_agent_service():
    """Create agent systemd service if it doesn't exist"""
    service_path = '/etc/systemd/system/gravae-agent.service'
    if os.path.exists(service_path):
        return

    service_content = """[Unit]
Description=Gravae Arena Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gravae-agent
ExecStart=/usr/bin/python3 /opt/gravae-agent/gravae_agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    try:
        with open('/tmp/gravae-agent.service', 'w') as f:
            f.write(service_content)
        subprocess.run(['sudo', 'mv', '/tmp/gravae-agent.service', service_path], check=True)
        print("[Update] Created gravae-agent.service")
    except Exception as e:
        print(f"[Update] Failed to create agent service: {e}")

def _ensure_phoenix_service():
    """Create phoenix systemd service if it doesn't exist"""
    service_path = '/etc/systemd/system/gravae-phoenix.service'
    if os.path.exists(service_path):
        return

    service_content = """[Unit]
Description=Gravae Phoenix Daemon
After=network.target gravae-agent.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gravae-agent
ExecStart=/usr/bin/python3 /opt/gravae-agent/phoenix_daemon.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
"""
    try:
        with open('/tmp/gravae-phoenix.service', 'w') as f:
            f.write(service_content)
        subprocess.run(['sudo', 'mv', '/tmp/gravae-phoenix.service', service_path], check=True)
        print("[Update] Created gravae-phoenix.service")
    except Exception as e:
        print(f"[Update] Failed to create phoenix service: {e}")

def restart_agent():
    try:
        subprocess.Popen(['systemctl', 'restart', 'gravae-agent'], start_new_session=True)
        return True
    except:
        return False

# === Shinobi Setup ===
def get_shinobi_super_key():
    for path in ['/home/Shinobi/super.json', '/opt/shinobi/super.json']:
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                if data:
                    if isinstance(data, list) and len(data) > 0:
                        tokens = data[0].get('tokens', [])
                        if tokens:
                            return tokens[0]
                    elif isinstance(data, dict):
                        return list(data.keys())[0]
        except Exception as e:
            print(f"Error reading super.json from {path}: {e}")
            continue
    return None

def get_shinobi_config():
    """Get full Shinobi config from conf.json"""
    for path in ['/home/Shinobi/conf.json', '/opt/shinobi/conf.json']:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            continue
    return None

def get_shinobi_db_config():
    """Get Shinobi database config from conf.json"""
    conf = get_shinobi_config()
    if conf:
        return conf.get('db', {})
    return None

def hash_shinobi_password(password):
    """Hash password using Shinobi's configured algorithm (md5, sha256, or sha512)"""
    import hashlib

    conf = get_shinobi_config()
    if not conf:
        return hashlib.md5(password.encode()).hexdigest()

    password_type = conf.get('passwordType', 'md5').lower()
    password_salt = conf.get('passwordSalt', '')

    print(f"[Shinobi] Using password hash type: {password_type}")

    if password_type == 'sha512':
        salted = password + password_salt
        return hashlib.sha512(salted.encode()).hexdigest()
    elif password_type == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        return hashlib.md5(password.encode()).hexdigest()

def create_api_key_in_db(group_key, user_id):
    """Create API key directly in Shinobi database"""
    import string
    import random

    db_config = get_shinobi_db_config()
    if not db_config:
        return None

    api_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(30))

    try:
        details = json.dumps({
            "auth_socket": "1",
            "api_key_create": "1",
            "user_change": "1",
            "edit_permissions": "1",
            "get_monitors": "1",
            "edit_monitors": "1",
            "control_monitors": "1",
            "monitor_create": "1",
            "monitor_edit": "1",
            "monitor_delete": "1",
            "get_logs": "1",
            "log_view": "1",
            "watch_stream": "1",
            "watch_snapshot": "1",
            "watch_videos": "1",
            "delete_videos": "1",
            "video_delete": "1",
            "view_events": "1",
            "edit_events": "1",
            "delete_events": "1",
            "event_delete": "1"
        })

        sql = f"INSERT INTO API (ke, uid, ip, code, details) VALUES ('{group_key}', '{user_id}', '0.0.0.0', '{api_key}', '{details}') ON DUPLICATE KEY UPDATE code='{api_key}', details='{details}';"

        result = subprocess.run([
            'mysql',
            '-u', db_config.get('user', 'majesticflame'),
            f"-p{db_config.get('password', '')}",
            '-h', db_config.get('host', 'localhost'),
            db_config.get('database', 'ccio'),
            '-e', sql
        ], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            return api_key
    except Exception as e:
        print(f"DB API key creation failed: {e}")

    return None

def create_shinobi_user_in_db(group_key, user_id, email, password):
    """Create Shinobi user directly in database"""
    db_config = get_shinobi_db_config()
    if not db_config:
        return {"success": False, "error": "Could not read Shinobi database config"}

    pass_hash = hash_shinobi_password(password)

    details = json.dumps({
        "factorAuth": "0",
        "size": "10000",
        "days": "5",
        "event_days": "10",
        "log_days": "10",
        "max_camera": "20",
        "permissions": "all",
        "use_admin": "1"
    })

    try:
        check_sql = f"SELECT ke, uid FROM Users WHERE mail = '{email}';"
        check_result = subprocess.run([
            'mysql', '-N', '-B',
            '-u', db_config.get('user', 'majesticflame'),
            f"-p{db_config.get('password', '')}",
            '-h', db_config.get('host', 'localhost'),
            db_config.get('database', 'ccio'),
            '-e', check_sql
        ], capture_output=True, text=True, timeout=10)

        if check_result.stdout.strip():
            parts = check_result.stdout.strip().split('\\t')
            existing_ke = parts[0] if len(parts) > 0 else ''
            existing_uid = parts[1] if len(parts) > 1 else ''
            print(f"[Shinobi DB] User exists: ke={existing_ke}, uid={existing_uid}")

            if existing_ke != group_key:
                return {
                    "success": False,
                    "error": f"Email already exists with different group_key ({existing_ke})",
                    "existingGroupKey": existing_ke
                }
            return {"success": True, "existed": True, "uid": existing_uid, "ke": existing_ke}

        insert_sql = f"INSERT INTO Users (ke, uid, mail, pass, details) VALUES ('{group_key}', '{user_id}', '{email}', '{pass_hash}', '{details}');"
        insert_result = subprocess.run([
            'mysql',
            '-u', db_config.get('user', 'majesticflame'),
            f"-p{db_config.get('password', '')}",
            '-h', db_config.get('host', 'localhost'),
            db_config.get('database', 'ccio'),
            '-e', insert_sql
        ], capture_output=True, text=True, timeout=10)

        if insert_result.returncode == 0:
            print(f"[Shinobi DB] User created: ke={group_key}, uid={user_id}, email={email}")
            return {"success": True, "existed": False, "uid": user_id, "ke": group_key}
        else:
            print(f"[Shinobi DB] Insert failed: {insert_result.stderr}")
            return {"success": False, "error": f"Database insert failed: {insert_result.stderr[:200]}"}

    except Exception as e:
        print(f"[Shinobi DB] Exception: {e}")
        return {"success": False, "error": str(e)}

def setup_shinobi_account(group_key, email, password):
    import string
    import random

    print(f"[Shinobi Setup] Starting setup with group_key={group_key}, email={email}")

    if not group_key:
        return {"success": False, "error": "Group key is required"}
    if not email:
        return {"success": False, "error": "Email is required"}
    if not password:
        return {"success": False, "error": "Password is required"}

    user_id = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(6))

    print(f"[Shinobi Setup] Creating user in database...")
    db_result = create_shinobi_user_in_db(group_key, user_id, email, password)

    if not db_result.get('success'):
        return db_result

    actual_uid = db_result.get('uid', user_id)
    account_existed = db_result.get('existed', False)

    print(f"[Shinobi Setup] User {'exists' if account_existed else 'created'}: uid={actual_uid}")

    login_url = "http://localhost:8080/?json=true"
    login_data = json.dumps({"mail": email, "pass": password, "machineID": "gravae-agent"}).encode()

    verified_user_id = None
    verified_group_key = None
    session_token = None

    try:
        req = urllib.request.Request(login_url, data=login_data, headers={'Content-Type': 'application/json'})
        response = urllib.request.urlopen(req, timeout=30)
        result = json.loads(response.read().decode())
        print(f"[Shinobi Setup] Login response keys: {list(result.keys())}")

        user_data = result.get('$user', {})
        verified_user_id = user_data.get('uid', '')
        verified_group_key = user_data.get('ke', '')
        session_token = user_data.get('auth_token', '')

        print(f"[Shinobi Setup] Verified - uid: {verified_user_id}, ke: {verified_group_key}")

        if verified_group_key and verified_group_key != group_key:
            return {
                "success": False,
                "error": f"Account exists with different group_key ({verified_group_key}). Please use group_key '{verified_group_key}' or create account with different email.",
                "existingGroupKey": verified_group_key
            }

        if not verified_user_id:
            return {"success": False, "error": "Login succeeded but could not get user ID"}

    except Exception as e:
        if account_existed:
            return {"success": False, "error": f"Account exists but login failed - wrong password? Error: {str(e)}"}
        return {"success": False, "error": f"Login failed after account creation: {str(e)}"}

    api_key = create_api_key_in_db(group_key, verified_user_id)
    if api_key:
        status_msg = "verified (existing)" if account_existed else "created"
        return {
            "success": True,
            "groupKey": group_key,
            "apiKey": api_key,
            "userId": verified_user_id,
            "message": f"Account {status_msg}, API key generated"
        }

    if session_token:
        api_add_url = f"http://localhost:8080/{session_token}/api/{group_key}/add"
        api_data = json.dumps({
            "data": {
                "ip": "0.0.0.0",
                "details": {"auth_socket": "1", "get_monitors": "1", "control_monitors": "1", "get_logs": "1", "watch_stream": "1", "watch_snapshot": "1", "watch_videos": "1", "delete_videos": "1", "view_monitor": "1", "edit_monitor": "1", "view_events": "1", "delete_events": "1", "monitor_create": "1", "monitor_edit": "1", "monitor_delete": "1", "video_delete": "1", "event_delete": "1", "log_view": "1"}
            }
        }).encode()

        try:
            req = urllib.request.Request(api_add_url, data=api_data, headers={'Content-Type': 'application/json'})
            response = urllib.request.urlopen(req, timeout=30)
            result = json.loads(response.read().decode())
            api_key = result.get('api', {}).get('code', '') or result.get('key', '') or result.get('code', '')
            if api_key:
                return {"success": True, "groupKey": group_key, "apiKey": api_key, "userId": verified_user_id}
        except Exception as e:
            print(f"[Shinobi Setup] API key creation via endpoint failed: {e}")

        return {
            "success": True,
            "groupKey": group_key,
            "apiKey": session_token,
            "userId": verified_user_id,
            "warning": "Using session token (temporary, expires in 15min)"
        }

    return {"success": False, "error": "Could not create API key"}

def cleanup_shinobi(group_key, email, password):
    """Delete all monitors and API keys for a group, optionally delete user"""
    import urllib.error

    if not group_key or not email or not password:
        return {"success": False, "error": "groupKey, email and password required"}

    login_url = "http://localhost:8080/?json=true"
    login_data = json.dumps({"mail": email, "pass": password, "machineID": "gravae-agent"}).encode()

    try:
        req = urllib.request.Request(login_url, data=login_data, headers={'Content-Type': 'application/json'})
        response = urllib.request.urlopen(req, timeout=30)
        result = json.loads(response.read().decode())

        user_data = result.get('$user', {})
        session_token = user_data.get('auth_token', '')
        verified_group_key = user_data.get('ke', '')

        if not session_token:
            return {"success": False, "error": "Could not login to Shinobi"}

        if verified_group_key != group_key:
            return {"success": False, "error": f"Group key mismatch: expected {group_key}, got {verified_group_key}"}

    except Exception as e:
        return {"success": False, "error": f"Login failed: {str(e)}"}

    deleted_monitors = []
    errors = []

    try:
        monitors_url = f"http://localhost:8080/{session_token}/monitor/{group_key}"
        req = urllib.request.Request(monitors_url)
        response = urllib.request.urlopen(req, timeout=30)
        monitors = json.loads(response.read().decode())

        print(f"[Shinobi Cleanup] Found {len(monitors)} monitors to delete")

        for monitor in monitors:
            mid = monitor.get('mid', '')
            if mid:
                try:
                    delete_url = f"http://localhost:8080/{session_token}/configureMonitor/{group_key}/{mid}/delete"
                    req = urllib.request.Request(delete_url, method='POST')
                    urllib.request.urlopen(req, timeout=30)
                    deleted_monitors.append(mid)
                    print(f"[Shinobi Cleanup] Deleted monitor {mid}")
                except Exception as e:
                    errors.append(f"monitor {mid}: {str(e)}")
    except Exception as e:
        errors.append(f"list monitors: {str(e)}")

    db_config = get_shinobi_db_config()
    user_deleted = False
    if db_config:
        try:
            sql = f"DELETE FROM API WHERE ke = '{group_key}';"
            result = subprocess.run([
                'mysql',
                '-u', db_config.get('user', 'majesticflame'),
                f"-p{db_config.get('password', '')}",
                '-h', db_config.get('host', 'localhost'),
                db_config.get('database', 'ccio'),
                '-e', sql
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                print(f"[Shinobi Cleanup] Deleted API keys for group {group_key}")
            else:
                errors.append(f"delete API keys: {result.stderr}")
        except Exception as e:
            errors.append(f"delete API keys: {str(e)}")

        try:
            sql = f"DELETE FROM Users WHERE ke = '{group_key}' AND mail = '{email}';"
            result = subprocess.run([
                'mysql',
                '-u', db_config.get('user', 'majesticflame'),
                f"-p{db_config.get('password', '')}",
                '-h', db_config.get('host', 'localhost'),
                db_config.get('database', 'ccio'),
                '-e', sql
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                print(f"[Shinobi Cleanup] Deleted user {email} for group {group_key}")
                user_deleted = True
            else:
                errors.append(f"delete user: {result.stderr}")
        except Exception as e:
            errors.append(f"delete user: {str(e)}")

    return {
        "success": len(errors) == 0,
        "deletedMonitors": deleted_monitors,
        "userDeleted": user_deleted,
        "errors": errors if errors else None,
    }

# === Cloudflare Tunnel ===
def install_cloudflared():
    result = subprocess.run(['which', 'cloudflared'], capture_output=True)
    if result.returncode != 0:
        try:
            arch = subprocess.run(['dpkg', '--print-architecture'], capture_output=True, text=True).stdout.strip()
            # Select correct package for architecture
            if arch == 'arm64':
                url = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb'
            elif arch == 'armhf':
                url = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm.deb'
            else:
                url = 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb'
            subprocess.run(['curl', '-L', '--output', '/tmp/cloudflared.deb', url], check=True)
            subprocess.run(['sudo', 'dpkg', '-i', '/tmp/cloudflared.deb'], check=True)
        except Exception as e:
            return {"success": False, "error": str(e)}
    return {"success": True}

def setup_quick_tunnel():
    subprocess.run(['pkill', '-f', 'cloudflared.*tunnel'], capture_output=True)
    time.sleep(2)

    shinobi_url = agent_url = None

    try:
        with open('/tmp/cf_shinobi.log', 'w') as log:
            subprocess.Popen(['cloudflared', 'tunnel', '--url', 'http://localhost:8080', '--no-autoupdate'], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(15):
            time.sleep(1)
            try:
                with open('/tmp/cf_shinobi.log', 'r') as f:
                    match = re.search(r'https://[a-z0-9-]+\\.trycloudflare\\.com', f.read())
                    if match:
                        shinobi_url = match.group(0)
                        break
            except:
                pass
    except Exception as e:
        return {"success": False, "error": str(e)}

    try:
        with open('/tmp/cf_agent.log', 'w') as log:
            subprocess.Popen(['cloudflared', 'tunnel', '--url', 'http://localhost:8888', '--no-autoupdate'], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(15):
            time.sleep(1)
            try:
                with open('/tmp/cf_agent.log', 'r') as f:
                    match = re.search(r'https://[a-z0-9-]+\\.trycloudflare\\.com', f.read())
                    if match:
                        agent_url = match.group(0)
                        break
            except:
                pass
    except Exception as e:
        return {"success": False, "error": str(e)}

    return {"success": True, "shinobiUrl": shinobi_url or "", "agentUrl": agent_url or ""}

def run_tunnel_with_token(tunnel_token, tunnel_name='custom-tunnel'):
    """Run cloudflared with a token (ingress configured via Cloudflare API)"""
    install_result = install_cloudflared()
    if not install_result.get('success'):
        return install_result

    subprocess.run(['sudo', 'systemctl', 'stop', 'cloudflared'], capture_output=True)
    subprocess.run(['pkill', '-f', 'cloudflared'], capture_output=True)
    time.sleep(2)

    try:
        subprocess.run(['sudo', 'cloudflared', 'service', 'uninstall'], capture_output=True)
        time.sleep(1)

        result = subprocess.run(
            ['sudo', 'cloudflared', 'service', 'install', tunnel_token],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            log_path = f'/tmp/cf_{tunnel_name}.log'
            with open(log_path, 'w') as log:
                subprocess.Popen(
                    ['cloudflared', 'tunnel', 'run', '--token', tunnel_token],
                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True
                )
            time.sleep(5)
            pgrep = subprocess.run(['pgrep', '-f', 'cloudflared.*tunnel'], capture_output=True)
            if pgrep.returncode != 0:
                return {"success": False, "error": "Tunnel failed to start"}
            return {"success": True, "method": "manual", "log": log_path}
        else:
            time.sleep(3)
            status = subprocess.run(['systemctl', 'is-active', 'cloudflared'], capture_output=True, text=True)
            if status.stdout.strip() != 'active':
                return {"success": False, "error": "Tunnel service not active"}
            return {"success": True, "method": "systemd"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def setup_named_tunnel(tunnel_token, shinobi_hostname, agent_hostname):
    subprocess.run(['sudo', 'systemctl', 'stop', 'cloudflared'], capture_output=True)
    subprocess.run(['pkill', '-f', 'cloudflared'], capture_output=True)
    time.sleep(2)

    try:
        subprocess.run(['sudo', 'cloudflared', 'service', 'uninstall'], capture_output=True)
        time.sleep(1)

        result = subprocess.run(
            ['sudo', 'cloudflared', 'service', 'install', tunnel_token],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            with open('/tmp/cf_named.log', 'w') as log:
                subprocess.Popen(['cloudflared', 'tunnel', 'run', '--token', tunnel_token], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            time.sleep(5)
            pgrep = subprocess.run(['pgrep', '-f', 'cloudflared.*tunnel'], capture_output=True)
            if pgrep.returncode != 0:
                return {"success": False, "error": "Tunnel failed to start"}
        else:
            time.sleep(3)
            status = subprocess.run(['systemctl', 'is-active', 'cloudflared'], capture_output=True, text=True)
            if status.stdout.strip() != 'active':
                return {"success": False, "error": "Tunnel service not active"}

        return {"success": True, "shinobiUrl": f"https://{shinobi_hostname}", "agentUrl": f"https://{agent_hostname}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def setup_cloudflare_tunnel(tunnel_type='quick', tunnel_token=None, shinobi_hostname=None, agent_hostname=None):
    install_result = install_cloudflared()
    if not install_result.get('success'):
        return install_result

    if tunnel_type == 'named' and tunnel_token:
        return setup_named_tunnel(tunnel_token, shinobi_hostname, agent_hostname)
    return setup_quick_tunnel()

# === Discovery (for Import) ===
def get_cloudflared_info():
    """Get information about Cloudflare tunnel installation and configuration"""
    info = {
        "installed": False,
        "running": False,
        "serviceActive": False,
        "tunnelId": None,
        "ingress": [],
        "configPath": None
    }

    result = subprocess.run(['which', 'cloudflared'], capture_output=True, text=True)
    info["installed"] = result.returncode == 0

    if not info["installed"]:
        return info

    status = subprocess.run(['systemctl', 'is-active', 'cloudflared'], capture_output=True, text=True)
    info["serviceActive"] = status.stdout.strip() == 'active'

    pgrep = subprocess.run(['pgrep', '-f', 'cloudflared'], capture_output=True)
    info["running"] = pgrep.returncode == 0

    config_paths = [
        '/etc/cloudflared/config.yml',
        '/root/.cloudflared/config.yml',
        '/home/pi/.cloudflared/config.yml',
        '/home/gravae/.cloudflared/config.yml',
        '/home/replayme/.cloudflared/config.yml'
    ]

    for path in config_paths:
        if os.path.exists(path):
            info["configPath"] = path
            try:
                with open(path, 'r') as f:
                    content = f.read()
                    for line in content.splitlines():
                        if 'tunnel:' in line:
                            parts = line.split(':')
                            if len(parts) > 1:
                                info["tunnelId"] = parts[1].strip()
                        if 'hostname:' in line:
                            parts = line.split(':')
                            if len(parts) > 1:
                                hostname = parts[1].strip()
                                if hostname:
                                    info["ingress"].append(hostname)
            except:
                pass
            break

    try:
        result = subprocess.run(['systemctl', 'cat', 'cloudflared'], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if '--token' in line or 'tunnel run' in line:
                    info["configuredViaApi"] = True
                    break
    except:
        pass

    return info

def get_shinobi_info():
    """Get information about Shinobi installation"""
    info = {
        "installed": False,
        "running": False,
        "path": None,
        "port": 8080,
        "groupKey": None,
        "apiKey": None,
        "monitors": [],
        "monitorCount": 0
    }

    shinobi_paths = ['/home/Shinobi', '/opt/shinobi']
    for path in shinobi_paths:
        if os.path.exists(path):
            info["installed"] = True
            info["path"] = path
            break

    if not info["installed"]:
        return info

    try:
        netstat = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True)
        if ':8080' in netstat.stdout:
            info["running"] = True
    except:
        pass

    if not info["running"]:
        pm2_paths = ['/usr/bin/pm2', '/usr/local/bin/pm2', 'pm2']
        for pm2_path in pm2_paths:
            try:
                pm2_check = subprocess.run([pm2_path, 'jlist'], capture_output=True, text=True, timeout=5)
                if pm2_check.returncode == 0 and pm2_check.stdout.strip():
                    pm2_list = json.loads(pm2_check.stdout)
                    for proc in pm2_list:
                        proc_name = proc.get('name', '').lower()
                        if 'shinobi' in proc_name or 'camera' in proc_name:
                            info["running"] = proc.get('pm2_env', {}).get('status') == 'online'
                            break
                    break
            except:
                continue

    conf_path = os.path.join(info["path"] or '/home/Shinobi', 'conf.json')
    if os.path.exists(conf_path):
        try:
            with open(conf_path, 'r') as f:
                conf = json.load(f)
                info["port"] = conf.get('port', 8080)
        except:
            pass

    db_config = get_shinobi_db_config()
    if db_config:
        try:
            sql = "SELECT mid, name, ke FROM Monitors;"
            result = subprocess.run([
                'mysql', '-N', '-B',
                '-u', db_config.get('user', 'majesticflame'),
                f"-p{db_config.get('password', '')}",
                '-h', db_config.get('host', 'localhost'),
                db_config.get('database', 'ccio'),
                '-e', sql
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().splitlines():
                    parts = line.split('\\t')
                    if len(parts) >= 2:
                        monitor = {"mid": parts[0], "name": parts[1]}
                        if len(parts) >= 3:
                            monitor["ke"] = parts[2]
                            if not info["groupKey"]:
                                info["groupKey"] = parts[2]
                        info["monitors"].append(monitor)
                info["monitorCount"] = len(info["monitors"])
        except Exception as e:
            print(f"Error getting monitors: {e}")

    if db_config and info["groupKey"]:
        try:
            sql = f"SELECT code FROM API WHERE ke = '{info['groupKey']}' LIMIT 1;"
            result = subprocess.run([
                'mysql', '-N', '-B',
                '-u', db_config.get('user', 'majesticflame'),
                f"-p{db_config.get('password', '')}",
                '-h', db_config.get('host', 'localhost'),
                db_config.get('database', 'ccio'),
                '-e', sql
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                info["apiKey"] = result.stdout.strip()
        except:
            pass

    return info

def get_full_discovery():
    """Get complete system discovery for arena import"""
    return {
        "timestamp": datetime.now().isoformat(),
        "device": {
            "serial": get_device_serial(),
            "model": get_device_model(),
            "hostname": get_hostname(),
            "localIp": get_local_ip(),
            "os": get_os_info(),
            "gpio": get_gpio_info()
        },
        "system": {
            "uptime": get_uptime(),
            "memory": get_memory_info(),
            "cpu": get_cpu_info(),
            "disk": get_disk_info()
        },
        "cloudflare": get_cloudflared_info(),
        "shinobi": get_shinobi_info(),
        "buttonDaemon": get_button_daemon_status(),
        "agent": {
            "version": VERSION,
            "config": CONFIG
        }
    }

# === Button Daemon ===
def check_button_daemon_deps():
    """Check if dependencies for button daemon are available"""
    issues = []

    result = subprocess.run(['which', 'node'], capture_output=True)
    if result.returncode != 0:
        issues.append("Node.js nao esta instalado")

    gpio_info = get_gpio_info()
    if gpio_info.get('is_pi5'):
        onoff_check = subprocess.run(['npm', 'list', '-g', 'onoff'], capture_output=True)
        if onoff_check.returncode != 0:
            issues.append("Biblioteca 'onoff' nao instalada (npm install -g onoff)")
    else:
        pigpiod_check = subprocess.run(['pgrep', 'pigpiod'], capture_output=True)
        if pigpiod_check.returncode != 0:
            issues.append("pigpiod nao esta rodando (sudo pigpiod)")

    return issues

def deploy_button_daemon(script_content):
    try:
        dep_issues = check_button_daemon_deps()
        if dep_issues:
            return {
                "success": False,
                "error": "Dependencias faltando: " + "; ".join(dep_issues),
                "dependencies": dep_issues
            }

        os.makedirs(os.path.dirname(BUTTON_DAEMON_PATH), exist_ok=True)
        with open(BUTTON_DAEMON_PATH, 'w') as f:
            f.write(script_content)
        os.chmod(BUTTON_DAEMON_PATH, 0o755)

        restart_result = subprocess.run(
            ['systemctl', 'restart', 'gravae-buttons'],
            capture_output=True,
            text=True
        )

        if restart_result.returncode != 0:
            journal = subprocess.run(
                ['journalctl', '-u', 'gravae-buttons', '-n', '10', '--no-pager'],
                capture_output=True,
                text=True
            )
            error_details = restart_result.stderr or journal.stdout or "Erro desconhecido"
            return {
                "success": False,
                "error": f"Servico nao iniciou: {error_details[:200]}",
                "details": error_details
            }

        time.sleep(2)

        status_result = subprocess.run(
            ['systemctl', 'is-active', 'gravae-buttons'],
            capture_output=True,
            text=True
        )
        is_active = status_result.stdout.strip() == 'active'

        if not is_active:
            journal = subprocess.run(
                ['journalctl', '-u', 'gravae-buttons', '-n', '10', '--no-pager'],
                capture_output=True,
                text=True
            )
            return {
                "success": False,
                "error": "Servico iniciou mas nao esta ativo",
                "details": journal.stdout[:500] if journal.stdout else "Sem logs"
            }

        return {"success": True, "message": "Button daemon deployed and running"}
    except Exception as e:
        return {"success": False, "error": f"Excecao: {str(e)}"}

# === Cleanup ===
def cleanup_arena(options=None):
    """Clean up arena data from the device"""
    if options is None:
        options = {}

    results = {
        "buttons": None,
        "logs": None,
        "tunnel": None,
        "config": None,
        "phoenix": None,
    }
    errors = []

    # Always stop Phoenix first to prevent reboots during cleanup
    try:
        subprocess.run(['systemctl', 'stop', 'gravae-phoenix'], capture_output=True)
        subprocess.run(['systemctl', 'disable', 'gravae-phoenix'], capture_output=True)
        results["phoenix"] = "stopped"
    except Exception as e:
        errors.append(f"phoenix: {str(e)}")
        results["phoenix"] = "error"

    if options.get('buttons', True):
        try:
            subprocess.run(['systemctl', 'stop', 'gravae-buttons'], capture_output=True)
            subprocess.run(['systemctl', 'disable', 'gravae-buttons'], capture_output=True)
            if os.path.exists(BUTTON_DAEMON_PATH):
                os.remove(BUTTON_DAEMON_PATH)
            results["buttons"] = "cleaned"
        except Exception as e:
            errors.append(f"buttons: {str(e)}")
            results["buttons"] = "error"

    if options.get('logs', True):
        try:
            log_dir = os.path.dirname(BUTTON_DAEMON_PATH) + '/logs'
            if os.path.exists(log_dir):
                import shutil
                shutil.rmtree(log_dir)
            results["logs"] = "cleaned"
        except Exception as e:
            errors.append(f"logs: {str(e)}")
            results["logs"] = "error"

    if options.get('tunnel', True):
        try:
            subprocess.run(['pkill', '-f', 'cloudflared'], capture_output=True)
            for f in ['/tmp/cf_shinobi.log', '/tmp/cf_agent.log', '/tmp/cf_named.log']:
                if os.path.exists(f):
                    os.remove(f)
            results["tunnel"] = "stopped"
        except Exception as e:
            errors.append(f"tunnel: {str(e)}")
            results["tunnel"] = "error"

    if options.get('config', True):
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, 'r') as f:
                    config = json.load(f)
                clean_config = {
                    "deviceId": config.get("deviceId"),
                    "arenaType": config.get("arenaType"),
                    "arenaUser": config.get("arenaUser"),
                    "cleanedAt": datetime.now().isoformat(),
                }
                with open(CONFIG_PATH, 'w') as f:
                    json.dump(clean_config, f, indent=2)
            results["config"] = "cleaned"
        except Exception as e:
            errors.append(f"config: {str(e)}")
            results["config"] = "error"

    return {
        "success": len(errors) == 0,
        "results": results,
        "errors": errors if errors else None,
    }

# === Phoenix Integration ===
PHOENIX_LOG_PATH = "/var/log/gravae/phoenix.log"
PHOENIX_ALERT_DB = "/var/log/gravae/alerts.db"

def get_phoenix_status():
    """Get Phoenix daemon status with full system info"""
    status = {
        "running": False,
        "version": "1.0.0",
        "uptime": None,
        "lastCheck": None,
        "services": {},
        "connectivity": True,
        "resources": {},
        "monitors": []
    }

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "gravae-phoenix"],
            capture_output=True, text=True, timeout=5
        )
        status["running"] = result.stdout.strip() == "active"
    except:
        pass

    services_to_check = [
        ("gravae-agent", "gravae-agent"),
        ("cloudflared", "cloudflared"),
        ("shinobi", "pm2"),
        ("gravae-buttons", "gravae-buttons")
    ]

    for service_name, check_type in services_to_check:
        try:
            if check_type == "pm2":
                result = subprocess.run(
                    ["pm2", "list", "--no-color"],
                    capture_output=True, text=True, timeout=10
                )
                status["services"][service_name] = "online" in result.stdout.lower()
            else:
                result = subprocess.run(
                    ["systemctl", "is-active", service_name],
                    capture_output=True, text=True, timeout=5
                )
                status["services"][service_name] = result.stdout.strip() == "active"
        except:
            status["services"][service_name] = False

    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            status["resources"]["temp"] = round(int(f.read().strip()) / 1000, 1)
    except:
        pass

    try:
        with open("/proc/meminfo", "r") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
            total = meminfo.get("MemTotal", 0)
            free = meminfo.get("MemFree", 0) + meminfo.get("Buffers", 0) + meminfo.get("Cached", 0)
            if total > 0:
                status["resources"]["memory"] = round(((total - free) / total) * 100, 1)
    except:
        pass

    try:
        st = os.statvfs("/")
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        if total > 0:
            status["resources"]["disk"] = round(((total - free) / total) * 100, 1)
    except:
        pass

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "8.8.8.8"],
            capture_output=True, timeout=5
        )
        status["connectivity"] = result.returncode == 0
    except:
        status["connectivity"] = False

    try:
        shinobi_conf = get_shinobi_config()
        if shinobi_conf:
            api_key = shinobi_conf.get("apiKey") or CONFIG.get("shinobiApiKey")
            group_key = shinobi_conf.get("groupKey") or CONFIG.get("shinobiGroupKey")

            if api_key and group_key:
                monitors_url = f"http://localhost:8080/{api_key}/monitor/{group_key}"
                req = urllib.request.Request(monitors_url)
                req.add_header("Accept", "application/json")
                response = urllib.request.urlopen(req, timeout=5)
                monitors_data = json.loads(response.read().decode())

                if isinstance(monitors_data, list):
                    for m in monitors_data[:20]:
                        status["monitors"].append({
                            "mid": m.get("mid", ""),
                            "name": m.get("name", m.get("mid", "")),
                            "mode": m.get("mode", "unknown"),
                            "status": m.get("status", "unknown"),
                            "type": m.get("type", "")
                        })
    except Exception as e:
        print(f"Failed to get monitors: {e}")

    if os.path.exists(PHOENIX_LOG_PATH):
        try:
            with open(PHOENIX_LOG_PATH, "r") as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    try:
                        last_entry = json.loads(last_line)
                        status["lastCheck"] = last_entry.get("timestamp")
                    except:
                        pass
        except:
            pass

    return status

def phoenix_disable():
    """Disable Phoenix daemon - emergency kill switch

    This will:
    1. Create the kill switch file to prevent reboots
    2. Stop the Phoenix service
    3. Disable the service from starting on boot
    """
    result = {
        "success": True,
        "killSwitch": False,
        "serviceStopped": False,
        "serviceDisabled": False,
        "errors": []
    }

    # 1. Create kill switch file
    try:
        os.makedirs("/etc/gravae", exist_ok=True)
        with open("/etc/gravae/no_reboot", "w") as f:
            f.write(f"Phoenix disabled via agent at {datetime.now().isoformat()}\\n")
        result["killSwitch"] = True
    except Exception as e:
        result["errors"].append(f"Failed to create kill switch: {e}")
        result["success"] = False

    # 2. Stop the service
    try:
        subprocess.run(["sudo", "systemctl", "stop", "gravae-phoenix"],
                      capture_output=True, timeout=10)
        # Also kill any running process
        subprocess.run(["sudo", "pkill", "-9", "-f", "phoenix_daemon.py"],
                      capture_output=True, timeout=5)
        result["serviceStopped"] = True
    except Exception as e:
        result["errors"].append(f"Failed to stop service: {e}")

    # 3. Disable the service
    try:
        subprocess.run(["sudo", "systemctl", "disable", "gravae-phoenix"],
                      capture_output=True, timeout=10)
        result["serviceDisabled"] = True
    except Exception as e:
        result["errors"].append(f"Failed to disable service: {e}")

    # Verify it's stopped
    try:
        check = subprocess.run(["systemctl", "is-active", "gravae-phoenix"],
                              capture_output=True, text=True, timeout=5)
        result["status"] = check.stdout.strip()
    except:
        result["status"] = "unknown"

    return result

def phoenix_enable():
    """Re-enable Phoenix daemon

    This will:
    1. Remove the kill switch file
    2. Enable the service
    3. Start the Phoenix service
    """
    result = {
        "success": True,
        "killSwitchRemoved": False,
        "serviceEnabled": False,
        "serviceStarted": False,
        "errors": []
    }

    # 1. Remove kill switch file
    try:
        if os.path.exists("/etc/gravae/no_reboot"):
            os.remove("/etc/gravae/no_reboot")
        result["killSwitchRemoved"] = True
    except Exception as e:
        result["errors"].append(f"Failed to remove kill switch: {e}")

    # 2. Enable the service
    try:
        subprocess.run(["sudo", "systemctl", "enable", "gravae-phoenix"],
                      capture_output=True, timeout=10)
        result["serviceEnabled"] = True
    except Exception as e:
        result["errors"].append(f"Failed to enable service: {e}")
        result["success"] = False

    # 3. Start the service
    try:
        subprocess.run(["sudo", "systemctl", "start", "gravae-phoenix"],
                      capture_output=True, timeout=10)
        result["serviceStarted"] = True
    except Exception as e:
        result["errors"].append(f"Failed to start service: {e}")
        result["success"] = False

    # Verify it's running
    try:
        check = subprocess.run(["systemctl", "is-active", "gravae-phoenix"],
                              capture_output=True, text=True, timeout=5)
        result["status"] = check.stdout.strip()
    except:
        result["status"] = "unknown"

    return result

def get_phoenix_alerts(limit=50, pending_only=True):
    """Get Phoenix alerts from database"""
    alerts = []

    if not os.path.exists(PHOENIX_ALERT_DB):
        return {"alerts": [], "total": 0}

    try:
        import sqlite3
        conn = sqlite3.connect(PHOENIX_ALERT_DB)
        cursor = conn.cursor()

        if pending_only:
            cursor.execute(
                "SELECT id, timestamp, type, severity, message, details FROM alerts WHERE synced = 0 ORDER BY id DESC LIMIT ?",
                (limit,)
            )
        else:
            cursor.execute(
                "SELECT id, timestamp, type, severity, message, details FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,)
            )

        for row in cursor:
            alerts.append({
                "id": row[0],
                "timestamp": row[1],
                "type": row[2],
                "severity": row[3],
                "message": row[4],
                "details": json.loads(row[5]) if row[5] else None
            })

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE synced = 0")
        total = cursor.fetchone()[0]

        conn.close()
        return {"alerts": alerts, "total": total}

    except Exception as e:
        return {"alerts": [], "total": 0, "error": str(e)}

def mark_phoenix_alerts_synced(alert_ids):
    """Mark alerts as synced"""
    if not alert_ids or not os.path.exists(PHOENIX_ALERT_DB):
        return False

    try:
        import sqlite3
        conn = sqlite3.connect(PHOENIX_ALERT_DB)
        placeholders = ",".join("?" * len(alert_ids))
        conn.execute(f"UPDATE alerts SET synced = 1 WHERE id IN ({placeholders})", alert_ids)
        conn.commit()
        conn.close()
        return True
    except:
        return False

def get_phoenix_logs(lines=100):
    """Get recent Phoenix log entries"""
    logs = []

    if not os.path.exists(PHOENIX_LOG_PATH):
        return {"logs": [], "error": "Log file not found"}

    try:
        with open(PHOENIX_LOG_PATH, "r") as f:
            all_lines = f.readlines()
            recent_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines

            for line in recent_lines:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        logs.append(entry)
                    except:
                        logs.append({"raw": line})

        return {"logs": logs}
    except Exception as e:
        return {"logs": [], "error": str(e)}

def get_button_history():
    """Get recent button press history from Shinobi events or button daemon logs"""
    button_presses = []

    try:
        shinobi_conf = get_shinobi_config()
        if shinobi_conf.get("apiKey") and shinobi_conf.get("groupKey"):
            api_key = shinobi_conf["apiKey"]
            group_key = shinobi_conf["groupKey"]

            monitors_url = f"http://localhost:8080/{api_key}/monitor/{group_key}"
            try:
                req = urllib.request.Request(monitors_url)
                response = urllib.request.urlopen(req, timeout=5)
                monitors = json.loads(response.read().decode())

                for monitor in monitors[:10]:
                    mid = monitor.get("mid", "")
                    mname = monitor.get("name", mid)

                    events_url = f"http://localhost:8080/{api_key}/events/{group_key}/{mid}"
                    try:
                        req = urllib.request.Request(events_url)
                        response = urllib.request.urlopen(req, timeout=5)
                        events = json.loads(response.read().decode())

                        for event in events[:5]:
                            if event.get("details", {}).get("reason") == "recording":
                                button_presses.append({
                                    "monitor": mname,
                                    "monitorId": mid,
                                    "timestamp": event.get("time", ""),
                                    "action": "recording_triggered",
                                    "type": "shinobi_event"
                                })
                    except:
                        pass
            except Exception as e:
                print(f"Failed to get Shinobi events: {e}")
    except:
        pass

    button_log_paths = [
        "/var/log/gravae/buttons.log",
        "/home/gravae/Documents/Gravae/buttons.log",
        "/home/pi/Documents/Gravae/buttons.log"
    ]

    for log_path in button_log_paths:
        if os.path.exists(log_path):
            try:
                with open(log_path, "r") as f:
                    lines = f.readlines()[-50:]
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            if entry.get("type") == "button_press":
                                button_presses.append({
                                    "monitor": entry.get("monitor", "unknown"),
                                    "timestamp": entry.get("timestamp", ""),
                                    "action": entry.get("action", "pressed"),
                                    "type": "button_daemon"
                                })
                        except:
                            if "button" in line.lower() or "pressed" in line.lower():
                                button_presses.append({
                                    "monitor": "unknown",
                                    "timestamp": "",
                                    "action": line[:100],
                                    "type": "log_line"
                                })
            except:
                pass
            break

    button_presses.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"buttonPresses": button_presses[:30]}

# === HTTP Handler ===
class AgentHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode() if length else '{}'
        try:
            data = json.loads(body)
        except:
            data = {}

        if path == '/terminal/create':
            session_id = create_terminal_session()
            self._send_json({"sessionId": session_id})

        elif path == '/terminal/input':
            session_id = data.get('sessionId')
            input_data = data.get('data', '')
            session = get_terminal_session(session_id)
            if session:
                success = session.write(input_data)
                self._send_json({"success": success})
            else:
                self._send_json({"error": "Session not found"}, 404)

        elif path == '/terminal/resize':
            session_id = data.get('sessionId')
            cols = data.get('cols', 80)
            rows = data.get('rows', 24)
            session = get_terminal_session(session_id)
            if session:
                success = session.resize(cols, rows)
                self._send_json({"success": success})
            else:
                self._send_json({"error": "Session not found"}, 404)

        elif path == '/terminal/close':
            session_id = data.get('sessionId')
            success = close_terminal_session(session_id)
            self._send_json({"success": success})

        elif path == '/update/perform':
            threading.Thread(target=perform_update, daemon=True).start()
            self._send_json({"success": True, "message": "Update started"})

        elif path == '/update/restart':
            self._send_json({"success": True, "message": "Restarting..."})
            threading.Thread(target=lambda: (time.sleep(1), restart_agent()), daemon=True).start()

        elif path == '/shinobi/setup':
            if not data.get('groupKey') or not data.get('email') or not data.get('password'):
                self._send_json({"success": False, "error": "groupKey, email and password required"}, 400)
                return
            result = setup_shinobi_account(data['groupKey'], data['email'], data['password'])
            if result.get('success') and result.get('apiKey') and result.get('groupKey'):
                CONFIG['shinobiApiKey'] = result['apiKey']
                CONFIG['shinobiGroupKey'] = result['groupKey']
                if result.get('userId'):
                    CONFIG['shinobiUserId'] = result['userId']
                save_config()
                print(f"[Shinobi Setup] Saved credentials to config: apiKey={result['apiKey'][:8]}..., groupKey={result['groupKey']}")
            self._send_json({**result, "deviceId": CONFIG.get('deviceId'), "deviceSerial": get_device_serial()})

        elif path == '/shinobi/cleanup':
            if not data.get('groupKey') or not data.get('email') or not data.get('password'):
                self._send_json({"success": False, "error": "groupKey, email and password required"}, 400)
                return
            result = cleanup_shinobi(data['groupKey'], data['email'], data['password'])
            self._send_json(result)

        elif path == '/phoenix/disable':
            # Emergency endpoint to disable Phoenix daemon and prevent reboots
            result = phoenix_disable()
            self._send_json(result)

        elif path == '/phoenix/enable':
            # Re-enable Phoenix daemon after emergency disable
            result = phoenix_enable()
            self._send_json(result)

        elif path == '/tunnel/setup':
            result = setup_cloudflare_tunnel(
                tunnel_type=data.get('type', 'quick'),
                tunnel_token=data.get('tunnelToken'),
                shinobi_hostname=data.get('shinobiHostname'),
                agent_hostname=data.get('agentHostname')
            )
            self._send_json({**result, "deviceId": CONFIG.get('deviceId'), "deviceSerial": get_device_serial()})

        elif path == '/tunnel/run':
            tunnel_token = data.get('tunnelToken')
            tunnel_name = data.get('tunnelName', 'custom-tunnel')
            if not tunnel_token:
                self._send_json({"success": False, "error": "tunnelToken required"}, 400)
                return
            result = run_tunnel_with_token(tunnel_token, tunnel_name)
            self._send_json(result)

        elif path == '/buttons/deploy':
            if not data.get('script'):
                self._send_json({"success": False, "error": "Script required"}, 400)
                return
            self._send_json(deploy_button_daemon(data['script']))

        elif path == '/buttons/restart':
            try:
                subprocess.run(['systemctl', 'restart', 'gravae-buttons'], check=True)
                time.sleep(2)
                self._send_json({"success": True, "status": get_button_daemon_status()})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})

        elif path == '/config/update':
            # Update config with tunnel hostnames (for emergency SSH access, etc.)
            updated = []
            if data.get('shinobiHostname'):
                CONFIG['shinobiHostname'] = data['shinobiHostname']
                updated.append('shinobiHostname')
            if data.get('agentHostname'):
                CONFIG['agentHostname'] = data['agentHostname']
                updated.append('agentHostname')
            if data.get('sshHostname'):
                CONFIG['sshHostname'] = data['sshHostname']
                updated.append('sshHostname')
            if data.get('tunnelId'):
                CONFIG['tunnelId'] = data['tunnelId']
                updated.append('tunnelId')
            if updated:
                save_config()
                self._send_json({"success": True, "updated": updated, "config": CONFIG})
            else:
                self._send_json({"success": False, "error": "No fields to update"}, 400)

        elif path == '/cleanup':
            options = {
                'buttons': data.get('buttons', True),
                'logs': data.get('logs', True),
                'tunnel': data.get('tunnel', True),
                'config': data.get('config', True),
            }
            result = cleanup_arena(options)
            self._send_json(result)

        elif path == '/phoenix/alerts/sync':
            alert_ids = data.get('alertIds', [])
            success = mark_phoenix_alerts_synced(alert_ids)
            self._send_json({"success": success})

        elif path == '/phoenix/status':
            self._send_json(get_phoenix_status())

        elif path == '/phoenix/monitors':
            api_key = data.get('apiKey') or CONFIG.get('shinobiApiKey')
            group_key = data.get('groupKey') or CONFIG.get('shinobiGroupKey')

            if not api_key or not group_key:
                self._send_json({"monitors": [], "error": "No Shinobi credentials available"})
                return

            try:
                shinobi_url = f"http://localhost:8080/{api_key}/monitor/{group_key}"
                req = urllib.request.Request(shinobi_url, headers={'Accept': 'application/json'})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    monitors_data = json.loads(resp.read().decode())

                monitors = []
                for m in monitors_data:
                    mid = m.get('mid', '')
                    name = m.get('name', mid)
                    mode = m.get('mode', 'stop')
                    status = m.get('status', 'unknown')

                    is_online = mode == 'start' and status not in ['died', 'connecting', 'failed', 'error']

                    events = []
                    try:
                        events_url = f"http://localhost:8080/{api_key}/events/{group_key}/{mid}?limit=5"
                        events_req = urllib.request.Request(events_url, headers={'Accept': 'application/json'})
                        with urllib.request.urlopen(events_req, timeout=5) as events_resp:
                            events_data = json.loads(events_resp.read().decode())
                            for ev in (events_data if isinstance(events_data, list) else []):
                                events.append({
                                    'time': ev.get('time', ''),
                                    'reason': ev.get('reason', ''),
                                    'confidence': ev.get('confidence'),
                                    'plug': ev.get('plug', '')
                                })
                    except:
                        pass

                    monitors.append({
                        'mid': mid,
                        'name': name,
                        'mode': mode,
                        'status': status,
                        'isOnline': is_online,
                        'events': events
                    })

                self._send_json({"monitors": monitors})
            except Exception as e:
                self._send_json({"monitors": [], "error": str(e)})

        elif path == '/network/configure':
            # Configure static IP or DHCP
            action = data.get('action')  # 'static' or 'dhcp'
            interface = data.get('interface', 'eth0')

            if action == 'static':
                ip = data.get('ip')
                prefix = data.get('prefix', 24)
                gateway = data.get('gateway')
                dns = data.get('dns')

                if not ip or not gateway:
                    self._send_json({"success": False, "error": "ip and gateway are required"}, 400)
                    return

                result = configure_network_static(interface, ip, prefix, gateway, dns)
                self._send_json(result)

            elif action == 'dhcp':
                result = configure_network_dhcp(interface)
                self._send_json(result)

            else:
                self._send_json({"success": False, "error": "action must be 'static' or 'dhcp'"}, 400)

        elif path == '/network/alias':
            # Add or remove IP alias
            action = data.get('action', 'add')  # 'add' or 'remove'
            interface = data.get('interface', 'eth0')
            ip = data.get('ip')
            prefix = data.get('prefix', 24)
            label = data.get('label')  # Optional, like eth0:1

            if not ip:
                self._send_json({"success": False, "error": "ip is required"}, 400)
                return

            if action == 'add':
                result = add_network_alias(interface, ip, prefix, label)
            elif action == 'remove':
                result = remove_network_alias(interface, ip, prefix)
            else:
                self._send_json({"success": False, "error": "action must be 'add' or 'remove'"}, 400)
                return

            self._send_json(result)

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == '/terminal/output':
            session_id = query.get('sessionId', [None])[0]
            session = get_terminal_session(session_id)
            if session:
                output = session.get_output()
                self._send_json({"output": output, "connected": session.running})
            else:
                self._send_json({"error": "Session not found"}, 404)
            return

        if path == '/terminal/status':
            cleanup_old_sessions()
            self._send_json({"activeSessions": len(terminal_sessions)})
            return

        if path == '/update/check':
            self._send_json(check_for_updates())
            return

        if path == '/update/status':
            self._send_json(update_status)
            return

        if path == '/update/version':
            self._send_json({"version": VERSION})
            return

        routes = {
            '/': lambda: {"status": "ok", "agent": "gravae", "version": VERSION, "deviceId": CONFIG.get("deviceId"), "deviceSerial": get_device_serial(), "deviceModel": get_device_model()},
            '/health': lambda: {"status": "ok", "agent": "gravae", "version": VERSION},
            '/config': lambda: CONFIG,
            '/system/info': get_full_system_info,
            '/system/memory': get_memory_info,
            '/system/cpu': get_cpu_info,
            '/system/disk': get_disk_info,
            '/system/network': lambda: {"localIp": get_local_ip(), "gateway": get_gateway(), "hostname": get_hostname()},
            '/system/uptime': get_uptime,
            '/network/info': get_network_interfaces,
            '/hardware/info': lambda: {"model": get_device_model(), "serial": get_device_serial(), "os": get_os_info(), "gpio": get_gpio_info()},
            '/gpio/info': get_gpio_info,
            '/buttons/status': get_button_daemon_status,
            '/discovery': get_full_discovery,
            '/phoenix/status': get_phoenix_status,
            '/phoenix/alerts': get_phoenix_alerts,
            '/phoenix/logs': get_phoenix_logs,
            '/phoenix/buttons': get_button_history
        }
        if path in routes:
            self._send_json(routes[path]())
        else:
            self._send_json({"error": "Not found"}, 404)

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")

def main():
    server = HTTPServer(('0.0.0.0', PORT), AgentHandler)
    print(f"Gravae Agent v{VERSION} on port {PORT}")
    server.serve_forever()

if __name__ == '__main__':
    main()
