#!/usr/bin/env python3
"""
Phoenix Daemon v1.5.0
Self-healing module for Gravae Arena Agent

Features:
- Service Guardian: Monitors and restarts failed services
- Connectivity Sentinel: Tracks internet connectivity and escalates recovery
- Network Recovery: Auto-switches between static IP and DHCP
- Alert Queue: Stores alerts offline, syncs when back online
- Persistent Logging: Structured logs with rotation
"""

import os
import sys
import json
import time
import socket
import sqlite3
import subprocess
import threading
import signal
from datetime import datetime, timedelta
from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler

# === Configuration ===
VERSION = "1.8.2"
LOG_DIR = Path("/var/log/gravae")
LOG_FILE = LOG_DIR / "phoenix.log"
ALERT_DB = LOG_DIR / "alerts.db"
NETWORK_BACKUP_DIR = LOG_DIR / "network_backup"
CONFIG_PATH = Path("/etc/gravae/device.json")
DHCPCD_CONF = Path("/etc/dhcpcd.conf")

# Kill switch - if this file exists, Phoenix will NOT reboot the system
# This is a safety mechanism to prevent boot loops
KILL_SWITCH_PATH = Path("/etc/gravae/no_reboot")

# Timing configuration (in seconds)
# NOTE: Intervals increased to reduce CPU usage on Raspberry Pi
CHECK_INTERVAL = 120  # Check every 2 minutes (was 60s)
CONNECTIVITY_CHECK_INTERVAL = 60  # Check connectivity every minute (was 30s)
SERVICE_RESTART_MAX_ATTEMPTS = 3
SERVICE_RESTART_COOLDOWN = 300  # 5 minutes between restart attempts

# Escalation thresholds (in minutes)
ESCALATION_RESTART_CLOUDFLARED = 30
ESCALATION_RESTART_NETWORKING = 60   # 1 hour
ESCALATION_TRY_DHCP_STATIC = 120    # 2 hours (only when static IP - common modem change scenario)
ESCALATION_REBOOT = 240             # 4 hours

# Minimum uptime before allowing reboot (prevents boot loops)
MIN_UPTIME_FOR_REBOOT = 600  # 10 minutes - system must be up at least this long before Phoenix can reboot

# Connectivity check targets
PING_TARGETS = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
HTTP_TARGETS = ["https://cloudflare.com", "https://google.com"]

# Services to monitor
SERVICES = {
    "gravae-agent": {"critical": True, "port": 8888},
    "cloudflared": {"critical": True, "port": None},
    "gravae-buttons": {"critical": True, "port": None, "alert_only": True},  # Alert but don't auto-restart
    "shinobi": {"critical": True, "port": 8080, "pm2": True},  # Shinobi via pm2
}

# Resource thresholds
TEMP_WARNING = 70  # Celsius
TEMP_CRITICAL = 80
DISK_WARNING = 85  # Percent
DISK_CRITICAL = 95
MEMORY_WARNING = 85
MEMORY_CRITICAL = 95
VOLTAGE_LOW = 4.63  # Volts - RPi hardware undervoltage threshold (firmware-defined)

# === Logging Setup ===
def setup_logging():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("phoenix")
    logger.setLevel(logging.DEBUG)

    # File handler with rotation (10MB, keep 7 files)
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024, backupCount=7
    )
    file_handler.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # JSON formatter for file
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_obj = {
                "timestamp": datetime.now().isoformat(),
                "level": record.levelname,
                "module": record.name,
                "message": record.getMessage(),
            }
            if hasattr(record, "extra"):
                log_obj.update(record.extra)
            return json.dumps(log_obj)

    file_handler.setFormatter(JsonFormatter())
    console_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(message)s", "%H:%M:%S"
    ))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

log = setup_logging()

# === Alert Database ===
class AlertQueue:
    def __init__(self, db_path=ALERT_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT,
                synced INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def add(self, alert_type, severity, message, details=None):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO alerts (timestamp, type, severity, message, details) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), alert_type, severity, message, json.dumps(details) if details else None)
        )
        conn.commit()
        conn.close()
        log.info(f"Alert queued: [{severity}] {alert_type} - {message}")

    def get_pending(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            "SELECT id, timestamp, type, severity, message, details FROM alerts WHERE synced = 0 ORDER BY id LIMIT ?",
            (limit,)
        )
        alerts = []
        for row in cursor:
            alerts.append({
                "id": row[0],
                "timestamp": row[1],
                "type": row[2],
                "severity": row[3],
                "message": row[4],
                "details": json.loads(row[5]) if row[5] else None
            })
        conn.close()
        return alerts

    def mark_synced(self, alert_ids):
        if not alert_ids:
            return
        conn = sqlite3.connect(self.db_path)
        placeholders = ",".join("?" * len(alert_ids))
        conn.execute(f"UPDATE alerts SET synced = 1 WHERE id IN ({placeholders})", alert_ids)
        conn.commit()
        conn.close()

    def cleanup_old(self, days=30):
        conn = sqlite3.connect(self.db_path)
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        conn.execute("DELETE FROM alerts WHERE synced = 1 AND timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()

alerts = AlertQueue()

# === Service Guardian ===
class ServiceGuardian:
    def __init__(self):
        self.restart_attempts = {}  # service -> (count, last_attempt)
        self.service_status = {}

    def check_service_systemd(self, service_name):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip() == "active"
        except:
            return False

    def check_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex(("localhost", port))
            sock.close()
            return result == 0
        except:
            return False

    def check_shinobi(self):
        # Shinobi runs via pm2, check port 8080
        return self.check_port(8080)

    def check_pm2_process(self, name_contains):
        """Check if a pm2 process is running"""
        try:
            result = subprocess.run(
                ["pm2", "jlist"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                processes = json.loads(result.stdout)
                for proc in processes:
                    if name_contains.lower() in proc.get("name", "").lower():
                        return proc.get("pm2_env", {}).get("status") == "online"
        except:
            pass
        return False

    def check_legacy_button_process(self):
        """Check if legacy botao.py is running (for older arenas)"""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "botao.py"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0 and result.stdout.strip() != ""
        except:
            return False

    def restart_pm2_process(self, name):
        """Restart a pm2 process"""
        try:
            subprocess.run(["pm2", "restart", name], capture_output=True, timeout=30)
            return True
        except:
            return False

    def restart_service(self, service_name):
        now = time.time()
        attempts, last_attempt = self.restart_attempts.get(service_name, (0, 0))

        # Check cooldown
        if now - last_attempt < SERVICE_RESTART_COOLDOWN:
            log.debug(f"Service {service_name} in cooldown, skipping restart")
            return False

        # Check max attempts
        if attempts >= SERVICE_RESTART_MAX_ATTEMPTS:
            log.warning(f"Service {service_name} exceeded max restart attempts")
            alerts.add(
                "service_restart_failed",
                "critical",
                f"Service {service_name} failed after {attempts} restart attempts",
                {"service": service_name, "attempts": attempts}
            )
            return False

        log.info(f"Restarting service: {service_name} (attempt {attempts + 1})")

        try:
            subprocess.run(
                ["systemctl", "restart", service_name],
                capture_output=True, timeout=30
            )
            self.restart_attempts[service_name] = (attempts + 1, now)

            # Wait and verify
            time.sleep(5)
            if self.check_service_systemd(service_name):
                log.info(f"Service {service_name} restarted successfully")
                alerts.add(
                    "service_restarted",
                    "info",
                    f"Service {service_name} was restarted",
                    {"service": service_name, "attempt": attempts + 1}
                )
                return True
            else:
                log.error(f"Service {service_name} failed to restart")
                return False
        except Exception as e:
            log.error(f"Error restarting {service_name}: {e}")
            return False

    def check_all_services(self):
        status_changed = False

        for service_name, config in SERVICES.items():
            is_running = self.check_service_systemd(service_name)

            # Also check port if specified
            if config.get("port") and is_running:
                is_running = self.check_port(config["port"])

            prev_status = self.service_status.get(service_name)
            self.service_status[service_name] = is_running

            if prev_status is not None and prev_status != is_running:
                status_changed = True
                if is_running:
                    log.info(f"Service {service_name} is now running")
                    alerts.add("service_recovered", "info", f"Service {service_name} recovered")
                    # Reset restart attempts on recovery
                    self.restart_attempts[service_name] = (0, 0)
                else:
                    log.warning(f"Service {service_name} is down")
                    alerts.add("service_down", "warning", f"Service {service_name} is down")

            # Try to restart if not running
            if not is_running and config.get("critical", False):
                self.restart_service(service_name)

        return self.service_status

    def check_all_services_v2(self):
        """Enhanced service check with pm2 and alert-only support"""
        status_changed = False

        for service_name, config in SERVICES.items():
            is_running = False

            # Check based on service type
            if config.get("pm2"):
                # PM2 service (like Shinobi)
                is_running = self.check_port(config.get("port", 8080))
                if not is_running:
                    is_running = self.check_pm2_process(service_name)
            elif service_name == "gravae-buttons":
                # Button service - check both possible systemd names, then legacy botao.py
                is_running = self.check_service_systemd(service_name)
                if not is_running:
                    is_running = self.check_service_systemd("gravae-button-daemon")
                if not is_running:
                    # Check for legacy botao.py process (older arenas)
                    is_running = self.check_legacy_button_process()
            elif config.get("port"):
                # Service with port check
                is_running = self.check_service_systemd(service_name) and self.check_port(config["port"])
            else:
                # Regular systemd service
                is_running = self.check_service_systemd(service_name)

            prev_status = self.service_status.get(service_name)
            self.service_status[service_name] = is_running

            # Check for status changes
            if prev_status is not None and prev_status != is_running:
                status_changed = True
                if is_running:
                    log.info(f"Service {service_name} is now running")
                    alerts.add("service_recovered", "info", f"Service {service_name} recovered")
                    self.restart_attempts[service_name] = (0, 0)
                else:
                    severity = "critical" if config.get("critical") else "warning"
                    log.warning(f"Service {service_name} is down")
                    alerts.add("service_down", severity, f"Service {service_name} is down")

            # Try to restart if not running and not alert-only
            if not is_running and config.get("critical") and not config.get("alert_only"):
                if config.get("pm2"):
                    self.restart_pm2_process(service_name)
                else:
                    self.restart_service(service_name)

        return self.service_status

# === Shinobi Monitor Watcher ===
class ShinobiMonitorWatcher:
    def __init__(self):
        self.monitor_status = {}  # mid -> status
        self.shinobi_config = None
        self._load_shinobi_config()

    def _load_shinobi_config(self):
        """Load Shinobi credentials from device config or conf.json"""
        try:
            # Try to get from device config
            if CONFIG_PATH.exists():
                config = json.loads(CONFIG_PATH.read_text())
                self.shinobi_config = {
                    "groupKey": config.get("shinobiGroupKey"),
                    "apiKey": config.get("shinobiApiKey"),
                }

            # If not in device config, try to read from Shinobi database
            if not self.shinobi_config or not self.shinobi_config.get("apiKey"):
                self._load_from_shinobi_db()

        except Exception as e:
            log.debug(f"Failed to load Shinobi config: {e}")

    def _load_from_shinobi_db(self):
        """Load Shinobi credentials from database"""
        try:
            # Read conf.json to get database credentials
            conf_paths = ["/home/Shinobi/conf.json", "/opt/shinobi/conf.json"]
            db_config = None

            for path in conf_paths:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        conf = json.load(f)
                        db_config = conf.get("db", {})
                        break

            if not db_config:
                return

            # Get first user's group key and API key
            sql = "SELECT ke, code FROM API LIMIT 1;"
            result = subprocess.run([
                "mysql", "-N", "-B",
                "-u", db_config.get("user", "majesticflame"),
                f"-p{db_config.get('password', '')}",
                "-h", db_config.get("host", "localhost"),
                db_config.get("database", "ccio"),
                "-e", sql
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split("\\t")
                if len(parts) >= 2:
                    self.shinobi_config = {
                        "groupKey": parts[0],
                        "apiKey": parts[1],
                    }

        except Exception as e:
            log.debug(f"Failed to load Shinobi config from DB: {e}")

    def get_monitors_status(self):
        """Get status of all Shinobi monitors"""
        if not self.shinobi_config or not self.shinobi_config.get("apiKey"):
            return None

        try:
            import urllib.request

            group_key = self.shinobi_config["groupKey"]
            api_key = self.shinobi_config["apiKey"]

            url = f"http://localhost:8080/{api_key}/monitor/{group_key}"
            req = urllib.request.Request(url)
            response = urllib.request.urlopen(req, timeout=10)
            monitors = json.loads(response.read().decode())

            return monitors

        except Exception as e:
            log.debug(f"Failed to get monitors status: {e}")
            return None

    def check_monitors(self):
        """Check monitors and alert on status changes"""
        monitors = self.get_monitors_status()
        if not monitors:
            return

        for monitor in monitors:
            mid = monitor.get("mid", "")
            name = monitor.get("name", mid)
            mode = monitor.get("mode", "")
            status = monitor.get("status", "")

            # Possible modes: stop, start, record
            # Possible status: watching, died, connecting, etc.

            prev_status = self.monitor_status.get(mid, {})
            prev_mode = prev_status.get("mode")
            prev_status_val = prev_status.get("status")

            # Store current status
            self.monitor_status[mid] = {"mode": mode, "status": status, "name": name}

            # Check for problematic status changes
            if prev_status_val and prev_status_val != status:
                # Alert if changed to died or connecting
                if status in ["died", "connecting", "No Signal"]:
                    log.warning(f"Monitor '{name}' status changed: {prev_status_val} -> {status}")
                    alerts.add(
                        "monitor_status_change",
                        "warning" if status == "connecting" else "critical",
                        f"Monitor '{name}' status: {status}",
                        {
                            "monitor_id": mid,
                            "monitor_name": name,
                            "previous_status": prev_status_val,
                            "current_status": status,
                            "mode": mode
                        }
                    )
                # Alert if recovered
                elif prev_status_val in ["died", "connecting", "No Signal"] and status == "watching":
                    log.info(f"Monitor '{name}' recovered: {prev_status_val} -> {status}")
                    alerts.add(
                        "monitor_recovered",
                        "info",
                        f"Monitor '{name}' recovered and is now watching",
                        {
                            "monitor_id": mid,
                            "monitor_name": name,
                            "previous_status": prev_status_val,
                            "current_status": status
                        }
                    )

# === Connectivity Sentinel ===
ESCALATION_STATE_PATH = LOG_DIR / "escalation_state.json"

class ConnectivitySentinel:
    def __init__(self):
        self.is_online = True
        self.offline_since = None
        self.last_successful_ping = datetime.now()
        self.escalation_level = 0  # 0=none, 1=cloudflared, 2=networking, 3=reboot, 4=dhcp
        self.actions_taken = []
        self._load_persisted_state()

    def _load_persisted_state(self):
        """Load escalation state from disk (survives reboots).
        If we rebooted due to connectivity loss and internet is still down,
        we skip straight to level 3+ to avoid rebooting again."""
        try:
            if ESCALATION_STATE_PATH.exists():
                data = json.loads(ESCALATION_STATE_PATH.read_text())
                saved_level = data.get("escalation_level", 0)
                saved_time = data.get("offline_since")
                if saved_level >= 3:
                    # We already rebooted for connectivity - don't reboot again
                    self.escalation_level = saved_level
                    if saved_time:
                        self.offline_since = datetime.fromisoformat(saved_time)
                    self.is_online = False
                    log.info(f"Restored escalation state: level={saved_level}, "
                            f"offline_since={saved_time} - reboot will NOT repeat")
        except Exception as e:
            log.debug(f"Could not load escalation state: {e}")

    def _persist_state(self):
        """Save escalation state to disk before reboot or periodically."""
        try:
            data = {
                "escalation_level": self.escalation_level,
                "offline_since": self.offline_since.isoformat() if self.offline_since else None,
                "timestamp": datetime.now().isoformat()
            }
            ESCALATION_STATE_PATH.write_text(json.dumps(data))
        except Exception as e:
            log.debug(f"Could not save escalation state: {e}")

    def _clear_persisted_state(self):
        """Clear persisted state when connectivity is restored."""
        try:
            if ESCALATION_STATE_PATH.exists():
                ESCALATION_STATE_PATH.unlink()
        except Exception as e:
            log.debug(f"Could not clear escalation state: {e}")

    def ping(self, host):
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "5", host],
                capture_output=True, timeout=10
            )
            return result.returncode == 0
        except:
            return False

    def http_check(self, url):
        try:
            import urllib.request
            req = urllib.request.Request(url, method="HEAD")
            urllib.request.urlopen(req, timeout=10)
            return True
        except:
            return False

    def check_connectivity(self):
        # Try ping first
        for target in PING_TARGETS:
            if self.ping(target):
                return True

        # Try HTTP as fallback
        for target in HTTP_TARGETS:
            if self.http_check(target):
                return True

        return False

    def get_offline_minutes(self):
        if self.offline_since:
            return (datetime.now() - self.offline_since).total_seconds() / 60
        return 0

    def restart_cloudflared(self):
        log.info("Escalation: Restarting cloudflared")
        try:
            subprocess.run(["systemctl", "restart", "cloudflared"], timeout=30)
            self.actions_taken.append(("restart_cloudflared", datetime.now().isoformat()))
            alerts.add(
                "connectivity_action",
                "warning",
                "Restarted cloudflared due to connectivity issues",
                {"offline_minutes": self.get_offline_minutes()}
            )
            return True
        except Exception as e:
            log.error(f"Failed to restart cloudflared: {e}")
            return False

    def restart_networking(self):
        log.info("Escalation: Restarting networking")
        try:
            # Try different methods
            subprocess.run(["systemctl", "restart", "networking"], capture_output=True, timeout=30)
            subprocess.run(["systemctl", "restart", "dhcpcd"], capture_output=True, timeout=30)

            self.actions_taken.append(("restart_networking", datetime.now().isoformat()))
            alerts.add(
                "connectivity_action",
                "warning",
                "Restarted networking due to connectivity issues",
                {"offline_minutes": self.get_offline_minutes()}
            )
            return True
        except Exception as e:
            log.error(f"Failed to restart networking: {e}")
            return False

    def reboot_system(self):
        # Safety check 1: Kill switch file
        if KILL_SWITCH_PATH.exists():
            log.warning("Reboot blocked: kill switch file exists (/etc/gravae/no_reboot)")
            alerts.add(
                "reboot_blocked",
                "warning",
                "System reboot was blocked by kill switch",
                {"reason": "kill_switch", "offline_minutes": self.get_offline_minutes()}
            )
            return

        # Safety check 2: Minimum uptime of 10 minutes (prevents boot loops)
        try:
            with open("/proc/uptime", "r") as f:
                uptime_seconds = float(f.read().split()[0])
            if uptime_seconds < MIN_UPTIME_FOR_REBOOT:
                log.warning(f"Reboot blocked: system uptime ({uptime_seconds:.0f}s) < minimum ({MIN_UPTIME_FOR_REBOOT}s)")
                alerts.add(
                    "reboot_blocked",
                    "warning",
                    f"System reboot blocked - uptime too short ({uptime_seconds:.0f}s)",
                    {"reason": "min_uptime", "uptime": uptime_seconds}
                )
                return
        except Exception as e:
            # If we can't check uptime, block the reboot to be safe
            log.error(f"Could not check uptime, blocking reboot: {e}")
            return

        # Safety check 3: Minimum 10 minutes between reboots
        try:
            last_will_path = LOG_DIR / "last_will.json"
            if last_will_path.exists():
                with open(last_will_path, "r") as f:
                    last_will = json.load(f)
                last_reboot = datetime.fromisoformat(last_will.get("timestamp", "2000-01-01"))
                time_since_last = (datetime.now() - last_reboot).total_seconds() / 60
                if time_since_last < 10:
                    log.warning(f"Reboot blocked: last reboot was {time_since_last:.0f} minutes ago (minimum 10 min)")
                    alerts.add(
                        "reboot_blocked",
                        "critical",
                        "System reboot blocked - minimum 10 min between reboots",
                        {"reason": "boot_loop_protection", "minutes_since_last": time_since_last}
                    )
                    return
        except Exception as e:
            log.debug(f"Could not check last reboot: {e}")

        # Safety check 4: Max 3 reboots per day
        try:
            reboot_count_path = LOG_DIR / "reboot_count.json"
            today = datetime.now().strftime("%Y-%m-%d")
            reboot_count = 0
            if reboot_count_path.exists():
                with open(reboot_count_path, "r") as f:
                    data = json.load(f)
                if data.get("date") == today:
                    reboot_count = data.get("count", 0)
            if reboot_count >= 3:
                log.warning(f"Reboot blocked: already rebooted {reboot_count} times today (max 3)")
                alerts.add(
                    "reboot_blocked",
                    "critical",
                    f"System reboot blocked - max daily reboots reached ({reboot_count}/3)",
                    {"reason": "max_daily_reboots", "count": reboot_count}
                )
                return
            with open(reboot_count_path, "w") as f:
                json.dump({"date": today, "count": reboot_count + 1}, f)
        except Exception as e:
            log.debug(f"Could not check reboot count: {e}")

        log.warning("Escalation: Rebooting system")
        alerts.add(
            "system_reboot",
            "critical",
            "System reboot triggered due to extended connectivity loss",
            {
                "offline_minutes": self.get_offline_minutes(),
                "actions_taken": self.actions_taken
            }
        )

        # Save state before reboot (so we don't reboot again on next boot)
        self._save_last_will()
        self._persist_state()

        try:
            subprocess.run(["reboot"], timeout=10)
        except Exception as e:
            log.error(f"Failed to reboot: {e}")

    def _save_last_will(self):
        """Save current state before reboot"""
        try:
            state = {
                "timestamp": datetime.now().isoformat(),
                "reason": "connectivity_loss",
                "offline_since": self.offline_since.isoformat() if self.offline_since else None,
                "offline_minutes": self.get_offline_minutes(),
                "actions_taken": self.actions_taken,
                "escalation_level": self.escalation_level
            }
            with open(LOG_DIR / "last_will.json", "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            log.error(f"Failed to save last will: {e}")

    def update(self):
        was_online = self.is_online
        self.is_online = self.check_connectivity()

        if self.is_online:
            if not was_online:
                offline_duration = self.get_offline_minutes()
                log.info(f"Connectivity restored after {offline_duration:.1f} minutes")
                alerts.add(
                    "connectivity_restored",
                    "info",
                    f"Connectivity restored after {offline_duration:.1f} minutes offline",
                    {"offline_minutes": offline_duration, "actions_taken": self.actions_taken}
                )

            # Reset state
            self.offline_since = None
            self.last_successful_ping = datetime.now()
            self.escalation_level = 0
            self.actions_taken = []
            self._clear_persisted_state()
            return True

        # We're offline
        if was_online:
            self.offline_since = datetime.now()
            log.warning("Connectivity lost")
            alerts.add("connectivity_lost", "warning", "Internet connectivity lost")

        offline_minutes = self.get_offline_minutes()

        # Escalation logic
        # When static IP: cloudflared(30m) → networking(1h) → DHCP(2h) → reboot(4h)
        # When DHCP:      cloudflared(30m) → networking(1h) → reboot(4h)
        is_static = NetworkRecovery().is_static_ip()

        if offline_minutes >= ESCALATION_REBOOT and self.escalation_level < 4:
            self.escalation_level = 4
            self.reboot_system()

        elif is_static and offline_minutes >= ESCALATION_TRY_DHCP_STATIC and self.escalation_level < 3:
            self.escalation_level = 3
            # DHCP fallback handled by NetworkRecovery in main loop

        elif offline_minutes >= ESCALATION_RESTART_NETWORKING and self.escalation_level < 2:
            self.escalation_level = 2
            self.restart_networking()

        elif offline_minutes >= ESCALATION_RESTART_CLOUDFLARED and self.escalation_level < 1:
            self.escalation_level = 1
            self.restart_cloudflared()

        return False

# === Network Recovery ===
class NetworkRecovery:
    def __init__(self):
        NETWORK_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        self.original_config = None
        self.is_dhcp_mode = False

    def is_static_ip(self):
        """Check if current config is static IP"""
        try:
            if not DHCPCD_CONF.exists():
                return False

            content = DHCPCD_CONF.read_text()
            return "static ip_address" in content
        except:
            return False

    def backup_network_config(self):
        """Backup current network config"""
        try:
            if DHCPCD_CONF.exists():
                backup_path = NETWORK_BACKUP_DIR / f"dhcpcd.conf.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                backup_path.write_text(DHCPCD_CONF.read_text())

                # Also keep a "last known good" backup
                (NETWORK_BACKUP_DIR / "dhcpcd.conf.last_good").write_text(DHCPCD_CONF.read_text())

                log.info(f"Network config backed up to {backup_path}")
                return True
        except Exception as e:
            log.error(f"Failed to backup network config: {e}")
        return False

    def switch_to_dhcp(self):
        """Temporarily switch to DHCP"""
        if not self.is_static_ip():
            log.info("Already using DHCP")
            return False

        self.backup_network_config()

        try:
            # Read current config
            content = DHCPCD_CONF.read_text()
            self.original_config = content

            # Comment out static IP lines
            new_content = []
            for line in content.splitlines():
                if any(x in line for x in ["static ip_address", "static routers", "static domain_name_servers"]):
                    new_content.append(f"# PHOENIX_DISABLED: {line}")
                else:
                    new_content.append(line)

            DHCPCD_CONF.write_text("\\n".join(new_content))

            # Restart networking
            subprocess.run(["systemctl", "restart", "dhcpcd"], timeout=30)

            self.is_dhcp_mode = True
            log.info("Switched to DHCP mode")
            alerts.add(
                "network_config_changed",
                "warning",
                "Switched from static IP to DHCP due to connectivity issues"
            )
            return True

        except Exception as e:
            log.error(f"Failed to switch to DHCP: {e}")
            self.restore_static_ip()
            return False

    def restore_static_ip(self):
        """Restore original static IP config"""
        if not self.original_config:
            # Try to restore from backup
            last_good = NETWORK_BACKUP_DIR / "dhcpcd.conf.last_good"
            if last_good.exists():
                self.original_config = last_good.read_text()
            else:
                log.error("No original config to restore")
                return False

        try:
            DHCPCD_CONF.write_text(self.original_config)
            subprocess.run(["systemctl", "restart", "dhcpcd"], timeout=30)

            self.is_dhcp_mode = False
            log.info("Restored static IP configuration")
            alerts.add(
                "network_config_restored",
                "info",
                "Restored original static IP configuration"
            )
            return True

        except Exception as e:
            log.error(f"Failed to restore static IP: {e}")
            return False

    def attempt_recovery(self, connectivity):
        """Called when we've been offline long enough to try DHCP"""
        if not self.is_static_ip() or self.is_dhcp_mode:
            return

        log.warning("Attempting network recovery by switching to DHCP")

        if self.switch_to_dhcp():
            # Wait for DHCP to get an IP
            time.sleep(30)

            # Check if we're online now
            if connectivity.check_connectivity():
                log.info("DHCP recovery successful!")
                alerts.add(
                    "network_recovery_success",
                    "warning",
                    "Network recovered by switching to DHCP - possible IP range change",
                    {"action": "switched_to_dhcp"}
                )
            else:
                log.warning("DHCP didn't help, restoring static IP")
                self.restore_static_ip()

# === Resource Monitor ===
class ResourceMonitor:
    def __init__(self):
        self.undervoltage_alerted = False  # Avoid spamming alerts
        self.last_voltage_check = 0  # Timestamp for daily voltage check

    def get_throttled(self):
        """Check Raspberry Pi throttling/voltage status via vcgencmd.
        Bit flags from 'vcgencmd get_throttled':
          0: Under-voltage detected (now)
          1: ARM frequency capped (now)
          2: Currently throttled (now)
          3: Soft temperature limit active (now)
         16: Under-voltage has occurred (since boot)
         17: ARM frequency capping has occurred
         18: Throttling has occurred
         19: Soft temperature limit has occurred
        """
        try:
            result = subprocess.run(
                ["vcgencmd", "get_throttled"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Output: throttled=0x50000
                value = result.stdout.strip().split("=")[-1]
                return int(value, 16)
        except:
            pass
        return None

    def get_voltage(self):
        """Read core voltage via vcgencmd. Returns float (e.g. 1.2000)."""
        try:
            result = subprocess.run(
                ["vcgencmd", "measure_volts", "core"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Output: volt=1.2000V
                value = result.stdout.strip().replace("volt=", "").replace("V", "")
                return float(value)
        except:
            pass
        return None

    def get_temperature(self):
        try:
            with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
                return int(f.read().strip()) / 1000
        except:
            return None

    def get_disk_usage(self):
        try:
            st = os.statvfs("/")
            total = st.f_frsize * st.f_blocks
            used = total - (st.f_frsize * st.f_bavail)
            return (used / total) * 100 if total > 0 else 0
        except:
            return None

    def get_memory_usage(self):
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
                return (used / total) * 100 if total > 0 else 0
        except:
            return None

    def check_resources(self):
        issues = []

        # Temperature
        temp = self.get_temperature()
        if temp:
            if temp >= TEMP_CRITICAL:
                issues.append(("temperature", "critical", f"CPU temperature critical: {temp}°C"))
                alerts.add("temperature_critical", "critical", f"CPU temperature: {temp}°C")
            elif temp >= TEMP_WARNING:
                issues.append(("temperature", "warning", f"CPU temperature high: {temp}°C"))

        # Disk
        disk = self.get_disk_usage()
        if disk:
            if disk >= DISK_CRITICAL:
                issues.append(("disk", "critical", f"Disk usage critical: {disk:.1f}%"))
                alerts.add("disk_critical", "critical", f"Disk usage: {disk:.1f}%")
                self._cleanup_disk()
            elif disk >= DISK_WARNING:
                issues.append(("disk", "warning", f"Disk usage high: {disk:.1f}%"))

        # Memory
        memory = self.get_memory_usage()
        if memory:
            if memory >= MEMORY_CRITICAL:
                issues.append(("memory", "critical", f"Memory usage critical: {memory:.1f}%"))
                alerts.add("memory_critical", "critical", f"Memory usage: {memory:.1f}%")
            elif memory >= MEMORY_WARNING:
                issues.append(("memory", "warning", f"Memory usage high: {memory:.1f}%"))

        # Voltage / Throttling (Raspberry Pi)
        throttled = self.get_throttled()
        if throttled is not None:
            under_voltage_now = bool(throttled & 0x1)
            freq_capped_now = bool(throttled & 0x2)
            throttled_now = bool(throttled & 0x4)
            under_voltage_boot = bool(throttled & 0x10000)

            if under_voltage_now:
                voltage = self.get_voltage()
                issues.append(("voltage", "critical", "Under-voltage detected - power supply inadequate"))
                if not self.undervoltage_alerted:
                    alerts.add(
                        "undervoltage",
                        "critical",
                        "Tensão baixa detectada - fonte de alimentação inadequada",
                        {"throttled_hex": hex(throttled), "voltage": voltage, "freq_capped": freq_capped_now, "throttled": throttled_now}
                    )
                    self.undervoltage_alerted = True
            elif under_voltage_boot and not under_voltage_now:
                # Voltage recovered but happened since boot
                if self.undervoltage_alerted:
                    voltage = self.get_voltage()
                    alerts.add(
                        "undervoltage_recovered",
                        "warning",
                        "Tensão normalizada, mas houve queda desde o boot",
                        {"throttled_hex": hex(throttled), "voltage": voltage}
                    )
                    self.undervoltage_alerted = False
            else:
                self.undervoltage_alerted = False

            if throttled_now and not under_voltage_now:
                issues.append(("throttling", "warning", "CPU throttled due to thermal/power constraints"))

        return issues

    def _cleanup_disk(self):
        """Clean up disk space when critical"""
        log.warning("Cleaning up disk space")
        try:
            # Clean old logs
            subprocess.run(["journalctl", "--vacuum-time=7d"], capture_output=True)

            # Clean apt cache
            subprocess.run(["apt-get", "clean"], capture_output=True)

            # Clean old phoenix logs (keep last 3)
            log_files = sorted(LOG_DIR.glob("phoenix.log.*"))
            for old_log in log_files[:-3]:
                old_log.unlink()

            alerts.add("disk_cleanup", "info", "Performed disk cleanup due to low space")
        except Exception as e:
            log.error(f"Disk cleanup failed: {e}")

# === Heartbeat ===
class Heartbeat:
    def __init__(self):
        self.last_heartbeat = None
        self.platform_url = None
        self._load_config()

    def _load_config(self):
        try:
            if CONFIG_PATH.exists():
                config = json.loads(CONFIG_PATH.read_text())
                # Future: get platform URL from config
        except:
            pass

    def send(self, status):
        """Send heartbeat to platform (future implementation)"""
        self.last_heartbeat = datetime.now()
        # TODO: Implement when platform endpoint is ready
        pass

# === Boot Report ===
def check_boot_report():
    """Check if we just rebooted and send report"""
    last_will_path = LOG_DIR / "last_will.json"

    if last_will_path.exists():
        try:
            with open(last_will_path, "r") as f:
                last_will = json.load(f)

            log.info("System was rebooted by Phoenix")
            alerts.add(
                "boot_after_phoenix_reboot",
                "info",
                "System booted after Phoenix-initiated reboot",
                last_will
            )

            # Remove last will after processing
            last_will_path.unlink()

        except Exception as e:
            log.error(f"Failed to process last will: {e}")

# === Hardware Watchdog (DISABLED) ===
class HardwareWatchdog:
    """Hardware watchdog DISABLED in v1.8.2.

    REASON: Opening /dev/watchdog on Raspberry Pi is extremely dangerous.
    The bcm2835_wdt has a ~15 second timeout. If the process dies or the
    system is slow (SD card I/O, heavy boot), the watchdog fires and causes
    a hard reset. Combined with RuntimeWatchdogSec in systemd, this caused
    infinite reboot loops on multiple production devices.

    The systemd WatchdogSec (software) is sufficient for service monitoring.
    Hardware watchdog should NEVER be used on RPi with SD cards.
    """
    def __init__(self):
        self.enabled = False

    def enable(self):
        log.info("Hardware watchdog DISABLED (removed in v1.8.2 - too dangerous on RPi)")
        return False

    def ping(self):
        pass

    def disable(self):
        pass

# === Main Phoenix Daemon ===
class PhoenixDaemon:
    def __init__(self):
        self.running = True
        self.service_guardian = ServiceGuardian()
        self.connectivity = ConnectivitySentinel()
        self.network_recovery = NetworkRecovery()
        self.resources = ResourceMonitor()
        self.heartbeat = Heartbeat()
        self.watchdog = HardwareWatchdog()
        self.shinobi_watcher = None  # Lazy loaded to save memory

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _get_shinobi_watcher(self):
        """Lazy load Shinobi watcher to save memory"""
        if self.shinobi_watcher is None:
            self.shinobi_watcher = ShinobiMonitorWatcher()
        return self.shinobi_watcher

    def _handle_signal(self, signum, frame):
        log.info(f"Received signal {signum}, shutting down")
        self.running = False
        self.watchdog.disable()

    def _is_setup_complete(self):
        """Check if the system is fully set up before enabling critical features.
        Without cloudflared configured, the watchdog would cause boot loops
        since Phoenix can't maintain connectivity checks."""
        try:
            # Check if cloudflared is actively running (strongest signal)
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "cloudflared"],
                    capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip() == "active":
                    return True
            except:
                pass

            # Fallback: check config + service file
            if not CONFIG_PATH.exists():
                log.warning("Setup incomplete: device.json not found")
                return False

            result = subprocess.run(
                ["systemctl", "list-unit-files", "cloudflared.service"],
                capture_output=True, text=True, timeout=10
            )
            if "cloudflared.service" not in result.stdout:
                log.warning("Setup incomplete: cloudflared service not installed")
                return False

            return True
        except Exception as e:
            log.warning(f"Setup check failed: {e}")
            return False

    def run(self):
        log.info(f"Phoenix Daemon v{VERSION} starting")

        # Check if we just rebooted
        check_boot_report()

        # sd_notify kept for backwards compatibility (no-op if service is Type=simple)
        def sd_notify(msg):
            try:
                addr = os.environ.get("NOTIFY_SOCKET")
                if not addr:
                    return
                import socket as _sock
                s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_DGRAM)
                if addr[0] == "@":
                    addr = "\0" + addr[1:]
                s.sendto(msg.encode(), addr)
                s.close()
            except:
                pass

        sd_notify("READY=1")
        log.info(f"Phoenix v{VERSION} started (Type=simple, no hardware watchdog)")

        last_service_check = 0
        last_connectivity_check = 0
        last_resource_check = 0
        last_monitor_check = 0
        last_heartbeat = 0
        last_alert_cleanup = 0
        last_gc = 0
        last_voltage_check = 0

        while self.running:
            now = time.time()

            try:

                # Service check (every minute)
                if now - last_service_check >= CHECK_INTERVAL:
                    self.service_guardian.check_all_services_v2()
                    last_service_check = now

                # Connectivity check (every 30 seconds)
                if now - last_connectivity_check >= CONNECTIVITY_CHECK_INTERVAL:
                    is_online = self.connectivity.update()

                    # Check if we need to try DHCP recovery (level 3 = DHCP for static IP)
                    if not is_online and self.connectivity.escalation_level >= 3:
                        self.network_recovery.attempt_recovery(self.connectivity)

                    last_connectivity_check = now

                # Shinobi monitor check (every 5 minutes, only when online)
                if now - last_monitor_check >= 300 and self.connectivity.is_online:
                    try:
                        watcher = self._get_shinobi_watcher()
                        watcher.check_monitors()
                    except Exception as e:
                        log.debug(f"Monitor check error: {e}")
                    last_monitor_check = now

                # Resource check (every 5 minutes)
                if now - last_resource_check >= 300:
                    self.resources.check_resources()
                    last_resource_check = now

                # Daily undervoltage check (every 24 hours)
                # Uses get_throttled() bit flags (hardware-level detection) instead of
                # get_voltage() which returns core voltage (~0.85V), NOT the 5V USB supply.
                if now - last_voltage_check >= 86400:
                    throttled = self.resources.get_throttled()
                    if throttled is not None:
                        under_voltage_boot = bool(throttled & 0x10000)
                        if under_voltage_boot:
                            voltage = self.resources.get_voltage()
                            alerts.add(
                                "voltage_low",
                                "warning",
                                f"Subtensão detectada desde o boot (fonte inadequada). Core: {voltage:.2f}V" if voltage else "Subtensão detectada desde o boot (fonte inadequada)",
                                {"throttled_hex": hex(throttled), "core_voltage": voltage, "threshold": VOLTAGE_LOW}
                            )
                    last_voltage_check = now

                # Heartbeat (every 5 minutes when online)
                if now - last_heartbeat >= 300 and self.connectivity.is_online:
                    status = {
                        "services": self.service_guardian.service_status,
                        "connectivity": self.connectivity.is_online,
                        "resources": {
                            "temp": self.resources.get_temperature(),
                            "disk": self.resources.get_disk_usage(),
                            "memory": self.resources.get_memory_usage(),
                            "voltage": self.resources.get_voltage()
                        }
                    }
                    self.heartbeat.send(status)
                    last_heartbeat = now

                # Try to enable watchdog if not yet enabled (setup may have completed)
                if not self.watchdog.enabled and now - last_resource_check >= 300:
                    if self._is_setup_complete():
                        log.info("System setup now complete - enabling hardware watchdog")
                        self.watchdog.enable()

                # Alert cleanup (daily)
                if now - last_alert_cleanup >= 86400:
                    alerts.cleanup_old()
                    last_alert_cleanup = now

                # Garbage collection (every 10 minutes to free memory)
                if now - last_gc >= 600:
                    import gc
                    gc.collect()
                    last_gc = now

            except Exception as e:
                log.error(f"Phoenix loop error: {e}")

            time.sleep(30)  # Main loop sleep (increased from 10s to reduce CPU)

        log.info("Phoenix Daemon stopped")

# === Entry Point ===
def main():
    daemon = PhoenixDaemon()
    daemon.run()

if __name__ == "__main__":
    main()
