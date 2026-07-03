#!/usr/bin/env python3
"""
Phoenix Daemon v1.15.0
Self-healing module for Gravae Arena Agent

Features:
- Service Guardian: Monitors and restarts failed services
- Connectivity Sentinel: Tracks internet connectivity with escalating recovery
- DHCP Fallback (nmcli + dhcpcd): After 2h offline on a static IP, switch to DHCP
  to recover from network reconfigurations; auto-revert if it doesn't help.
- Safe Reboot: After 4h offline, reboot up to 3x/day with boot-loop protection
- Alert Queue: Stores alerts offline, syncs when back online
- Persistent Logging: Structured logs with rotation

SAFETY GUARDS:
- DHCP fallback: max 1 attempt per 24h (persisted across reboots), kill-switch
  honored at /etc/gravae/no_network_change, auto-revert on failure.
- Reboot escalation: only after 4h offline, max 3/day, uptime > 5min.
- Network config edits (nmcli/dhcpcd) backup the previous state before touching it.
"""

import os
import sys
import json
import time
import uuid
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
VERSION = "1.16.1"
LOG_DIR = Path("/var/log/gravae")
LOG_FILE = LOG_DIR / "phoenix.log"
ALERT_DB = LOG_DIR / "alerts.db"
NETWORK_BACKUP_DIR = LOG_DIR / "network_backup"
CONFIG_PATH = Path("/etc/gravae/device.json")
DHCPCD_CONF = Path("/etc/dhcpcd.conf")

# Timing configuration (in seconds)
CHECK_INTERVAL = 120  # Check every 2 minutes
CONNECTIVITY_CHECK_INTERVAL = 60  # Check connectivity every minute
SERVICE_RESTART_MAX_ATTEMPTS = 3
SERVICE_RESTART_COOLDOWN = 300  # 5 minutes between restart attempts

# Escalation thresholds (in minutes)
ESCALATION_RESTART_CLOUDFLARED = 30  # Restart cloudflared service
ESCALATION_RESTART_NETWORKING = 60   # Restart networking services (no config changes)
ESCALATION_DHCP_FALLBACK = 120       # Try DHCP fallback after 2 hours offline
ESCALATION_REBOOT = 240              # Reboot system after 4 hours without internet
MAX_REBOOTS_PER_DAY = 3              # Maximum reboots in a 24-hour window
MIN_UPTIME_BEFORE_REBOOT = 300       # 5 minutes: don't reboot if system just booted (prevents boot loops)
REBOOT_STATE_FILE = LOG_DIR / "reboot_state.json"
NETWORK_BACKUP_FILE = Path("/etc/gravae/network-backup.json")
NETWORK_CHANGE_KILLSWITCH = Path("/etc/gravae/no_network_change")
DHCP_FALLBACK_STATE_FILE = LOG_DIR / "dhcp_fallback_state.json"
DHCP_FALLBACK_COOLDOWN_HOURS = 24  # Anti boot-loop: at most 1 dhcp fallback per 24h
DHCPCD_BACKUP = Path("/etc/dhcpcd.conf.gravae-backup")

# Shinobi directories (try both common locations)
SHINOBI_DIRS = [Path("/home/Shinobi"), Path("/opt/shinobi")]

# PM2: Shinobi's canonical PM2 lives as root under a single PM2_HOME.
# Running pm2 without a fixed PM2_HOME, or as the arena user (`sudo -u <user> pm2`),
# spawns a SECOND PM2 God daemon under a different home (e.g. /home/<user>/.pm2).
# Those stray daemons are the root cause of Bug6 (multiple pm2 daemons): they hold
# orphan camera/cron processes and break resurrection on reboot. Always pin root + this home.
PM2_HOME = "/root/.pm2"

def _pm2_env():
    """Environment for every pm2 subprocess call: pin root's canonical PM2_HOME."""
    return {**os.environ, "PM2_HOME": PM2_HOME, "HOME": "/root"}

# Connectivity check targets
PING_TARGETS = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
HTTP_TARGETS = ["https://cloudflare.com", "https://google.com"]

# Services to monitor
SERVICES = {
    "gravae-agent": {"critical": True, "port": 8888},
    "cloudflared": {"critical": True, "port": None},
    "gravae-buttons": {"critical": True, "port": None, "alert_only": True},  # Alert but don't auto-restart
    "shinobi": {"critical": True, "port": 8080, "pm2": True, "pm2_names": ["camera", "cron"]},  # Shinobi via pm2
    "mariadb": {"critical": True, "port": 3306},  # MariaDB database server
}

# Webhook configuration
WEBHOOK_SECRET = "b36d1655-99ea-45b1-a627-984eb7e376a9"
WEBHOOK_URLS = {
    "gravae": "https://api.gravae.io/webhooks/phoenix/incidents",
    "replayme": "https://api.replayme.io/webhooks/phoenix/incidents",
}
WEBHOOK_SEND_INTERVAL = 300  # Send pending alerts every 5 minutes
WEBHOOK_MAX_RETRIES = 3
WEBHOOK_TIMEOUT = 10

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

# === Offline Event Tracker ===
# Persists (start_at, end_at, cause) transitions so OPS can show
# "historico de offline" on the ticket Device tab. Causes:
#   - power:   Pi was off. Detected when Phoenix starts up and finds an
#              open event still in the DB → we only get here if the process
#              died without a clean shutdown, which for a Pi basically means
#              power loss. Also classifies events that span a boot.
#   - network: Pi stayed up but lost connectivity (ping/http to external
#              targets failed). Detected via ConnectivitySentinel transitions.
#   - unknown: fallback when we can't classify.
class OfflineEventTracker:
    def __init__(self, db_path=ALERT_DB):
        self.db_path = db_path
        self._init_db()
        self._close_dangling_as_power()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS offline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_at TEXT NOT NULL,
                end_at TEXT,
                cause TEXT NOT NULL DEFAULT 'unknown',
                evidence TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def _close_dangling_as_power(self):
        # Phoenix just booted. Any offline_event with end_at=NULL was
        # left open by the previous process → Pi rebooted → assume power.
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute(
                "SELECT id, start_at FROM offline_events WHERE end_at IS NULL"
            )
            rows = cur.fetchall()
            if rows:
                now_iso = datetime.now().isoformat()
                evidence = f"phoenix restart detected at {now_iso}; end inferred"
                conn.execute(
                    "UPDATE offline_events SET end_at = ?, cause = 'power', "
                    "evidence = COALESCE(evidence || ' | ', '') || ? "
                    "WHERE end_at IS NULL",
                    (now_iso, evidence),
                )
                conn.commit()
                for row_id, start_at in rows:
                    log.info(f"[offline-tracker] closed dangling event id={row_id} "
                             f"start={start_at} as cause=power")
            conn.close()
        except Exception as e:
            log.debug(f"[offline-tracker] _close_dangling_as_power error: {e}")

    def mark_offline(self, evidence=""):
        # Idempotent: only inserts if there isn't an already-open event.
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute(
                "SELECT id FROM offline_events WHERE end_at IS NULL LIMIT 1"
            )
            if cur.fetchone() is None:
                conn.execute(
                    "INSERT INTO offline_events (start_at, cause, evidence) "
                    "VALUES (?, 'network', ?)",
                    (datetime.now().isoformat(), evidence or "connectivity probe failed"),
                )
                conn.commit()
                log.info("[offline-tracker] offline event opened (cause=network)")
            conn.close()
        except Exception as e:
            log.debug(f"[offline-tracker] mark_offline error: {e}")

    def mark_online(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "UPDATE offline_events SET end_at = ? WHERE end_at IS NULL",
                (datetime.now().isoformat(),),
            )
            conn.commit()
            conn.close()
            log.info("[offline-tracker] offline event closed (connectivity restored)")
        except Exception as e:
            log.debug(f"[offline-tracker] mark_online error: {e}")

    def list_events(self, days=10):
        days = max(1, min(30, int(days)))
        try:
            conn = sqlite3.connect(self.db_path)
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            cursor = conn.execute(
                "SELECT start_at, end_at, cause, evidence FROM offline_events "
                "WHERE start_at >= ? ORDER BY id DESC",
                (cutoff,),
            )
            events = []
            for start_at, end_at, cause, evidence in cursor:
                duration = None
                if end_at:
                    try:
                        duration = (datetime.fromisoformat(end_at)
                                    - datetime.fromisoformat(start_at)).total_seconds()
                    except Exception:
                        duration = None
                events.append({
                    "startAt": start_at,
                    "endAt": end_at,
                    "durationSeconds": duration,
                    "cause": cause or "unknown",
                    "evidence": evidence,
                })
            conn.close()
            return events
        except Exception as e:
            log.debug(f"[offline-tracker] list_events error: {e}")
            return []

    def cleanup_old(self, days=60):
        try:
            conn = sqlite3.connect(self.db_path)
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            conn.execute(
                "DELETE FROM offline_events WHERE end_at IS NOT NULL AND end_at < ?",
                (cutoff,),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            log.debug(f"[offline-tracker] cleanup_old error: {e}")

offline_tracker = OfflineEventTracker()

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

    def _get_arena_user(self):
        """Detect the arena user (gravae or replayme) from device config or home dirs."""
        try:
            if CONFIG_PATH.exists():
                config = json.loads(CONFIG_PATH.read_text())
                return config.get("arenaUser", "gravae")
        except:
            pass
        if Path("/home/replayme").exists():
            return "replayme"
        return "gravae"

    def _run_pm2_jlist(self):
        """Run `pm2 jlist` as root under the canonical PM2_HOME.

        Never falls back to `sudo -u <arena_user> pm2`: that spawns a second PM2
        God daemon under /home/<user>/.pm2 just to list — the root cause of Bug6
        (multiple pm2 daemons). Stray daemons are cleaned by _cleanup_duplicate_pm2_daemons()."""
        try:
            result = subprocess.run(
                ["pm2", "jlist"],
                capture_output=True, text=True, timeout=10,
                env=_pm2_env()
            )
            if result.returncode == 0 and result.stdout.strip():
                procs = json.loads(result.stdout)
                if procs:
                    return procs
        except Exception:
            pass
        return []

    def check_pm2_process(self, service_name):
        """Check if PM2 processes for a service are running.
        Uses pm2_names from SERVICES config to find the correct process names.
        Checks both root and arena user PM2 instances."""
        try:
            processes = self._run_pm2_jlist()
            if not processes:
                return False
            pm2_names = SERVICES.get(service_name, {}).get("pm2_names", [service_name])
            for target_name in pm2_names:
                found = False
                for proc in processes:
                    if proc.get("name", "").lower() == target_name.lower():
                        if proc.get("pm2_env", {}).get("status") == "online":
                            found = True
                            break
                if not found:
                    return False
            return True
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

    def _find_shinobi_dir(self):
        """Find the Shinobi installation directory"""
        for d in SHINOBI_DIRS:
            if d.exists() and (d / "camera.js").exists():
                return d
        return None

    def _get_pm2_processes(self):
        """Get list of PM2 processes from the canonical root PM2_HOME."""
        return self._run_pm2_jlist()

    def _cleanup_duplicate_pm2_daemons(self):
        """Kill any PM2 God daemon NOT running under the canonical PM2_HOME (/root/.pm2).

        Fixes Bug6 at the source: stray daemons (usually spawned under
        /home/<arena_user>/.pm2 by an old `sudo -u <user> pm2` call) hold orphan
        camera/cron processes and break resurrection on reboot. PM2 encodes its home
        in the God Daemon process title: "PM2 v<ver>: God Daemon (/home/x/.pm2)"."""
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,args"],
                capture_output=True, text=True, timeout=10
            )
        except Exception as e:
            log.debug(f"[pm2-dedup] ps failed: {e}")
            return
        killed = 0
        for line in result.stdout.splitlines():
            if "God Daemon" not in line or "PM2" not in line:
                continue
            # Extract the home path from the trailing "(...)" of the process title.
            home = None
            if line.rstrip().endswith(")") and "(" in line:
                home = line[line.rfind("(") + 1:line.rfind(")")].strip()
            if not home or home == PM2_HOME:
                continue  # canonical daemon (or home unknown) — leave it alone
            try:
                pid = int(line.split(None, 1)[0])
                os.kill(pid, signal.SIGKILL)
                killed += 1
                log.warning(f"[pm2-dedup] killed stray PM2 daemon pid={pid} home={home}")
            except Exception as e:
                log.error(f"[pm2-dedup] failed to kill stray daemon '{line.strip()}': {e}")
        if killed:
            alerts.add(
                "pm2_duplicate_cleaned",
                "warning",
                f"Removed {killed} stray PM2 daemon(s) not under {PM2_HOME}",
                {"killed": killed}
            )

    def restart_pm2_process(self, service_name):
        """Restart PM2 processes for a service, with fallback to re-register if PM2 list is empty.
        Uses cooldown and max attempts like restart_service()."""
        now = time.time()
        attempts, last_attempt = self.restart_attempts.get(service_name, (0, 0))

        # Check cooldown
        if now - last_attempt < SERVICE_RESTART_COOLDOWN:
            log.debug(f"PM2 service {service_name} in cooldown, skipping restart")
            return False

        # Check max attempts
        if attempts >= SERVICE_RESTART_MAX_ATTEMPTS:
            log.warning(f"PM2 service {service_name} exceeded max restart attempts ({attempts})")
            alerts.add(
                "service_restart_failed",
                "critical",
                f"PM2 service {service_name} failed after {attempts} restart attempts",
                {"service": service_name, "attempts": attempts}
            )
            return False

        pm2_names = SERVICES.get(service_name, {}).get("pm2_names", [service_name])

        # Repair/prevent Bug6 before doing anything: remove any PM2 God daemon that
        # is NOT the canonical /root/.pm2 one, so we always act on a single daemon.
        self._cleanup_duplicate_pm2_daemons()

        processes = self._get_pm2_processes()
        registered_names = {p.get("name", "").lower() for p in processes}

        # Check if any of the expected PM2 processes are registered
        any_registered = any(n.lower() in registered_names for n in pm2_names)

        if any_registered:
            # Processes exist in PM2 — just restart them (always root + canonical PM2_HOME)
            log.info(f"Restarting PM2 processes for {service_name}: {pm2_names} (attempt {attempts + 1})")
            for pm2_name in pm2_names:
                try:
                    result = subprocess.run(
                        ["pm2", "restart", pm2_name],
                        capture_output=True, text=True, timeout=30,
                        env=_pm2_env()
                    )
                    if result.returncode != 0:
                        log.error(f"pm2 restart {pm2_name} failed: {result.stderr.strip()}")
                except Exception as e:
                    log.error(f"Error running pm2 restart {pm2_name}: {e}")
        else:
            # PM2 process list is empty or processes not registered — re-register from scratch.
            # Always register as root under the canonical PM2_HOME (never `sudo -u <user>`,
            # which would spawn a second God daemon under that user's home = Bug6).
            shinobi_dir = self._find_shinobi_dir()
            if not shinobi_dir:
                log.error(f"Cannot find Shinobi directory to re-register PM2 processes")
                self.restart_attempts[service_name] = (attempts + 1, now)
                return False

            log.warning(f"PM2 processes for {service_name} not registered, re-registering as root (attempt {attempts + 1})")

            for pm2_name in pm2_names:
                script = shinobi_dir / f"{pm2_name}.js"
                if not script.exists():
                    log.error(f"PM2 script not found: {script}")
                    continue
                try:
                    # CRITICAL: cwd must be shinobi_dir so PM2 saves pm_cwd=/home/Shinobi.
                    # Shinobi resolves s.location.languages from process.cwd(), so a wrong
                    # cwd (e.g. /opt/gravae-agent) makes camera.js crash loop trying to read
                    # /opt/gravae-agent/languages/en_CA.json.
                    result = subprocess.run(
                        ["pm2", "start", str(script), "--name", pm2_name],
                        capture_output=True, text=True, timeout=30,
                        cwd=str(shinobi_dir), env=_pm2_env()
                    )
                    if result.returncode != 0:
                        log.error(f"pm2 start {script} failed: {result.stderr.strip()}")
                    else:
                        log.info(f"PM2 process {pm2_name} registered from {script}")
                except Exception as e:
                    log.error(f"Error running pm2 start for {pm2_name}: {e}")

            # Save PM2 process list so it persists across reboots
            try:
                subprocess.run(["pm2", "save"], capture_output=True, timeout=10,
                               cwd=str(shinobi_dir), env=_pm2_env())
                log.info("PM2 process list saved")
            except Exception:
                log.warning("Failed to save PM2 process list")

        self.restart_attempts[service_name] = (attempts + 1, now)

        # Wait and verify
        time.sleep(5)
        port = SERVICES.get(service_name, {}).get("port")
        if port and self.check_port(port):
            log.info(f"PM2 service {service_name} recovered successfully")
            alerts.add(
                "service_restarted",
                "info",
                f"PM2 service {service_name} was restarted",
                {"service": service_name, "attempt": attempts + 1}
            )
            return True
        elif self.check_pm2_process(service_name):
            log.info(f"PM2 service {service_name} processes online (port not yet ready)")
            return True
        else:
            log.error(f"PM2 service {service_name} failed to recover after attempt {attempts + 1}")
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
            if prev_status is None and not is_running:
                # First check after startup — service already down
                severity = "critical" if config.get("critical") else "warning"
                log.warning(f"Service {service_name} found down on startup")
                alerts.add("service_down", severity, f"Service {service_name} found down on startup")
                status_changed = True
            elif prev_status is not None and prev_status != is_running:
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

# === Shinobi Crash-Loop Detector ===
# Detects the "silent event-recording death" bug in Shinobi CE where
# libs/events/utils.js (~line 645) writes 'q' to a closed ffmpeg stdin after
# the event-based recording timeout fires. The write emits EPIPE asynchronously,
# bypasses the try/catch, and is swallowed by Shinobi's global uncaughtException
# handler — leaving `activeMonitor.eventBasedRecording[fileTime]` in a corrupted
# state. Subsequent motion triggers register events but never spawn a new ffmpeg,
# so no videos are saved until camera.js is restarted.
class ShinobiCrashLoopDetector:
    LOG_PATH = Path("/root/.pm2/logs/camera-error.log")
    STATE_FILE = LOG_DIR / "shinobi_epipe.state"
    RESTART_COOLDOWN = 15 * 60  # 15 min between auto-restarts
    MAX_CHUNK_BYTES = 2 * 1024 * 1024  # cap read to 2MB per check

    def __init__(self, service_guardian):
        self.guardian = service_guardian
        self.last_restart = 0
        # On first run (no persisted offset), skip the existing log backlog —
        # we only want to react to NEW crashes, not re-trigger on historical
        # EPIPE entries from before the detector was deployed.
        persisted = self._load_offset()
        if persisted is None:
            try:
                self.last_offset = self.LOG_PATH.stat().st_size if self.LOG_PATH.exists() else 0
                self._save_offset(self.last_offset)
                log.info(f"[shinobi-epipe] first run, seeking to end of log (offset={self.last_offset})")
            except Exception:
                self.last_offset = 0
        else:
            self.last_offset = persisted

    def _load_offset(self):
        try:
            if self.STATE_FILE.exists():
                return int(self.STATE_FILE.read_text().strip())
        except Exception:
            pass
        return None

    def _save_offset(self, offset):
        try:
            self.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            self.STATE_FILE.write_text(str(offset))
        except Exception as e:
            log.debug(f"[shinobi-epipe] failed to persist offset: {e}")

    def check(self):
        if not self.LOG_PATH.exists():
            return False
        try:
            size = self.LOG_PATH.stat().st_size
            # Handle log rotation / truncation
            if size < self.last_offset:
                self.last_offset = 0
            if size == self.last_offset:
                return False

            read_from = self.last_offset
            # Cap the chunk we read so a huge backlog doesn't OOM Phoenix
            if size - read_from > self.MAX_CHUNK_BYTES:
                read_from = size - self.MAX_CHUNK_BYTES

            with open(self.LOG_PATH, "rb") as f:
                f.seek(read_from)
                chunk = f.read(size - read_from).decode("utf-8", errors="replace")
            self.last_offset = size
            self._save_offset(self.last_offset)

            # Fingerprint: all three markers must appear in the new window.
            # Keeps false-positives at zero — generic EPIPE in other code paths
            # won't trigger a restart.
            if ("Uncaught Exception" in chunk
                    and "EPIPE" in chunk
                    and "events/utils.js" in chunk):
                now = time.time()
                if now - self.last_restart < self.RESTART_COOLDOWN:
                    log.warning("[shinobi-epipe] detected again within cooldown; skipping restart")
                    return False
                log.warning("[shinobi-epipe] Shinobi event-recording crash detected — restarting camera.js")
                alerts.add(
                    "shinobi_epipe_recovery",
                    "warning",
                    "Shinobi event-recording crash detected (EPIPE em events/utils.js) — camera.js reiniciado automaticamente",
                    {"log_path": str(self.LOG_PATH)}
                )
                ok = self.guardian.restart_pm2_process("shinobi")
                if ok:
                    self.last_restart = now
                    log.info("[shinobi-epipe] camera.js restart completed")
                else:
                    log.error("[shinobi-epipe] camera.js restart failed")
                return bool(ok)
        except Exception as e:
            log.debug(f"[shinobi-epipe] check error: {e}")
        return False

# === Connectivity Sentinel ===
class ConnectivitySentinel:
    def __init__(self):
        self.is_online = True
        self.offline_since = None
        self.last_successful_ping = datetime.now()
        self.escalation_level = 0  # 0=none, 1=cloudflared, 2=networking, 3=dhcp_fallback, 4=reboot
        self.actions_taken = []
        self.reboot_timestamps = []  # timestamps of reboots in last 24h
        self.dhcp_fallback_attempted = False  # Only one DHCP fallback per offline event
        self._dhcp_fallback_last_attempt = None  # persisted across reboots for cooldown
        self._dhcp_fallback_method = None  # 'nmcli' or 'dhcpcd', set when fallback runs
        self._load_reboot_state()
        self._load_dhcp_fallback_state()

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

    def _get_primary_interface(self):
        """Get the primary network interface name (usually eth0)."""
        try:
            result = subprocess.run(
                ['ip', '-j', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout:
                routes = json.loads(result.stdout)
                if routes:
                    return routes[0].get('dev', 'eth0')
        except:
            pass
        return 'eth0'

    def _get_nm_connection_name(self, interface):
        """Get the NetworkManager connection name for an interface."""
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show', '--active'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    name, dev = line.rsplit(':', 1)
                    if dev.strip() == interface:
                        return name.strip()
        except:
            pass
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    name, dev = line.rsplit(':', 1)
                    if dev.strip() == interface:
                        return name.strip()
        except:
            pass
        return interface

    def _is_networkmanager_running(self):
        """Check if NetworkManager service is active. Returns False on dhcpcd-based Pis."""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'NetworkManager'],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() == 'active'
        except:
            return False

    def _is_static_ip_nmcli(self, interface):
        """Check static IP via NetworkManager (only valid when NM is running)."""
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'IP4.METHOD', 'device', 'show', interface],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return False
            return 'manual' in result.stdout.lower()
        except:
            return False

    def _dhcpcd_static_block_lines(self, interface):
        """Locate the 'interface <iface>' block in /etc/dhcpcd.conf containing a
        'static ip_address=' directive. Returns (start_idx, end_idx) where end is
        exclusive (next 'interface' line or EOF). (None, None) if absent.
        """
        if not DHCPCD_CONF.exists():
            return None, None
        try:
            lines = DHCPCD_CONF.read_text().splitlines()
            block_start = None
            for i, raw in enumerate(lines):
                stripped = raw.strip()
                if stripped.startswith('#'):
                    continue
                if stripped.startswith('interface '):
                    block_start = i if stripped == f'interface {interface}' else None
                elif block_start is not None and stripped.startswith('static ip_address='):
                    end = len(lines)
                    for j in range(block_start + 1, len(lines)):
                        s2 = lines[j].strip()
                        if s2.startswith('interface ') and not s2.startswith('#'):
                            end = j
                            break
                    return block_start, end
            return None, None
        except Exception as e:
            log.debug(f"[dhcpcd-fallback] read failed: {e}")
            return None, None

    def _dhcpcd_has_static(self, interface):
        """True if dhcpcd.conf has a 'static ip_address=' inside an 'interface <iface>' block."""
        s, _ = self._dhcpcd_static_block_lines(interface)
        return s is not None

    def _is_static_ip(self, interface):
        """Detect static IP across both supported backends (nmcli + dhcpcd)."""
        if self._is_networkmanager_running() and self._is_static_ip_nmcli(interface):
            return True
        return self._dhcpcd_has_static(interface)

    def _dhcpcd_get_static_config(self, interface):
        """Extract current static config from dhcpcd.conf for backup/alerts."""
        config = {
            'method': 'dhcpcd',
            'interface': interface,
            'timestamp': datetime.now().isoformat(),
        }
        s, e = self._dhcpcd_static_block_lines(interface)
        if s is None:
            return config
        try:
            block = DHCPCD_CONF.read_text().splitlines()[s:e]
            for line in block:
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue
                if stripped.startswith('static ip_address='):
                    config['ip'] = stripped.split('=', 1)[1].strip()
                elif stripped.startswith('static routers='):
                    config['gateway'] = stripped.split('=', 1)[1].strip()
                elif stripped.startswith('static domain_name_servers='):
                    config['dns'] = stripped.split('=', 1)[1].strip()
        except Exception as e:
            log.warning(f"[dhcpcd-fallback] could not parse static block: {e}")
        return config

    def _switch_dhcpcd_to_auto(self, interface):
        """Comment out the static block for `interface` in /etc/dhcpcd.conf, save a
        binary backup to DHCPCD_BACKUP, and restart dhcpcd. Idempotent — if already
        commented, returns False (nothing to do).
        """
        import shutil
        s, end = self._dhcpcd_static_block_lines(interface)
        if s is None:
            log.warning(f"[dhcpcd-fallback] no static block for {interface}, nothing to do")
            return False
        try:
            shutil.copy2(DHCPCD_CONF, DHCPCD_BACKUP)
            log.info(f"[dhcpcd-fallback] dhcpcd.conf backed up to {DHCPCD_BACKUP}")
        except Exception as e:
            log.error(f"[dhcpcd-fallback] backup failed: {e}")
            return False
        try:
            lines = DHCPCD_CONF.read_text().splitlines(keepends=True)
            for i in range(s, min(end, len(lines))):
                stripped = lines[i].lstrip()
                if stripped.startswith('#'):
                    continue
                if (stripped.startswith('interface ')
                        or stripped.startswith('static ip_address=')
                        or stripped.startswith('static routers=')
                        or stripped.startswith('static domain_name_servers=')):
                    lines[i] = f'# [phoenix-dhcp-fallback] {lines[i]}'
            DHCPCD_CONF.write_text(''.join(lines))
            log.info(f"[dhcpcd-fallback] commented static block for {interface}")
        except Exception as e:
            log.error(f"[dhcpcd-fallback] failed to rewrite dhcpcd.conf: {e}")
            # Try to restore the backup we just made
            try:
                shutil.copy2(DHCPCD_BACKUP, DHCPCD_CONF)
            except Exception:
                pass
            return False
        try:
            subprocess.run(['systemctl', 'restart', 'dhcpcd'],
                          capture_output=True, timeout=30)
            return True
        except Exception as e:
            log.error(f"[dhcpcd-fallback] dhcpcd restart failed: {e}")
            return False

    def _restore_dhcpcd_static(self):
        """Restore /etc/dhcpcd.conf from DHCPCD_BACKUP and restart dhcpcd."""
        import shutil
        if not DHCPCD_BACKUP.exists():
            log.warning("[dhcpcd-fallback] no backup file to restore")
            return False
        try:
            shutil.copy2(DHCPCD_BACKUP, DHCPCD_CONF)
            subprocess.run(['systemctl', 'restart', 'dhcpcd'],
                          capture_output=True, timeout=30)
            log.info("[dhcpcd-fallback] static config restored from backup")
            return True
        except Exception as e:
            log.error(f"[dhcpcd-fallback] restore failed: {e}")
            return False

    def _load_dhcp_fallback_state(self):
        """Load persistent DHCP fallback state. If last attempt was within
        DHCP_FALLBACK_COOLDOWN_HOURS, mark `dhcp_fallback_attempted=True` so we
        don't retry across a reboot — the only loop guard for this escalation.
        """
        try:
            if DHCP_FALLBACK_STATE_FILE.exists():
                data = json.loads(DHCP_FALLBACK_STATE_FILE.read_text())
                ts = data.get('last_attempt_at')
                if ts:
                    self._dhcp_fallback_last_attempt = datetime.fromisoformat(ts)
                    self._dhcp_fallback_method = data.get('method')
                    age_h = (datetime.now() - self._dhcp_fallback_last_attempt).total_seconds() / 3600
                    if age_h < DHCP_FALLBACK_COOLDOWN_HOURS:
                        self.dhcp_fallback_attempted = True
                        log.info(
                            f"[dhcp-fallback] cooldown active "
                            f"({age_h:.1f}h since last {self._dhcp_fallback_method or 'attempt'}; "
                            f"min={DHCP_FALLBACK_COOLDOWN_HOURS}h)"
                        )
        except Exception as e:
            log.debug(f"[dhcp-fallback] could not load state: {e}")

    def _save_dhcp_fallback_state(self, method, outcome):
        """Persist last attempt timestamp + outcome (cross-reboot cooldown)."""
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            DHCP_FALLBACK_STATE_FILE.write_text(json.dumps({
                'last_attempt_at': datetime.now().isoformat(),
                'method': method,
                'outcome': outcome,
                'version': VERSION,
            }, indent=2))
            self._dhcp_fallback_last_attempt = datetime.now()
            self._dhcp_fallback_method = method
        except Exception as e:
            log.error(f"[dhcp-fallback] could not save state: {e}")

    def _get_current_network_config(self, interface, conn_name):
        """Get current network configuration for backup."""
        config = {
            'interface': interface,
            'connection': conn_name,
            'timestamp': datetime.now().isoformat(),
        }
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'IP4.ADDRESS', 'device', 'show', interface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if 'IP4.ADDRESS' in line:
                    config['ip'] = line.split(':', 1)[1].strip()
                    break
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'IP4.GATEWAY', 'device', 'show', interface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if 'IP4.GATEWAY' in line:
                    config['gateway'] = line.split(':', 1)[1].strip()
                    break
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'IP4.DNS', 'device', 'show', interface],
                capture_output=True, text=True, timeout=5
            )
            dns_servers = []
            for line in result.stdout.strip().split('\n'):
                if 'IP4.DNS' in line:
                    dns_servers.append(line.split(':', 1)[1].strip())
            if dns_servers:
                config['dns'] = ','.join(dns_servers)
        except Exception as e:
            log.warning(f"[dhcp-fallback] Could not read full network config: {e}")
        return config

    def _restore_static_config(self, backup):
        """Restore static IP configuration from backup."""
        conn_name = backup.get('connection', 'eth0')
        ip = backup.get('ip', '')
        gateway = backup.get('gateway', '')
        dns = backup.get('dns', '')
        log.info(f"[dhcp-fallback] Restoring static config: IP={ip}, GW={gateway}, DNS={dns}")
        try:
            commands = [
                ['sudo', 'nmcli', 'connection', 'modify', conn_name, 'ipv4.method', 'manual'],
                ['sudo', 'nmcli', 'connection', 'modify', conn_name, 'ipv4.addresses', ip],
                ['sudo', 'nmcli', 'connection', 'modify', conn_name, 'ipv4.gateway', gateway],
            ]
            if dns:
                commands.append(['sudo', 'nmcli', 'connection', 'modify', conn_name, 'ipv4.dns', dns])
            for cmd in commands:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    log.error(f"[dhcp-fallback] Restore failed: {' '.join(cmd)} -> {result.stderr}")
            subprocess.run(['sudo', 'nmcli', 'connection', 'down', conn_name],
                          capture_output=True, text=True, timeout=10)
            subprocess.run(['sudo', 'nmcli', 'connection', 'up', conn_name],
                          capture_output=True, text=True, timeout=10)
            log.info("[dhcp-fallback] Static config restored successfully")
            return True
        except Exception as e:
            log.error(f"[dhcp-fallback] Failed to restore static config: {e}")
            return False

    def try_dhcp_fallback(self):
        """Try switching to DHCP when static IP has no connectivity.
        Dispatches to nmcli (NetworkManager) or dhcpcd backend automatically.
        At most one attempt per 24h (cooldown persisted in DHCP_FALLBACK_STATE_FILE)
        — that's the loop guard against repeated reboot-then-flap cycles.
        Restores the previous static config if DHCP doesn't help.
        """
        if self.dhcp_fallback_attempted:
            return False

        if NETWORK_CHANGE_KILLSWITCH.exists():
            log.info("[dhcp-fallback] Kill switch active (/etc/gravae/no_network_change), skipping")
            alerts.add("dhcp_fallback_skipped", "info",
                "DHCP fallback skipped: kill switch active",
                {"offline_minutes": self.get_offline_minutes()})
            return False

        interface = self._get_primary_interface()
        nm_running = self._is_networkmanager_running()
        nm_static = nm_running and self._is_static_ip_nmcli(interface)
        dhcpcd_static = self._dhcpcd_has_static(interface)

        if not nm_static and not dhcpcd_static:
            log.info(f"[dhcp-fallback] Interface {interface} is already DHCP "
                     f"(nm_running={nm_running}), skipping")
            return False

        # Prefer the backend that actually has the static config.
        method = 'nmcli' if nm_static else 'dhcpcd'
        offline_min = self.get_offline_minutes()
        self.dhcp_fallback_attempted = True
        log.warning(f"[dhcp-fallback] Attempting after {offline_min:.0f}min offline "
                    f"(interface={interface}, method={method})")

        if method == 'nmcli':
            outcome = self._try_dhcp_fallback_nmcli(interface, offline_min)
        else:
            outcome = self._try_dhcp_fallback_dhcpcd(interface, offline_min)

        self._save_dhcp_fallback_state(method, 'success' if outcome else 'failed')
        return outcome

    def _try_dhcp_fallback_nmcli(self, interface, offline_min):
        """nmcli-based DHCP fallback (legacy path, used on NetworkManager Pis)."""
        conn_name = self._get_nm_connection_name(interface)
        log.info(f"[dhcp-fallback/nmcli] connection={conn_name}")

        # Backup current config
        backup = self._get_current_network_config(interface, conn_name)
        try:
            Path("/etc/gravae").mkdir(parents=True, exist_ok=True)
            NETWORK_BACKUP_FILE.write_text(json.dumps(backup, indent=2))
            log.info(f"[dhcp-fallback/nmcli] Config backed up to {NETWORK_BACKUP_FILE}")
        except Exception as e:
            log.error(f"[dhcp-fallback/nmcli] Failed to save backup, aborting: {e}")
            alerts.add("dhcp_fallback_error", "warning",
                f"DHCP fallback aborted: could not save backup ({e})",
                {"offline_minutes": offline_min})
            return False

        # Switch to DHCP
        try:
            for cmd in [
                ['sudo', 'nmcli', 'connection', 'modify', conn_name, 'ipv4.method', 'auto'],
                ['sudo', 'nmcli', 'connection', 'modify', conn_name, 'ipv4.addresses', ''],
                ['sudo', 'nmcli', 'connection', 'modify', conn_name, 'ipv4.gateway', ''],
                ['sudo', 'nmcli', 'connection', 'modify', conn_name, 'ipv4.dns', ''],
            ]:
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            subprocess.run(['sudo', 'nmcli', 'connection', 'down', conn_name],
                          capture_output=True, text=True, timeout=10)
            subprocess.run(['sudo', 'nmcli', 'connection', 'up', conn_name],
                          capture_output=True, text=True, timeout=10)
            log.info("[dhcp-fallback/nmcli] Switched to DHCP, waiting 60s...")
        except Exception as e:
            log.error(f"[dhcp-fallback/nmcli] Failed to switch to DHCP: {e}")
            self._restore_static_config(backup)
            return False

        time.sleep(60)

        if self.check_connectivity():
            log.warning("[dhcp-fallback/nmcli] RESTORED connectivity!")
            alerts.add("dhcp_fallback_success", "warning",
                f"Fallback DHCP (nmcli) restaurou conectividade após {offline_min:.0f}min offline. "
                f"Config anterior salva em {NETWORK_BACKUP_FILE}",
                {"offline_minutes": offline_min, "method": "nmcli",
                 "backup": str(NETWORK_BACKUP_FILE)})
            self.actions_taken.append(("dhcp_fallback_nmcli_success", datetime.now().isoformat()))
            return True
        else:
            log.warning("[dhcp-fallback/nmcli] Did NOT restore connectivity, reverting")
            self._restore_static_config(backup)
            alerts.add("dhcp_fallback_failed", "warning",
                f"DHCP fallback (nmcli) falhou após {offline_min:.0f}min offline. Config restaurada.",
                {"offline_minutes": offline_min, "method": "nmcli"})
            self.actions_taken.append(("dhcp_fallback_nmcli_failed", datetime.now().isoformat()))
            return False

    def _try_dhcp_fallback_dhcpcd(self, interface, offline_min):
        """dhcpcd-based DHCP fallback for Pis without NetworkManager.
        Comments the static block, restarts dhcpcd, validates connectivity.
        Reverts the file from .gravae-backup if it didn't help.
        """
        # Save semantic backup (JSON) for alerting/observability
        backup = self._dhcpcd_get_static_config(interface)
        try:
            Path("/etc/gravae").mkdir(parents=True, exist_ok=True)
            NETWORK_BACKUP_FILE.write_text(json.dumps(backup, indent=2))
            log.info(f"[dhcp-fallback/dhcpcd] semantic backup -> {NETWORK_BACKUP_FILE}")
        except Exception as e:
            log.warning(f"[dhcp-fallback/dhcpcd] could not save semantic backup: {e}")

        if not self._switch_dhcpcd_to_auto(interface):
            log.error("[dhcp-fallback/dhcpcd] switch to DHCP failed, attempting restore")
            self._restore_dhcpcd_static()
            alerts.add("dhcp_fallback_error", "warning",
                "DHCP fallback (dhcpcd) abortado: erro ao reescrever dhcpcd.conf",
                {"offline_minutes": offline_min, "method": "dhcpcd"})
            return False

        log.info("[dhcp-fallback/dhcpcd] dhcpcd restarted, waiting 60s for lease...")
        time.sleep(60)

        if self.check_connectivity():
            log.warning("[dhcp-fallback/dhcpcd] RESTORED connectivity!")
            alerts.add("dhcp_fallback_success", "warning",
                f"Fallback DHCP (dhcpcd) restaurou conectividade após {offline_min:.0f}min offline. "
                f"Backup do dhcpcd.conf em {DHCPCD_BACKUP}",
                {"offline_minutes": offline_min, "method": "dhcpcd",
                 "backup": str(DHCPCD_BACKUP), "previous_static": backup})
            self.actions_taken.append(("dhcp_fallback_dhcpcd_success", datetime.now().isoformat()))
            return True
        else:
            log.warning("[dhcp-fallback/dhcpcd] Did NOT restore connectivity, reverting")
            self._restore_dhcpcd_static()
            alerts.add("dhcp_fallback_failed", "warning",
                f"DHCP fallback (dhcpcd) falhou após {offline_min:.0f}min offline. Config restaurada.",
                {"offline_minutes": offline_min, "method": "dhcpcd"})
            self.actions_taken.append(("dhcp_fallback_dhcpcd_failed", datetime.now().isoformat()))
            return False

    def _load_reboot_state(self):
        """Load reboot timestamps from persistent file."""
        try:
            if REBOOT_STATE_FILE.exists():
                data = json.loads(REBOOT_STATE_FILE.read_text())
                self.reboot_timestamps = data.get("timestamps", [])
                # Prune entries older than 24h
                cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
                self.reboot_timestamps = [t for t in self.reboot_timestamps if t > cutoff]
        except Exception as e:
            log.debug(f"Could not load reboot state: {e}")
            self.reboot_timestamps = []

    def _save_reboot_state(self):
        """Save reboot timestamps to persistent file."""
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            REBOOT_STATE_FILE.write_text(json.dumps({
                "timestamps": self.reboot_timestamps,
                "version": VERSION,
            }))
        except Exception as e:
            log.error(f"Could not save reboot state: {e}")

    def _get_uptime_seconds(self):
        """Get system uptime in seconds."""
        try:
            with open("/proc/uptime", "r") as f:
                return float(f.read().split()[0])
        except:
            return 999999  # Assume long uptime if we can't read

    def _can_reboot(self):
        """Check if it's safe to reboot."""
        # Anti boot-loop: don't reboot if system just started
        uptime = self._get_uptime_seconds()
        if uptime < MIN_UPTIME_BEFORE_REBOOT:
            log.warning(f"Reboot blocked: uptime only {uptime:.0f}s (need {MIN_UPTIME_BEFORE_REBOOT}s)")
            return False

        # Max reboots per day
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        recent_reboots = [t for t in self.reboot_timestamps if t > cutoff]
        if len(recent_reboots) >= MAX_REBOOTS_PER_DAY:
            log.warning(f"Reboot blocked: already {len(recent_reboots)} reboots in last 24h (max {MAX_REBOOTS_PER_DAY})")
            return False

        return True

    def reboot_system(self):
        """Reboot the system as last resort after extended connectivity loss."""
        if not self._can_reboot():
            return False

        offline_min = self.get_offline_minutes()
        reboot_count = len(self.reboot_timestamps) + 1
        log.warning(f"Escalation: REBOOTING system after {offline_min:.0f}min offline (reboot {reboot_count}/{MAX_REBOOTS_PER_DAY} today)")

        # Record this reboot BEFORE rebooting
        self.reboot_timestamps.append(datetime.now().isoformat())
        self._save_reboot_state()

        alerts.add(
            "system_reboot",
            "critical",
            f"Reiniciando sistema após {offline_min:.0f} min sem internet (reboot {reboot_count}/{MAX_REBOOTS_PER_DAY} hoje)",
            {"offline_minutes": offline_min, "reboot_count": reboot_count, "uptime": self._get_uptime_seconds()}
        )

        self.actions_taken.append(("reboot", datetime.now().isoformat()))

        try:
            # Sync filesystem before reboot
            subprocess.run(["sync"], timeout=10)
            # Use systemctl reboot (clean shutdown)
            subprocess.run(["systemctl", "reboot"], timeout=10)
        except Exception as e:
            log.error(f"Reboot failed: {e}")
            return False

        return True

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
            self.dhcp_fallback_attempted = False
            return True

        # We're offline
        if was_online:
            self.offline_since = datetime.now()
            log.warning("Connectivity lost")
            alerts.add("connectivity_lost", "warning", "Internet connectivity lost")

        offline_minutes = self.get_offline_minutes()

        # Escalation: cloudflared(30m) → networking(60m) → DHCP fallback(120m) → reboot(240m)
        if offline_minutes >= ESCALATION_REBOOT and self.escalation_level < 4:
            # Level 4: Reboot after 4 hours offline (with safety checks)
            self.escalation_level = 4
            self.reboot_system()

        elif offline_minutes >= ESCALATION_DHCP_FALLBACK and self.escalation_level < 3:
            # Level 3: Try DHCP fallback after 2 hours (only for static IP interfaces)
            self.escalation_level = 3
            self.try_dhcp_fallback()

        elif offline_minutes >= ESCALATION_RESTART_NETWORKING and self.escalation_level < 2:
            self.escalation_level = 2
            self.restart_networking()

        elif offline_minutes >= ESCALATION_RESTART_CLOUDFLARED and self.escalation_level < 1:
            self.escalation_level = 1
            self.restart_cloudflared()

        # After Level 4 (reboot attempted), log periodically
        if offline_minutes >= ESCALATION_REBOOT and self.escalation_level >= 4:
            hours_offline = offline_minutes / 60
            if int(offline_minutes) % 30 == 0:
                log.warning(f"Extended connectivity loss: {hours_offline:.1f}h offline. "
                           f"Reboot was attempted. Waiting for internet to return.")

        return False

# NetworkRecovery REMOVED in v1.9.0 - modifying network config is too dangerous.
# Phoenix will NEVER touch dhcpcd.conf or switch between DHCP/static IP.
# DHCP fallback ADDED in v1.11.0 with safety: backup+restore, kill switch, 1 attempt per cycle.
# Reboot RE-ADDED in v1.10.0 with safety: 4h threshold, 3/day limit, 5min uptime guard.

# === Resource Monitor ===
class ResourceMonitor:
    def __init__(self):
        self.undervoltage_alerted = False  # Avoid spamming alerts
        self.last_voltage_check = 0  # Timestamp for daily voltage check
        self.last_speed_test = 0  # Timestamp for speed test
        self.download_speed_mbps = None  # Last measured download speed
        self.upload_speed_mbps = None    # Last measured upload speed (v1.16.0)
        # Thresholds (v1.16.0): upload é o gargalo real pra arenas Gravae
        # (gravam vídeo pra cloud). slow se download < 30 OU upload < 5;
        # very_slow se download < 10 OU upload < 1.
        self.slow_internet = False
        self.very_slow_internet = False

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

    def _run_speedtest(self):
        """Run speedtest-cli measuring download AND upload. Returns (download_mbps, upload_mbps) or (None, None)."""
        try:
            result = subprocess.run(
                ['speedtest-cli', '--simple', '--secure'],
                capture_output=True, text=True, timeout=180
            )
        except FileNotFoundError:
            # Install speedtest-cli and retry once
            try:
                subprocess.run(['pip3', 'install', 'speedtest-cli'], capture_output=True, timeout=30)
                result = subprocess.run(
                    ['speedtest-cli', '--simple', '--secure'],
                    capture_output=True, text=True, timeout=180
                )
            except Exception as e:
                log.debug(f"Failed to install/run speedtest-cli: {e}")
                return None, None
        except Exception as e:
            log.debug(f"speedtest-cli failed: {e}")
            return None, None

        if result.returncode != 0:
            return None, None

        download = None
        upload = None
        for line in result.stdout.strip().split('\n'):
            try:
                if line.startswith('Download:'):
                    download = round(float(line.split()[1]), 2)
                elif line.startswith('Upload:'):
                    upload = round(float(line.split()[1]), 2)
            except (IndexError, ValueError):
                pass
        return download, upload

    def check_speed(self):
        """Speed test via speedtest-cli measuring both download and upload (v1.16.0).

        Thresholds chosen for Gravae arenas which upload video to cloud:
          - slow_internet:      download < 30 Mbps  OR  upload < 5 Mbps
          - very_slow_internet: download < 10 Mbps  OR  upload < 1 Mbps
        Upload é o gargalo real — antes a gente só media download e perdia
        casos como a Azulina (download 7 Mbps OK pra operar, upload 0.28 Mbps
        inviabiliza envio de vídeo).
        """
        download, upload = self._run_speedtest()
        if download is None and upload is None:
            log.warning("Speed test failed")
            self.last_speed_test = time.time()
            return

        self.download_speed_mbps = download
        self.upload_speed_mbps = upload
        was_slow = self.slow_internet
        was_very_slow = self.very_slow_internet

        d_slow = download is not None and download < 30.0
        u_slow = upload is not None and upload < 5.0
        d_very = download is not None and download < 10.0
        u_very = upload is not None and upload < 1.0
        self.slow_internet = d_slow or u_slow
        self.very_slow_internet = d_very or u_very

        speed_str = f"↓{download} Mbps / ↑{upload} Mbps"
        if self.very_slow_internet and not was_very_slow:
            alerts.add("very_slow_internet", "critical", f"Internet muito lenta: {speed_str}",
                       {"download_mbps": download, "upload_mbps": upload})
        elif self.slow_internet and not was_slow:
            alerts.add("slow_internet", "warning", f"Internet lenta: {speed_str}",
                       {"download_mbps": download, "upload_mbps": upload})
        elif not self.slow_internet and was_slow:
            alerts.add("internet_recovered", "info", f"Internet normalizada: {speed_str}",
                       {"download_mbps": download, "upload_mbps": upload})

        label = '(muito lenta!)' if self.very_slow_internet else '(lenta)' if self.slow_internet else '(ok)'
        log.info(f"Speed test: {speed_str} {label}")
        try:
            import json as _json
            with open('/tmp/gravae_speed_test.json', 'w') as _f:
                _json.dump({
                    "download_mbps": download,
                    "upload_mbps": upload,
                    "speed_mbps": download,  # backwards compat (gravae_agent < v3.5)
                    "slow": self.slow_internet,
                    "very_slow": self.very_slow_internet,
                    "timestamp": time.time(),
                }, _f)
        except Exception:
            pass
        self.last_speed_test = time.time()

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

# === Webhook Sender ===
class WebhookSender:
    """Sends Phoenix incidents to the Gravae/Replayme API webhook."""

    # Map Phoenix alert types to webhook event types
    ALERT_TYPE_MAP = {
        "service_down": ("service_down", None),
        "service_recovered": ("service_up", None),
        "service_restarted": ("service_down", None),
        "service_restart_failed": ("service_down", None),
        "connectivity_lost": ("device_offline", "cloudflared"),
        "connectivity_restored": ("service_up", "cloudflared"),
        "connectivity_action": ("service_down", "cloudflared"),
        "monitor_status_change": ("monitor_offline", "camera"),
        "monitor_recovered": ("service_up", "camera"),
        "temperature_critical": ("resource_warning", "temperature"),
        "disk_critical": ("resource_warning", "disk"),
        "memory_critical": ("resource_warning", "memory"),
        "undervoltage": ("resource_warning", "undervoltage"),
        "undervoltage_recovered": ("resource_warning", "undervoltage"),
        "voltage_low": ("resource_warning", "undervoltage"),
        "system_reboot": ("device_offline", None),
    }

    def __init__(self):
        self.webhook_url = None
        self.platform = None
        self.device_serial = None
        self.device_name = None
        self.arena_name = None
        self._load_config()

    def _load_config(self):
        try:
            if CONFIG_PATH.exists():
                config = json.loads(CONFIG_PATH.read_text())
                self.arena_name = config.get("arenaName")
                self.device_name = config.get("deviceName", self.arena_name)

                # Detect platform from email or explicit config
                email = config.get("shinobiEmail", "")
                if config.get("platform"):
                    self.platform = config["platform"]
                elif "replayme" in email:
                    self.platform = "replayme"
                else:
                    self.platform = "gravae"

                self.webhook_url = config.get("webhookUrl") or WEBHOOK_URLS.get(self.platform)

            # Read device serial
            try:
                with open("/proc/cpuinfo") as f:
                    for line in f:
                        if line.startswith("Serial"):
                            self.device_serial = line.split(":")[1].strip()
                            break
            except Exception:
                pass

            log.info(f"Webhook configured: platform={self.platform}, url={self.webhook_url}, serial={self.device_serial}")
        except Exception as e:
            log.warning(f"Webhook config load failed: {e}")

    # Map systemd service names to webhook 'what' values
    SERVICE_NAME_MAP = {
        "gravae-agent": "agent",
        "cloudflared": "cloudflared",
        "gravae-buttons": "button_daemon",
        "shinobi": "shinobi",
        "mariadb": "shinobi",  # MariaDB down = Shinobi problem
    }

    def _extract_service_name(self, message):
        """Extract the service name from alert messages like 'Service cloudflared is down'."""
        if "Service " in message:
            # "Service cloudflared is down" → "cloudflared"
            parts = message.split("Service ", 1)
            if len(parts) > 1:
                name = parts[1].split(" ")[0]
                return self.SERVICE_NAME_MAP.get(name, name)
        return None

    def _alert_to_event(self, alert):
        """Convert a Phoenix alert to a webhook event."""
        alert_type = alert.get("type", "")
        message = alert.get("message", "")
        mapped = self.ALERT_TYPE_MAP.get(alert_type)

        if not mapped:
            event_type = "service_down" if "down" in alert_type or "fail" in alert_type else "resource_warning"
            what = alert_type
        else:
            event_type, what = mapped

        # Extract 'what' from message (service name) or details
        details = alert.get("details") or {}
        if what is None:
            what = self._extract_service_name(message) or details.get("service") or details.get("what") or alert_type

        event = {
            "type": event_type,
            "what": what,
            "device": {
                "serial": self.device_serial,
                "name": self.device_name,
            },
            "arena": {
                "name": self.arena_name,
                "platform": self.platform,
            },
            "timestamp": alert.get("timestamp", datetime.now().isoformat()),
            "summary": alert.get("message", ""),
            "details": details,
        }
        return event

    def send_pending(self, alert_queue):
        """Send all pending alerts as webhook events."""
        if not self.webhook_url:
            return

        pending = alert_queue.get_pending(limit=50)
        if not pending:
            return

        # Convert alerts to webhook events
        events = []
        alert_ids = []
        for alert in pending:
            events.append(self._alert_to_event(alert))
            alert_ids.append(alert["id"])

        payload = {
            "events": events,
            "metadata": {
                "phoenixVersion": VERSION,
                "generatedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            },
        }

        headers = {
            "Authorization": f"Bearer {WEBHOOK_SECRET}",
            "X-Phoenix-Timestamp": str(int(time.time())),
            "X-Phoenix-Event-Id": str(uuid.uuid4()),
            "Content-Type": "application/json",
        }

        # Send with retry
        for attempt in range(WEBHOOK_MAX_RETRIES):
            try:
                import urllib.request
                req = urllib.request.Request(
                    self.webhook_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT) as resp:
                    status = resp.status
                    if status in (200, 202):
                        alert_queue.mark_synced(alert_ids)
                        log.info(f"Webhook sent: {len(events)} event(s), status={status}")
                        return True
                    elif status == 429:
                        wait = 2 ** attempt
                        log.warning(f"Webhook rate limited, retrying in {wait}s")
                        time.sleep(wait)
                    else:
                        log.warning(f"Webhook returned {status}")
                        return False
            except Exception as e:
                if attempt < WEBHOOK_MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                else:
                    log.warning(f"Webhook send failed after {WEBHOOK_MAX_RETRIES} attempts: {e}")
        return False

# Boot report removed in v1.9.0 - Phoenix no longer reboots the system.

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
        self.resources = ResourceMonitor()
        self.webhook = WebhookSender()
        self.watchdog = HardwareWatchdog()
        self.shinobi_watcher = None  # Lazy loaded to save memory
        self.shinobi_epipe_detector = ShinobiCrashLoopDetector(self.service_guardian)

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

    def _cleanup_legacy_files(self):
        """Remove files from older Phoenix versions that are no longer needed."""
        legacy_files = [
            LOG_DIR / "last_will.json",
            LOG_DIR / "escalation_state.json",
            LOG_DIR / "reboot_count.json",
        ]
        for f in legacy_files:
            try:
                if f.exists():
                    f.unlink()
                    log.info(f"Cleaned up legacy file: {f}")
            except Exception as e:
                log.debug(f"Could not remove {f}: {e}")

        # Also restore dhcpcd.conf if Phoenix had disabled static IP lines
        try:
            dhcpcd = Path("/etc/dhcpcd.conf")
            if dhcpcd.exists():
                content = dhcpcd.read_text()
                if "# PHOENIX_DISABLED:" in content:
                    # Restore the original lines
                    new_lines = []
                    for line in content.splitlines():
                        if line.startswith("# PHOENIX_DISABLED: "):
                            new_lines.append(line.replace("# PHOENIX_DISABLED: ", ""))
                        else:
                            new_lines.append(line)
                    dhcpcd.write_text("\n".join(new_lines) + "\n")
                    subprocess.run(["systemctl", "restart", "dhcpcd"], capture_output=True, timeout=30)
                    log.warning("Restored static IP lines that were disabled by older Phoenix version")
                    alerts.add("network_config_restored", "warning",
                              "Restored static IP config disabled by older Phoenix version")
        except Exception as e:
            log.debug(f"Could not check/restore dhcpcd.conf: {e}")

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

        # Clean up legacy files from older versions
        self._cleanup_legacy_files()

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
        log.info(f"Phoenix v{VERSION} started (reboot after 4h offline, max {MAX_REBOOTS_PER_DAY}/day, no network config changes)")

        last_service_check = 0
        last_connectivity_check = 0
        last_resource_check = 0
        last_monitor_check = 0
        last_shinobi_epipe_check = 0
        last_webhook_send = 0
        last_alert_cleanup = 0
        last_gc = 0
        last_voltage_check = 0
        last_speed_test = 0
        SPEED_TEST_INTERVAL = 6 * 60 * 60  # 6 hours (v1.16.0: era 4h)
        SHINOBI_EPIPE_CHECK_INTERVAL = 120  # 2 minutes

        while self.running:
            now = time.time()

            try:

                # Service check (every 2 minutes)
                if now - last_service_check >= CHECK_INTERVAL:
                    self.service_guardian.check_all_services_v2()
                    last_service_check = now

                # Connectivity check (every minute)
                if now - last_connectivity_check >= CONNECTIVITY_CHECK_INTERVAL:
                    prev_online = self.connectivity.is_online
                    self.connectivity.update()
                    # Mirror transitions into offline_events so OPS can show
                    # "histórico de offline" on the ticket Device tab.
                    if prev_online and not self.connectivity.is_online:
                        offline_tracker.mark_offline(
                            evidence="ping+http targets unreachable"
                        )
                    elif not prev_online and self.connectivity.is_online:
                        offline_tracker.mark_online()
                    last_connectivity_check = now

                # Shinobi monitor check (every 5 minutes, only when online)
                if now - last_monitor_check >= 300 and self.connectivity.is_online:
                    try:
                        watcher = self._get_shinobi_watcher()
                        watcher.check_monitors()
                    except Exception as e:
                        log.debug(f"Monitor check error: {e}")
                    last_monitor_check = now

                # Shinobi EPIPE crash-loop recovery (every 2 minutes)
                # Detects the libs/events/utils.js event-recording bug that
                # leaves Shinobi silently dropping motion-triggered recordings.
                if now - last_shinobi_epipe_check >= SHINOBI_EPIPE_CHECK_INTERVAL:
                    try:
                        self.shinobi_epipe_detector.check()
                    except Exception as e:
                        log.debug(f"Shinobi EPIPE check error: {e}")
                    last_shinobi_epipe_check = now

                # Resource check (every 5 minutes)
                if now - last_resource_check >= 300:
                    self.resources.check_resources()
                    last_resource_check = now

                # Speed test (every 4 hours, only when online)
                if now - last_speed_test >= SPEED_TEST_INTERVAL and self.connectivity.is_online:
                    try:
                        self.resources.check_speed()
                    except Exception as e:
                        log.debug(f"Speed test error: {e}")
                    last_speed_test = now

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

                # Webhook: send pending alerts (every 5 minutes when online)
                if now - last_webhook_send >= WEBHOOK_SEND_INTERVAL and self.connectivity.is_online:
                    try:
                        self.webhook.send_pending(alerts)
                    except Exception as e:
                        log.debug(f"Webhook send error: {e}")
                    last_webhook_send = now

                # Alert cleanup (daily)
                if now - last_alert_cleanup >= 86400:
                    alerts.cleanup_old()
                    offline_tracker.cleanup_old(days=60)
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
