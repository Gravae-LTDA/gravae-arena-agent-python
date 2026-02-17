#!/usr/bin/env python3
"""
Gravae Agent - Centralized Logging System

Provides structured logging for all agent components with:
- Rotating file logs (JSON format) for machine parsing
- Console output (human-readable) for systemd journal
- Per-component loggers with shared configuration
- HTTP endpoint support for remote log retrieval
- Ring buffer for fast in-memory log access

Usage:
    from gravae_logging import get_logger
    log = get_logger('coaching')        # coaching.log
    log = get_logger('upload')          # upload.log
    log = get_logger('agent')           # agent.log
    log = get_logger('shinobi')         # agent.log (sub-logger)

    log.info("Recording started", extra={"session_id": "abc123", "monitor": "cam01"})
    log.error("Upload failed", extra={"file": "segment_001.ts", "error": str(e)})
"""

import json
import logging
import os
import threading
from collections import deque
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

# === Configuration ===
LOG_DIR = Path("/var/log/gravae")
MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file
BACKUP_COUNT = 5               # Keep 5 rotated files
RING_BUFFER_SIZE = 2000        # Keep last 2000 entries in memory

# Component → log file mapping
LOG_FILES = {
    'agent':    'agent.log',
    'coaching': 'coaching.log',
    'upload':   'coaching.log',    # upload logs go to coaching.log
    'shinobi':  'coaching.log',    # shinobi logs go to coaching.log
    's3':       'coaching.log',    # s3 logs go to coaching.log
    'config':   'coaching.log',    # config logs go to coaching.log
    'phoenix':  'phoenix.log',     # phoenix has its own (already exists)
}


# === JSON Formatter ===
class JsonFormatter(logging.Formatter):
    """Formats log records as JSON lines for file output."""

    def format(self, record):
        log_obj = {
            "ts": datetime.now().isoformat(),
            "level": record.levelname,
            "component": record.name,
            "msg": record.getMessage(),
        }
        # Include extra fields (session_id, file, error, etc.)
        if hasattr(record, 'extra') and record.extra:
            log_obj["data"] = record.extra
        return json.dumps(log_obj, ensure_ascii=False)


# === Console Formatter ===
class ConsoleFormatter(logging.Formatter):
    """Human-readable format for console/journald output."""

    COLORS = {
        'DEBUG':    '\033[36m',   # cyan
        'INFO':     '\033[32m',   # green
        'WARNING':  '\033[33m',   # yellow
        'ERROR':    '\033[31m',   # red
        'CRITICAL': '\033[35m',   # magenta
    }
    RESET = '\033[0m'

    def format(self, record):
        ts = datetime.now().strftime('%H:%M:%S')
        color = self.COLORS.get(record.levelname, '')
        reset = self.RESET if color else ''
        component = record.name.upper()

        msg = f"[{ts}] {color}[{component}]{reset} {record.getMessage()}"

        # Append extra data inline if present
        if hasattr(record, 'extra') and record.extra:
            data_str = ' '.join(f'{k}={v}' for k, v in record.extra.items())
            msg += f" | {data_str}"

        return msg


# === Ring Buffer Handler ===
class RingBufferHandler(logging.Handler):
    """Stores recent log entries in memory for fast HTTP access."""

    def __init__(self, capacity=RING_BUFFER_SIZE):
        super().__init__()
        self._buffer = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def emit(self, record):
        entry = {
            "ts": datetime.now().isoformat(),
            "level": record.levelname,
            "component": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, 'extra') and record.extra:
            entry["data"] = record.extra
        with self._lock:
            self._buffer.append(entry)

    def get_entries(self, lines=100, component=None, level=None):
        """Get recent log entries with optional filtering."""
        with self._lock:
            entries = list(self._buffer)

        if component:
            entries = [e for e in entries if e["component"] == component]
        if level:
            level_upper = level.upper()
            level_priority = {
                'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3, 'CRITICAL': 4
            }
            min_priority = level_priority.get(level_upper, 0)
            entries = [
                e for e in entries
                if level_priority.get(e["level"], 0) >= min_priority
            ]

        return entries[-lines:]


# === Custom Logger Class ===
class GravaeLogger(logging.Logger):
    """Logger that supports extra fields via keyword argument."""

    def _log(self, level, msg, args, exc_info=None, extra=None,
             stack_info=False, stacklevel=1, **kwargs):
        # Allow passing extra data directly: log.info("msg", extra={"key": "val"})
        if extra is None:
            extra = {}
        # Store our extra data in a custom attribute
        if not isinstance(extra, dict):
            extra = {}
        # We need to pass extra through the standard mechanism
        # but also keep our custom data accessible
        super()._log(level, msg, args, exc_info=exc_info,
                     extra={'extra': extra}, stack_info=stack_info,
                     stacklevel=stacklevel + 1)


# === Global State ===
logging.setLoggerClass(GravaeLogger)

_ring_buffer = RingBufferHandler()
_initialized_loggers = {}
_setup_lock = threading.Lock()
_log_dir_created = False


def _ensure_log_dir():
    """Create log directory if it doesn't exist."""
    global _log_dir_created, LOG_DIR
    if not _log_dir_created:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            _log_dir_created = True
        except PermissionError:
            # Running without root - use /tmp fallback
            LOG_DIR = Path("/tmp/gravae-logs")
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            _log_dir_created = True


def get_logger(component: str) -> GravaeLogger:
    """
    Get or create a logger for the given component.

    Args:
        component: Component name (agent, coaching, upload, shinobi, s3, config)

    Returns:
        Configured GravaeLogger instance
    """
    with _setup_lock:
        if component in _initialized_loggers:
            return _initialized_loggers[component]

        _ensure_log_dir()

        logger = logging.getLogger(component)
        logger.setLevel(logging.DEBUG)

        # Prevent duplicate handlers on re-initialization
        if logger.handlers:
            _initialized_loggers[component] = logger
            return logger

        # File handler (JSON, rotating)
        log_file = LOG_DIR / LOG_FILES.get(component, 'agent.log')
        try:
            file_handler = RotatingFileHandler(
                log_file, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(JsonFormatter())
            logger.addHandler(file_handler)
        except (PermissionError, OSError) as e:
            print(f"[Logging] Warning: Cannot write to {log_file}: {e}")

        # Console handler (human-readable)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(ConsoleFormatter())
        logger.addHandler(console_handler)

        # Ring buffer (shared across all loggers)
        logger.addHandler(_ring_buffer)

        # Don't propagate to root logger
        logger.propagate = False

        _initialized_loggers[component] = logger
        return logger


def get_recent_logs(lines=100, component=None, level=None):
    """
    Get recent log entries from the in-memory ring buffer.

    Args:
        lines: Number of recent entries to return (default 100)
        component: Filter by component name (optional)
        level: Minimum log level filter (optional)

    Returns:
        List of log entry dicts
    """
    return _ring_buffer.get_entries(lines=lines, component=component, level=level)


def get_log_file_entries(component='agent', lines=200):
    """
    Read recent entries from a log file on disk.
    Useful for entries older than the ring buffer.

    Args:
        component: Component name to read logs for
        lines: Number of recent lines to return

    Returns:
        List of parsed log entry dicts (or raw strings if JSON parse fails)
    """
    log_file = LOG_DIR / LOG_FILES.get(component, 'agent.log')
    if not log_file.exists():
        return []

    try:
        with open(log_file, 'r') as f:
            all_lines = f.readlines()

        recent = all_lines[-lines:]
        entries = []
        for line in recent:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                entries.append({"ts": "", "level": "INFO", "component": component, "msg": line})
        return entries
    except (PermissionError, OSError):
        return []


def get_log_stats():
    """Get logging system statistics."""
    stats = {
        "log_dir": str(LOG_DIR),
        "ring_buffer_size": len(_ring_buffer._buffer),
        "ring_buffer_capacity": _ring_buffer._buffer.maxlen,
        "initialized_loggers": list(_initialized_loggers.keys()),
        "log_files": {},
    }

    for component, filename in LOG_FILES.items():
        log_path = LOG_DIR / filename
        if log_path.exists() and filename not in [v for v in stats["log_files"].values()]:
            try:
                size = log_path.stat().st_size
                stats["log_files"][filename] = {
                    "path": str(log_path),
                    "size_bytes": size,
                    "size_mb": round(size / (1024 * 1024), 2),
                }
            except OSError:
                pass

    return stats
