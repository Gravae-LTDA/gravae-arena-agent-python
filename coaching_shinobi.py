"""
Coaching Review - Shinobi recording control.
Uses Shinobi's HTTP API to start/stop recordings and list videos.
Uses coaching-specific Shinobi credentials (separate account from OPS).
"""
import json
import os
import glob
import time
import urllib.request
import urllib.error
from datetime import datetime

from coaching_config import get_config

try:
    from gravae_logging import get_logger
    log = get_logger('shinobi')
except ImportError:
    import logging
    log = logging.getLogger('shinobi')

SHINOBI_URL = "http://127.0.0.1:8080"
SHINOBI_VIDEOS_PATH = "/home/Shinobi/videos"

# Cache session token to avoid login on every call
_session_cache = {"token": None, "group_key": None, "expires": 0}


def _get_shinobi_creds():
    """Get Shinobi session token and group key for the coaching account.
    Uses session token (from login) instead of API key because API keys
    have restricted permissions that strip sensitive monitor data (host, muser, mpass).
    Session tokens have full user permissions.
    Falls back to API key if login fails."""
    cfg = get_config()
    group_key = cfg.get('shinobiGroupKey')
    if not group_key:
        return None, None

    # Check cached session token (valid for 1 hour)
    now = time.time()
    if _session_cache["token"] and _session_cache["group_key"] == group_key and _session_cache["expires"] > now:
        return _session_cache["token"], _session_cache["group_key"]

    # Login to get session token
    email = cfg.get('shinobiEmail', '')
    password = cfg.get('shinobiPassword', '')
    if email and password:
        try:
            login_data = json.dumps({"mail": email, "pass": password, "machineID": "coaching-agent"}).encode()
            req = urllib.request.Request(
                f"{SHINOBI_URL}/?json=true",
                data=login_data,
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
            user = result.get('$user', {})
            token = user.get('auth_token', '')
            gk = user.get('ke', '')
            if token and gk:
                _session_cache["token"] = token
                _session_cache["group_key"] = gk
                _session_cache["expires"] = now + 3600  # 1 hour
                log.info(f"Session token obtained for group {gk[:8]}...")
                return token, gk
        except Exception as e:
            log.error(f"Login failed: {e}")

    # Fallback to API key
    api_key = cfg.get('shinobiApiKey')
    if api_key and group_key:
        return api_key, group_key
    return None, None


def _shinobi_get(path, timeout=10):
    """Make GET request to Shinobi API."""
    url = f"{SHINOBI_URL}{path}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        log.error(f"GET {path} failed: {e}")
        return None


def _shinobi_post(path, data=None, timeout=10):
    """Make POST request to Shinobi API."""
    url = f"{SHINOBI_URL}{path}"
    try:
        body = json.dumps(data or {}).encode()
        req = urllib.request.Request(url, data=body, method='POST')
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        log.error(f"POST {path} failed: {e}")
        return None


def _ensure_monitor_watching(monitor_id):
    """Ensure monitor is in 'start' (watching) mode so the RTSP stream is active.
    Coaching monitors are created with mode='stop'. Shinobi's /record endpoint
    works poorly on stopped monitors — the stream isn't established yet, causing
    very short recordings (~13s). By starting the monitor first and waiting for
    the stream to stabilize, recordings work correctly."""
    api_key, group_key = _get_shinobi_creds()
    if not api_key or not group_key:
        return False

    # Check current monitor state
    path = f"/{api_key}/monitor/{group_key}/{monitor_id}"
    info = _shinobi_get(path, timeout=10)

    if info is None:
        log.error(f"Could not get monitor {monitor_id} state")
        return False

    # info can be a list or dict depending on Shinobi version
    monitor_data = info[0] if isinstance(info, list) and info else info
    current_mode = monitor_data.get('mode', 'stop') if isinstance(monitor_data, dict) else 'stop'

    if current_mode == 'stop':
        log.info(f"Monitor {monitor_id} is stopped, starting watch mode...")
        # Use direct start endpoint (works with both session tokens and API keys)
        # configureMonitor returns "Invalid Data" with session tokens
        start_path = f"/{api_key}/monitor/{group_key}/{monitor_id}/start"
        result = _shinobi_get(start_path, timeout=15)
        log.info(f"Start result: {result}")
        # Wait for RTSP stream to establish (camera connection + first keyframe)
        time.sleep(5)
        log.info(f"Monitor {monitor_id} stream should be active now")
        return True

    log.info(f"Monitor {monitor_id} already in mode={current_mode}")
    return True


def start_recording(monitor_id, duration_minutes):
    """Start recording on a Shinobi monitor for a given duration.
    Uses Shinobi's built-in timed recording API.
    First ensures the monitor is watching (stream active) before recording."""
    api_key, group_key = _get_shinobi_creds()
    if not api_key or not group_key:
        return {"success": False, "error": "Shinobi credentials not found"}

    # Ensure the monitor is watching (RTSP stream active) before recording
    _ensure_monitor_watching(monitor_id)

    # Shinobi record endpoint: /record/{time}/{interval}
    # IMPORTANT: Without interval param, Shinobi defaults to SECONDS. Must append /min.
    path = f"/{api_key}/monitor/{group_key}/{monitor_id}/record/{duration_minutes}/min"
    result = _shinobi_get(path, timeout=15)

    if result is None:
        return {"success": False, "error": "Failed to contact Shinobi"}

    log.info(f"Started recording {monitor_id} for {duration_minutes}min")
    return {"success": True, "result": result}


def stop_recording(monitor_id):
    """Stop recording and set monitor back to 'stop' mode to save resources.
    Coaching monitors only need to stream during active recording sessions."""
    api_key, group_key = _get_shinobi_creds()
    if not api_key or not group_key:
        return {"success": False, "error": "Shinobi credentials not found"}

    # Use direct stop endpoint (works with both session tokens and API keys)
    # configureMonitor returns "Invalid Data" with session tokens
    path = f"/{api_key}/monitor/{group_key}/{monitor_id}/stop"
    result = _shinobi_get(path, timeout=15)

    if result is None:
        return {"success": False, "error": "Failed to contact Shinobi"}

    log.info(f"Stopped recording {monitor_id}, monitor set to stop mode")
    return {"success": True, "result": result}


def list_videos(monitor_id, start_time=None, end_time=None):
    """List recorded video files for a monitor.
    Times should be ISO format strings (UTC)."""
    api_key, group_key = _get_shinobi_creds()
    if not api_key or not group_key:
        return []

    # Build query params
    params = ""
    if start_time and end_time:
        params = f"?start={start_time}&end={end_time}"

    path = f"/{api_key}/videos/{group_key}/{monitor_id}{params}"
    result = _shinobi_get(path, timeout=15)

    if result is None or not isinstance(result, dict):
        return []

    videos = result.get('videos', [])
    log.info(f"Found {len(videos)} videos for {monitor_id}")
    return videos


def get_video_local_path(monitor_id, filename):
    """Get the local file path of a Shinobi recording."""
    _, group_key = _get_shinobi_creds()
    if not group_key:
        return None

    path = os.path.join(SHINOBI_VIDEOS_PATH, group_key, monitor_id, filename)
    if os.path.exists(path):
        return path

    # Try finding the file by searching (Shinobi may organize by date subfolders)
    pattern = os.path.join(SHINOBI_VIDEOS_PATH, group_key, monitor_id, '**', filename)
    matches = glob.glob(pattern, recursive=True)
    if matches:
        return matches[0]

    return None


def find_recent_videos(monitor_id, after_time=None):
    """Find video files on disk for a monitor, optionally after a timestamp.
    Returns list of {'path': str, 'filename': str, 'size': int, 'mtime': float}."""
    _, group_key = _get_shinobi_creds()
    if not group_key:
        return []

    base_dir = os.path.join(SHINOBI_VIDEOS_PATH, group_key, monitor_id)
    if not os.path.isdir(base_dir):
        return []

    results = []
    for root, _dirs, files in os.walk(base_dir):
        for f in files:
            if not f.endswith(('.mp4', '.ts', '.mkv')):
                continue
            full_path = os.path.join(root, f)
            try:
                stat = os.stat(full_path)
                if after_time and stat.st_mtime < after_time:
                    continue
                results.append({
                    'path': full_path,
                    'filename': f,
                    'size': stat.st_size,
                    'mtime': stat.st_mtime,
                })
            except OSError:
                continue

    results.sort(key=lambda x: x['mtime'])
    return results


def delete_video(monitor_id, filename):
    """Delete a video file via Shinobi API."""
    api_key, group_key = _get_shinobi_creds()
    if not api_key or not group_key:
        return False

    path = f"/{api_key}/videos/{group_key}/{monitor_id}/{filename}/delete"
    result = _shinobi_get(path, timeout=10)
    return result is not None
