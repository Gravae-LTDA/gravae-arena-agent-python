"""
Coaching Review - Main orchestrator module.
Handles job polling, recording orchestration, and upload coordination.
Integrates with the existing gravae_agent.py HTTP handler.
"""
import json
import os
import signal
import subprocess
import threading
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone

from coaching_config import get_config, is_configured, update_config, save_config
from coaching_shinobi import (
    start_recording, stop_recording, find_recent_videos,
    _ensure_monitor_watching, get_monitor_rtsp_url,
)
from coaching_upload import UploadQueue

try:
    from gravae_logging import get_logger
    log = get_logger('coaching')
except ImportError:
    import logging
    log = logging.getLogger('coaching')

POLL_INTERVAL = 10  # seconds
HLS_DIR = "/var/lib/gravae-coaching/hls"
SEGMENT_DURATION_SECONDS = 6
SEGMENT_WATCH_INTERVAL = 2


def _remux_to_hls(video_files, output_dir, segment_duration=6):
    """Remux MP4 video files to HLS segments using ffmpeg -codec copy.
    No re-encoding — just repackages the video into .ts segments.
    Near-zero CPU usage on RPi.

    Args:
        video_files: List of dicts with 'path' key, sorted by mtime
        output_dir: Directory to write HLS segments and manifest
        segment_duration: Target segment duration in seconds (default 6)

    Returns:
        {'manifest': path, 'segments': [paths], 'total_size': int} or None
    """
    os.makedirs(output_dir, exist_ok=True)

    manifest_path = os.path.join(output_dir, 'manifest.m3u8')
    segment_pattern = os.path.join(output_dir, 'seg_%06d.ts')

    if len(video_files) == 1:
        input_args = ['-i', video_files[0]['path']]
    else:
        # Multiple files — use ffmpeg concat demuxer
        concat_file = os.path.join(output_dir, 'concat.txt')
        with open(concat_file, 'w') as f:
            for v in video_files:
                safe_path = v['path'].replace("'", "'\\''")
                f.write(f"file '{safe_path}'\n")
        input_args = ['-f', 'concat', '-safe', '0', '-i', concat_file]

    cmd = [
        'ffmpeg', '-y',
        *input_args,
        '-codec', 'copy',
        '-f', 'hls',
        '-hls_time', str(segment_duration),
        '-hls_segment_filename', segment_pattern,
        '-hls_playlist_type', 'vod',
        manifest_path,
    ]

    log.info(f"Remuxing {len(video_files)} file(s) to HLS...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        log.error("FFmpeg timed out (600s)")
        return None

    if result.returncode != 0:
        log.error(f"FFmpeg error (rc={result.returncode}): {result.stderr[-500:]}")
        return None

    # Collect output files
    segments = sorted([
        os.path.join(output_dir, f)
        for f in os.listdir(output_dir)
        if f.endswith('.ts')
    ])

    if not segments:
        log.error("No HLS segments created")
        return None

    total_size = sum(os.path.getsize(f) for f in segments)
    total_size += os.path.getsize(manifest_path)

    # Clean up concat file
    concat_file = os.path.join(output_dir, 'concat.txt')
    if os.path.exists(concat_file):
        os.remove(concat_file)

    log.info(f"Created {len(segments)} HLS segments ({total_size / 1024 / 1024:.1f} MB total)")
    return {
        'manifest': manifest_path,
        'segments': segments,
        'total_size': total_size,
    }


class CoachingReviewModule:
    """Main coaching review module. Manages polling, recording, and upload threads."""

    def __init__(self):
        self._poll_thread = None
        self._upload_thread = None
        self._stop_event = threading.Event()
        self._active_sessions = {}  # session_id -> session info
        self._hls_uploads = {}  # session_id -> {file_id, r2_prefix, total_size}
        self._lock = threading.Lock()
        self._upload_queue = UploadQueue()

    def is_configured(self):
        return is_configured()

    def start(self):
        """Start polling and upload threads."""
        if not self.is_configured():
            log.warning("Not configured, skipping start")
            return False

        self._stop_event.clear()

        self._poll_thread = threading.Thread(
            target=self._polling_loop, daemon=True, name='coaching-poll'
        )
        self._poll_thread.start()

        self._upload_thread = threading.Thread(
            target=self._upload_loop, daemon=True, name='coaching-upload'
        )
        self._upload_thread.start()

        log.info("Module started (polling + upload threads)")
        return True

    def stop(self):
        """Stop all threads gracefully."""
        log.info("Stopping module...")
        self._stop_event.set()
        with self._lock:
            sessions = list(self._active_sessions.items())
        for session_id, session in sessions:
            self._stop_ffmpeg_session(session_id, session, mark_uploading=False)
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=10)
        if self._upload_thread and self._upload_thread.is_alive():
            self._upload_thread.join(timeout=10)
        log.info("Module stopped")

    def get_status(self):
        """Get module status for the /coaching/status endpoint."""
        cfg = get_config()
        with self._lock:
            active = {
                sid: {
                    'sessionId': s.get('sessionId'),
                    'cameraId': s.get('cameraId'),
                    'shinobiMonitorId': s.get('shinobiMonitorId'),
                    'startedAt': s.get('startedAt'),
                    'recordingId': s.get('recordingId'),
                    'hlsDir': s.get('hlsDir'),
                    'ffmpegRunning': bool(s.get('ffmpegProc') and s.get('ffmpegProc').poll() is None),
                    'segmentsEnqueued': len(s.get('seenSegments', set())),
                    'cloudRegistered': bool(s.get('recordingId')),
                }
                for sid, s in self._active_sessions.items()
            }
            hls = {sid: {
                'fileId': info.get('file_id'),
                'recordingId': info.get('recording_id'),
                'totalSize': info.get('total_size', 0),
                'needsRegistration': info.get('needs_registration', False),
                'manifestEnqueued': info.get('manifest_enqueued', False),
                'progress': self._upload_queue.get_session_progress(sid),
            } for sid, info in self._hls_uploads.items()}

        return {
            "configured": self.is_configured(),
            "running": (
                self._poll_thread is not None
                and self._poll_thread.is_alive()
            ),
            "uploadThreadAlive": (
                self._upload_thread is not None
                and self._upload_thread.is_alive()
            ),
            "activeSessions": active,
            "hlsUploads": hls,
            "uploadQueue": self._upload_queue.get_queue_status(),
        }

    def handle_request(self, handler, method, path, body=None):
        """Handle HTTP requests for /coaching/* endpoints."""
        if method == 'GET':
            if path == '/coaching/status':
                handler._send_json(self.get_status())
                return True
            if path == '/coaching/queue':
                handler._send_json(self._upload_queue.get_queue_status(detailed=True))
                return True
            if path.startswith('/coaching/hls/'):
                return self._handle_serve_hls(handler, path)
            if path == '/coaching/monitors':
                return self._handle_list_monitors(handler)
            if path == '/coaching/debug-db':
                return self._handle_debug_db(handler)
            if path == '/coaching/test-api':
                return self._handle_test_api(handler)
            if path == '/coaching/clone-via-api':
                return self._handle_clone_via_api(handler)
            if path == '/coaching/reclone-db':
                return self._handle_reclone_db(handler)

        elif method == 'POST':
            data = body or {}

            if path == '/coaching/configure':
                return self._handle_configure(handler, data)

            if path == '/coaching/start':
                return self._handle_start(handler)

            if path == '/coaching/stop':
                self.stop()
                handler._send_json({"success": True, "message": "Module stopped"})
                return True

            if path.startswith('/coaching/cancel/'):
                session_id = path.split('/coaching/cancel/')[-1]
                return self._handle_cancel(handler, session_id)

            if path == '/coaching/test-record':
                return self._handle_test_record(handler, data)

            if path == '/coaching/test-hls':
                return self._handle_test_hls(handler, data)

            if path == '/coaching/fix-api-key':
                return self._handle_fix_api_key(handler)

        handler._send_json({"error": "Not found"}, 404)
        return True

    def _handle_serve_hls(self, handler, path):
        """Serve HLS files (segments + manifest) from local disk.
        GET /coaching/hls/{session_id}/manifest.m3u8
        GET /coaching/hls/{session_id}/seg_000001.ts
        """
        # Extract relative path after /coaching/hls/
        rel_path = path[len('/coaching/hls/'):]
        if '..' in rel_path or rel_path.startswith('/'):
            handler._send_json({"error": "Invalid path"}, 400)
            return True

        file_path = os.path.join(HLS_DIR, rel_path)
        if not os.path.isfile(file_path):
            handler._send_json({"error": "File not found"}, 404)
            return True

        # Determine content type
        if file_path.endswith('.m3u8'):
            content_type = 'application/vnd.apple.mpegurl'
        elif file_path.endswith('.ts'):
            content_type = 'video/mp2t'
        else:
            content_type = 'application/octet-stream'

        try:
            file_size = os.path.getsize(file_path)
            handler.send_response(200)
            handler.send_header('Content-Type', content_type)
            handler.send_header('Content-Length', str(file_size))
            handler.send_header('Access-Control-Allow-Origin', '*')
            handler.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
            handler.send_header('Access-Control-Allow-Headers', 'Content-Type')
            handler.end_headers()

            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    handler.wfile.write(chunk)
        except Exception as e:
            log.error(f"Failed to serve HLS file {rel_path}: {e}")
        return True

    def _handle_list_monitors(self, handler):
        """Handle GET /coaching/monitors - list coaching and OPS monitors for comparison."""
        from coaching_shinobi import _get_shinobi_creds, _shinobi_get

        def _summarize(monitors, label):
            result = []
            for m in monitors:
                d = m.get('details', '{}')
                if isinstance(d, str):
                    try: d = json.loads(d)
                    except: d = {}
                result.append({
                    "mid": m.get('mid'), "name": m.get('name'),
                    "host": m.get('host'), "port": m.get('port'),
                    "mode": m.get('mode'), "protocol": m.get('protocol'),
                    "auto_host_enable": d.get('auto_host_enable', ''),
                    "auto_host": d.get('auto_host', '')[:100],
                    "muser": d.get('muser', ''),
                    "mpass": '***' if d.get('mpass') else '',
                    "stream_type": d.get('stream_type', ''),
                })
            return result

        # Coaching monitors
        api_key, group_key = _get_shinobi_creds()
        coaching_monitors = _shinobi_get(f"/{api_key}/monitor/{group_key}", timeout=10) if api_key else []

        # OPS monitors for comparison (read-only)
        import os, subprocess
        ops_config_path = '/etc/gravae/device.json'
        ops_monitors = []
        try:
            with open(ops_config_path) as f:
                ops_cfg = json.load(f)
            ops_ak = ops_cfg.get('shinobiApiKey')
            ops_gk = ops_cfg.get('shinobiGroupKey')
            if ops_ak and ops_gk:
                ops_monitors = _shinobi_get(f"/{ops_ak}/monitor/{ops_gk}", timeout=10) or []
        except Exception:
            pass

        handler._send_json({
            "coaching": _summarize(coaching_monitors or [], "coaching"),
            "ops": _summarize(ops_monitors, "ops"),
        })
        return True

    def _handle_debug_db(self, handler):
        """Debug DB: check API table schema and coaching monitors in raw DB."""
        import subprocess, os
        with open('/home/Shinobi/conf.json') as f:
            conf = json.load(f)
        db = conf.get('db', {})
        env = dict(os.environ)
        env['MYSQL_PWD'] = db.get('password') or ''
        cmd = ['mysql', '-u', db.get('user', 'majesticflame'), '-h', db.get('host', 'localhost'), db.get('database', 'ccio')]

        def run_sql(sql):
            r = subprocess.run(cmd + ['-N', '-B', '-e', sql], env=env, capture_output=True, text=True, timeout=10)
            return {"rc": r.returncode, "out": r.stdout.strip()[:2000], "err": r.stderr.strip()[:500]}

        # Check API table schema
        api_schema = run_sql("DESCRIBE API")
        # Check coaching API key record
        from coaching_config import get_config
        cfg = get_config()
        gk = cfg.get('shinobiGroupKey', '')
        api_record = run_sql(f"SELECT * FROM API WHERE ke='{gk}'")
        # Check OPS API key for comparison
        ops_gk = ''
        try:
            with open('/etc/gravae/device.json') as f:
                ops_gk = json.load(f).get('shinobiGroupKey', '')
        except: pass
        ops_api_record = run_sql(f"SELECT * FROM API WHERE ke='{ops_gk}'")

        handler._send_json({
            "api_schema": api_schema,
            "coaching_api_record": api_record,
            "ops_api_record": ops_api_record,
        })
        return True

    def _handle_reclone_db(self, handler):
        """Re-insert coaching monitors via DB and restart Shinobi."""
        import subprocess, os
        from coaching_config import get_config
        cfg = get_config()
        coaching_gk = cfg.get('shinobiGroupKey', '')
        try:
            with open('/etc/gravae/device.json') as f:
                ops_gk = json.load(f).get('shinobiGroupKey', '')
        except: ops_gk = ''

        with open('/home/Shinobi/conf.json') as f:
            conf = json.load(f)
        db = conf.get('db', {})
        env = dict(os.environ)
        env['MYSQL_PWD'] = db.get('password') or ''
        mysql_cmd = ['mysql', '-u', db.get('user', 'majesticflame'), '-h', db.get('host', 'localhost'), db.get('database', 'ccio')]

        def run_sql(sql, timeout=10):
            return subprocess.run(mysql_cmd + ['-N', '-e', sql], env=env, capture_output=True, text=True, timeout=timeout)

        # Delete and re-insert
        run_sql(f"DELETE FROM Monitors WHERE ke='{coaching_gk}'")
        clone_sql = (
            f"INSERT INTO Monitors (ke, mid, name, type, ext, protocol, host, path, port, fps, mode, width, height, details) "
            f"SELECT '{coaching_gk}', mid, CONCAT('Coaching - ', name), type, ext, protocol, host, path, port, fps, 'stop', width, height, details "
            f"FROM Monitors WHERE ke='{ops_gk}'"
        )
        r = run_sql(clone_sql, timeout=15)

        # Count monitors
        count_r = run_sql(f"SELECT COUNT(*) FROM Monitors WHERE ke='{coaching_gk}'")

        # Restart Shinobi
        pm2_r = subprocess.run(['pm2', 'restart', 'all'], capture_output=True, text=True, timeout=15)

        handler._send_json({
            "success": r.returncode == 0,
            "clone_err": r.stderr[:200] if r.stderr else "",
            "monitor_count": count_r.stdout.strip(),
            "pm2_restart": pm2_r.returncode == 0,
        })
        return True

    def _handle_clone_via_api(self, handler):
        """Clone OPS monitors to coaching account using Shinobi API (not SQL).
        This properly initializes monitors in Shinobi's internal state.
        Steps:
        1. Increase user's max_camera limit via super admin
        2. Login as coaching user
        3. Delete existing coaching monitors from DB
        4. Create each monitor via Shinobi API with full config"""
        from coaching_shinobi import _shinobi_get, _shinobi_post
        from coaching_config import get_config
        import urllib.request, subprocess, os
        cfg = get_config()
        coaching_gk = cfg.get('shinobiGroupKey', '')

        # Get OPS monitors (full config)
        try:
            with open('/etc/gravae/device.json') as f:
                ops_cfg = json.load(f)
            ops_ak = ops_cfg.get('shinobiApiKey')
            ops_gk = ops_cfg.get('shinobiGroupKey')
            ops_monitors = _shinobi_get(f"/{ops_ak}/monitor/{ops_gk}", timeout=10) or []
        except Exception as e:
            handler._send_json({"error": f"Failed to get OPS monitors: {e}"})
            return True

        # Step 1: Increase max_camera via super admin API
        with open('/home/Shinobi/conf.json') as f:
            conf = json.load(f)
        db = conf.get('db', {})
        env = dict(os.environ)
        env['MYSQL_PWD'] = db.get('password') or ''
        mysql_cmd = ['mysql', '-u', db.get('user', 'majesticflame'), '-h', db.get('host', 'localhost'), db.get('database', 'ccio')]

        # Update user's details to allow more cameras
        update_sql = f"UPDATE Users SET details=JSON_SET(details, '$.max_camera', '50') WHERE ke='{coaching_gk}'"
        subprocess.run(mysql_cmd + ['-N', '-e', update_sql], env=env, capture_output=True, text=True, timeout=10)
        log.info("Updated max_camera to 50")

        # Step 2: Login as coaching user
        email = cfg.get('shinobiEmail', '')
        password = cfg.get('shinobiPassword', '')
        try:
            login_data = json.dumps({"mail": email, "pass": password, "machineID": "clone"}).encode()
            req = urllib.request.Request(
                "http://127.0.0.1:8080/?json=true",
                data=login_data, headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
            session_token = result.get('$user', {}).get('auth_token', '')
        except Exception as e:
            handler._send_json({"error": f"Login failed: {e}"})
            return True

        if not session_token:
            handler._send_json({"error": "Could not get session token"})
            return True

        # Step 3: Delete existing coaching monitors from DB
        subprocess.run(mysql_cmd + ['-N', '-e', f"DELETE FROM Monitors WHERE ke='{coaching_gk}'"],
                       env=env, capture_output=True, text=True, timeout=10)

        # Step 4: Create each monitor via Shinobi API with full config
        cloned = []
        failed = []
        for m in ops_monitors:
            mid = m.get('mid', '')
            name = m.get('name', '')
            details = m.get('details', {})
            if isinstance(details, str):
                try: details = json.loads(details)
                except: details = {}

            monitor_data = {
                "data": {
                    "mid": mid,
                    "name": f"Coaching - {name}",
                    "type": m.get('type', 'h264'),
                    "ext": m.get('ext', 'mp4'),
                    "protocol": m.get('protocol', 'rtsp'),
                    "host": m.get('host', ''),
                    "path": m.get('path', ''),
                    "port": str(m.get('port', 554)),
                    "fps": str(m.get('fps', 15)),
                    "mode": "stop",
                    "width": str(m.get('width', 640)),
                    "height": str(m.get('height', 360)),
                    "details": details,
                }
            }

            try:
                url = f"http://127.0.0.1:8080/{session_token}/configureMonitor/{coaching_gk}/{mid}"
                req_data = json.dumps(monitor_data).encode()
                req = urllib.request.Request(url, data=req_data, headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result = json.loads(resp.read().decode())
                ok = result.get('ok', False)
                msg = result.get('msg', '')
                if ok:
                    cloned.append(mid)
                    log.info(f"Cloned monitor: {mid} ({name})")
                else:
                    failed.append({"mid": mid, "error": msg})
                    log.error(f"Clone failed: {mid}: {msg}")
            except Exception as e:
                failed.append({"mid": mid, "error": str(e)})
                log.error(f"Clone error: {mid}: {e}")

        handler._send_json({
            "success": len(cloned) > 0,
            "cloned": cloned,
            "failed": failed,
            "total_ops": len(ops_monitors),
        })
        return True

    def _handle_test_api(self, handler):
        """Test: login as coaching user and list monitors with session token."""
        from coaching_shinobi import _shinobi_get, _shinobi_post
        from coaching_config import get_config
        import urllib.request
        cfg = get_config()

        # Login as coaching user
        try:
            login_data = json.dumps({
                "mail": "coaching-mali@gravae.local",
                "pass": "DFap6c4fSAOUUGLM",
                "machineID": "test"
            }).encode()
            req = urllib.request.Request(
                "http://127.0.0.1:8080/?json=true",
                data=login_data,
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())

            user = result.get('$user', {})
            session_token = user.get('auth_token', '')
            gk = user.get('ke', '')

            # List monitors with session token
            monitors_via_session = _shinobi_get(f"/{session_token}/monitor/{gk}", timeout=10)
            session_summary = []
            if monitors_via_session:
                for m in monitors_via_session:
                    d = m.get('details', '{}')
                    if isinstance(d, str):
                        try: d = json.loads(d)
                        except: d = {}
                    session_summary.append({
                        "mid": m.get('mid'),
                        "host": m.get('host'),
                        "port": m.get('port'),
                        "auto_host": d.get('auto_host', '')[:60],
                    })

            # List with API key too
            api_key = cfg.get('shinobiApiKey')
            monitors_via_api = _shinobi_get(f"/{api_key}/monitor/{gk}", timeout=10)
            api_summary = []
            if monitors_via_api:
                for m in monitors_via_api:
                    d = m.get('details', '{}')
                    if isinstance(d, str):
                        try: d = json.loads(d)
                        except: d = {}
                    api_summary.append({
                        "mid": m.get('mid'),
                        "host": m.get('host'),
                        "port": m.get('port'),
                        "auto_host": d.get('auto_host', '')[:60],
                    })

            handler._send_json({
                "login_ok": bool(session_token),
                "gk": gk,
                "session_monitors": session_summary,
                "api_key_monitors": api_summary,
            })
        except Exception as e:
            handler._send_json({"error": str(e)})
        return True

    def _handle_fix_api_key(self, handler):
        """Fix coaching API key permissions to match OPS key pattern."""
        import subprocess, os
        from coaching_config import get_config
        cfg = get_config()
        gk = cfg.get('shinobiGroupKey', '')
        if not gk:
            handler._send_json({"error": "No coaching group key configured"}, 400)
            return True

        with open('/home/Shinobi/conf.json') as f:
            conf = json.load(f)
        db = conf.get('db', {})
        env = dict(os.environ)
        env['MYSQL_PWD'] = db.get('password') or ''
        cmd = ['mysql', '-u', db.get('user', 'majesticflame'), '-h', db.get('host', 'localhost'), db.get('database', 'ccio')]

        new_details = json.dumps({
            "treatAsSub": "0", "permissionSet": "", "monitorsRestricted": "0",
            "monitorPermissions": {},
            "auth_socket": "1", "create_api_keys": "1", "edit_user": "1",
            "edit_permissions": "1", "get_monitors": "1", "edit_monitors": "1",
            "control_monitors": "1", "get_logs": "1", "watch_stream": "1",
            "watch_snapshot": "1", "watch_videos": "1", "delete_videos": "1",
            "view_monitor": "1", "edit_monitor": "1", "view_events": "1",
            "delete_events": "1", "monitor_create": "1", "monitor_edit": "1",
            "monitor_delete": "1", "video_delete": "1", "event_delete": "1",
            "log_view": "1", "get_alarms": "1", "edit_alarms": "1"
        }).replace("'", "\\'")
        sql = f"UPDATE API SET details='{new_details}' WHERE ke='{gk}'"
        r = subprocess.run(cmd + ['-N', '-e', sql], env=env, capture_output=True, text=True, timeout=10)
        handler._send_json({"success": r.returncode == 0, "rc": r.returncode, "err": r.stderr[:200]})
        return True

    def _handle_configure(self, handler, data):
        """Handle POST /coaching/configure."""
        updated = update_config(data)
        if not updated:
            handler._send_json(
                {"success": False, "error": "No valid fields provided"}, 400
            )
            return True

        # Auto-start if newly configured and not running
        if self.is_configured() and (
            self._poll_thread is None or not self._poll_thread.is_alive()
        ):
            self.start()

        handler._send_json({
            "success": True,
            "updated": updated,
            "configured": self.is_configured(),
            "running": self._poll_thread is not None and self._poll_thread.is_alive(),
        })
        return True

    def _handle_test_record(self, handler, data):
        """Handle POST /coaching/test-record - test recording on a monitor."""
        monitor_id = data.get('monitorId')
        action = data.get('action', 'start')
        duration = data.get('duration', 1)  # minutes, default 1
        if not monitor_id:
            handler._send_json({"error": "monitorId required"}, 400)
            return True
        if action == 'stop':
            result = stop_recording(monitor_id)
        elif action == 'videos':
            videos = find_recent_videos(monitor_id)
            handler._send_json({"videos": videos})
            return True
        else:
            result = start_recording(monitor_id, duration)
        handler._send_json({"success": result.get('success', False), "result": result})
        return True

    def _handle_test_hls(self, handler, data):
        """Handle POST /coaching/test-hls - test HLS remux on recent videos.
        Usage: POST /coaching/test-hls {monitorId: "...", segmentDuration: 6}"""
        monitor_id = data.get('monitorId')
        segment_duration = data.get('segmentDuration', 6)

        if not monitor_id:
            handler._send_json({"error": "monitorId required"}, 400)
            return True

        # Find recent video files for this monitor
        videos = find_recent_videos(monitor_id)
        if not videos:
            handler._send_json({"error": "No video files found for this monitor"})
            return True

        # Use a test output directory
        test_id = f"test_{int(time.time())}"
        output_dir = os.path.join(HLS_DIR, test_id)

        result = _remux_to_hls(videos, output_dir, segment_duration)
        if not result:
            handler._send_json({"error": "HLS remux failed"})
            return True

        handler._send_json({
            "success": True,
            "inputFiles": len(videos),
            "inputTotalSize": sum(v['size'] for v in videos),
            "hlsSegments": len(result['segments']),
            "hlsTotalSize": result['total_size'],
            "hlsDir": output_dir,
            "manifest": result['manifest'],
        })
        return True

    def _handle_start(self, handler):
        """Handle POST /coaching/start."""
        if not self.is_configured():
            handler._send_json(
                {"success": False, "error": "Not configured"}, 400
            )
            return True
        started = self.start()
        handler._send_json({"success": started})
        return True

    def _handle_cancel(self, handler, session_id):
        """Handle POST /coaching/cancel/:sessionId."""
        with self._lock:
            session = self._active_sessions.pop(session_id, None)

        if not session:
            handler._send_json(
                {"success": False, "error": "Session not found"}, 404
            )
            return True

        proc = session.get('ffmpegProc')
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

        monitor_id = session.get('shinobiMonitorId')
        if monitor_id:
            stop_recording(monitor_id)

        self._update_session_status(session_id, 'canceled')
        handler._send_json({"success": True, "message": f"Session {session_id} canceled"})
        return True

    # ── Polling Loop ──────────────────────────────────────────────────────────

    def _polling_loop(self):
        """Poll the cloud API for recording jobs."""
        log.info("Polling loop started")

        while not self._stop_event.is_set():
            try:
                self._poll_once()
            except Exception as e:
                log.error(f"Poll error: {e}")

            try:
                self._stop_expired_sessions()
            except Exception as e:
                log.error(f"Local stop check error: {e}")

            try:
                self._recover_pending_hls_sessions()
            except Exception as e:
                log.error(f"Pending HLS recovery error: {e}")

            # Check HLS upload progress and report to API
            try:
                self._check_hls_progress()
            except Exception as e:
                log.error(f"HLS progress check error: {e}")

            # Send heartbeat
            try:
                self._send_heartbeat()
            except Exception as e:
                log.warning(f"Heartbeat error: {e}")

            self._stop_event.wait(POLL_INTERVAL)

        log.info("Polling loop ended")

    def _check_hls_progress(self):
        """Check HLS upload progress and report to API. Clean up when done.
        Also recovers orphaned sessions (uploads completed but not reported,
        e.g. after agent restart)."""
        from coaching_upload import _report_progress, _report_complete

        # Check tracked sessions first
        with self._lock:
            sessions = dict(self._hls_uploads)

        for session_id, info in sessions.items():
            if info.get('needs_registration'):
                session = info.get('session') or {}
                if self._ensure_session_registered(session_id, session):
                    self._scan_session_segments(session_id, session)
                    manifest_enqueued = self._enqueue_final_manifest(session_id, session)
                    with self._lock:
                        if session_id in self._hls_uploads:
                            self._hls_uploads[session_id].update({
                                'file_id': session.get('fileId'),
                                'recording_id': session.get('recordingId'),
                                'r2_prefix': session.get('r2Prefix'),
                                'needs_registration': False,
                                'manifest_enqueued': manifest_enqueued,
                                'total_size': self._hls_total_size(session.get('hlsDir')),
                                'session': session,
                            })
                    info = {
                        **info,
                        'file_id': session.get('fileId'),
                        'recording_id': session.get('recordingId'),
                        'r2_prefix': session.get('r2Prefix'),
                        'needs_registration': False,
                        'manifest_enqueued': manifest_enqueued,
                        'total_size': self._hls_total_size(session.get('hlsDir')),
                    }
                else:
                    log.warning(f"Session {session_id} waiting for internet/cloud registration")
                    continue

            if not info.get('manifest_enqueued'):
                session = info.get('session') or {}
                if session.get('recordingId') and self._enqueue_final_manifest(session_id, session):
                    with self._lock:
                        if session_id in self._hls_uploads:
                            self._hls_uploads[session_id]['manifest_enqueued'] = True
                    info = {**info, 'manifest_enqueued': True}

            progress_info = self._upload_queue.get_session_progress(session_id)
            if not progress_info or progress_info['total'] == 0:
                continue

            file_id = info['file_id']
            progress = progress_info['progress']

            # Report progress to API
            _report_progress(file_id, round(progress, 3))

            if progress_info['completed'] == progress_info['total']:
                # All files uploaded — report completion and clean up
                _report_complete(
                    file_id,
                    f"{info['r2_prefix']}/manifest.m3u8",
                    info['total_size'],
                )
                # Mark recording as ready (sets proxyManifestKey + session status)
                recording_id = info.get('recording_id')
                if recording_id:
                    self._complete_recording(recording_id, info['total_size'])
                else:
                    # Fallback: just update session status
                    self._update_session_status(session_id, 'ready')
                log.info(f"HLS upload completed: session={session_id}")

                # Clean up local files (HLS segments + original MP4s)
                self._cleanup_session_files(session_id, info)

                with self._lock:
                    self._hls_uploads.pop(session_id, None)

            elif progress_info['failed'] > 0:
                log.warning(f"HLS upload has {progress_info['failed']} "
                            f"failed segments for session {session_id}")

        # Recovery: check for orphaned sessions in SQLite that completed
        # but were never reported (e.g. after agent restart)
        self._recover_orphaned_uploads()

    _recovered_sessions = set()  # Track already-recovered sessions to avoid repeats

    def _recover_pending_hls_sessions(self):
        """Rebuild in-memory upload tracking from SQLite/local HLS after restart."""
        with self._lock:
            tracked = set(self._hls_uploads.keys()) | set(self._active_sessions.keys())

        # Re-track queued uploads that are not complete yet, so completion can
        # still notify the cloud after an agent restart.
        try:
            from coaching_upload import _get_db
            db = _get_db()
            try:
                rows = db.execute('''
                    SELECT session_id,
                           COUNT(*) as total,
                           SUM(total_bytes) as total_bytes,
                           MIN(CASE WHEN file_id NOT LIKE '_noreport_%' THEN file_id END) as file_id,
                           MIN(r2_key) as any_key
                    FROM uploads
                    WHERE status IN ('pending', 'uploading', 'completed')
                    GROUP BY session_id
                ''').fetchall()
            finally:
                db.close()
        except Exception as e:
            log.warning(f"Could not inspect upload DB for recovery: {e}")
            rows = []

        with self._lock:
            for session_id, _total, total_bytes, file_id, any_key in rows:
                if session_id in tracked or not any_key or not str(any_key).startswith('proxy/'):
                    continue
                parts = str(any_key).split('/')
                if len(parts) < 2:
                    continue
                recording_id = parts[1]
                self._hls_uploads[session_id] = {
                    'file_id': file_id or f"hls_{session_id}",
                    'recording_id': recording_id,
                    'r2_prefix': f"proxy/{recording_id}",
                    'total_size': total_bytes or 0,
                    'hls_dir': os.path.join(HLS_DIR, session_id),
                    'mp4_paths': [],
                    'needs_registration': False,
                    'manifest_enqueued': True,
                    'session': {
                        'sessionId': session_id,
                        'recordingId': recording_id,
                        'fileId': file_id or f"hls_{session_id}",
                        'r2Prefix': f"proxy/{recording_id}",
                        'hlsDir': os.path.join(HLS_DIR, session_id),
                        'seenSegments': set(),
                        'segmentSizes': {},
                    },
                }
                tracked.add(session_id)
                log.info(f"Recovered queued HLS upload tracking: session={session_id}")

        # Re-track local HLS dirs that never got cloud registration/upload rows.
        if not os.path.isdir(HLS_DIR):
            return

        with self._lock:
            tracked = set(self._hls_uploads.keys()) | set(self._active_sessions.keys())

        for session_id in os.listdir(HLS_DIR):
            hls_dir = os.path.join(HLS_DIR, session_id)
            if session_id in tracked or not os.path.isdir(hls_dir):
                continue
            if not os.path.exists(os.path.join(hls_dir, 'manifest.m3u8')):
                continue

            session = {
                'sessionId': session_id,
                'hlsDir': hls_dir,
                'seenSegments': set(),
                'segmentSizes': {},
            }
            with self._lock:
                if session_id not in self._hls_uploads and session_id not in self._active_sessions:
                    self._hls_uploads[session_id] = {
                        'file_id': None,
                        'recording_id': None,
                        'r2_prefix': None,
                        'total_size': self._hls_total_size(hls_dir),
                        'hls_dir': hls_dir,
                        'mp4_paths': [],
                        'needs_registration': True,
                        'manifest_enqueued': False,
                        'session': session,
                    }
                    log.info(f"Recovered local HLS directory waiting for cloud: session={session_id}")

    def _recover_orphaned_uploads(self):
        """Find sessions where all uploads completed but status was never
        reported to the API (happens after agent restart)."""
        try:
            from coaching_upload import _get_db
            db = _get_db()
            try:
                # Find sessions with uploads where ALL are completed
                # Also get the r2_key of the manifest to extract recording_id
                orphans = db.execute('''
                    SELECT session_id,
                           COUNT(*) as total,
                           SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as done,
                           SUM(total_bytes) as total_bytes
                    FROM uploads
                    GROUP BY session_id
                    HAVING total = done AND total > 0
                ''').fetchall()

                # Get recording IDs from r2_key patterns (proxy/{recordingId}/...)
                recording_ids = {}
                for session_id, _, _, _ in orphans:
                    row = db.execute('''
                        SELECT r2_key FROM uploads
                        WHERE session_id = ? AND r2_key LIKE 'proxy/%'
                        LIMIT 1
                    ''', (session_id,)).fetchone()
                    if row and row[0]:
                        # Extract recording ID from proxy/{recordingId}/filename
                        parts = row[0].split('/')
                        if len(parts) >= 2:
                            recording_ids[session_id] = parts[1]
            finally:
                db.close()

            with self._lock:
                tracked = set(self._hls_uploads.keys())

            for session_id, total, done, total_bytes in orphans:
                if session_id in tracked:
                    continue  # Already being tracked
                if session_id in self._recovered_sessions:
                    continue  # Already recovered in a previous cycle

                # This session completed but we lost tracking — report it
                log.info(f"Recovering orphaned upload: session={session_id} "
                         f"({done} files)", extra={"session_id": session_id})

                # Mark recording as ready if we have the recording ID
                recording_id = recording_ids.get(session_id)
                if recording_id:
                    self._complete_recording(recording_id, total_bytes or 0)
                else:
                    # Fallback: just update session status
                    self._update_session_status(session_id, 'ready')

                self._recovered_sessions.add(session_id)
                log.info(f"Orphaned session {session_id} marked as ready "
                         f"(recording={recording_id or 'unknown'})")

        except Exception as e:
            log.error(f"Error recovering orphaned uploads: {e}")

    def _cleanup_session_files(self, session_id, info):
        """Clean up local HLS segments and original MP4 files after upload."""
        import shutil

        # Remove HLS directory
        hls_dir = info.get('hls_dir')
        if hls_dir and os.path.isdir(hls_dir):
            try:
                shutil.rmtree(hls_dir)
                log.info(f"Cleaned up HLS dir: {hls_dir}")
            except Exception as e:
                log.warning(f"Failed to clean HLS dir: {e}")

        # Remove original MP4 files
        for mp4_path in info.get('mp4_paths', []):
            try:
                if os.path.exists(mp4_path):
                    os.remove(mp4_path)
                    log.info(f"Cleaned up MP4: {mp4_path}")
            except Exception as e:
                log.warning(f"Failed to clean MP4: {e}")

    def _poll_once(self):
        """Single poll iteration: fetch jobs and process them."""
        cfg = get_config()
        api_url = cfg.get('apiUrl')
        device_id = cfg.get('deviceId')
        device_token = cfg.get('deviceToken')

        if not all([api_url, device_id, device_token]):
            return

        # Fetch jobs
        url = f"{api_url}/devices/{device_id}/jobs"
        req = urllib.request.Request(url)
        req.add_header('X-Device-Token', device_token)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            log.error(f"Failed to fetch jobs: {e}")
            return

        jobs = data if isinstance(data, list) else data.get('jobs', [])

        for job in jobs:
            session_id = job.get('sessionId')
            action = job.get('action')

            if action == 'start':
                self._handle_start_job(job)
            elif action == 'stop':
                self._handle_stop_job(job)

    def _stop_expired_sessions(self):
        """Stop recordings locally when their planned duration ends.
        This is the offline safety net: if the internet is down and the cloud
        stop job cannot arrive, the Pi still closes the recording on time and
        keeps the HLS files queued on disk."""
        now = time.time()
        expired = []
        with self._lock:
            for session_id, session in list(self._active_sessions.items()):
                stop_at = session.get('localStopAt')
                if stop_at and now >= stop_at:
                    expired.append((session_id, self._active_sessions.pop(session_id)))

        for session_id, session in expired:
            monitor_id = session.get('shinobiMonitorId')
            log.info(f"Local stop fired for session={session_id} monitor={monitor_id}")
            if monitor_id:
                try:
                    stop_recording(monitor_id)
                except Exception as e:
                    log.warning(f"Failed to stop Shinobi monitor {monitor_id}: {e}")
            self._stop_ffmpeg_session(session_id, session, mark_uploading=True)

    def _handle_start_job(self, job):
        """Handle a 'start' recording job with offline-safe live HLS capture."""
        session_id = job['sessionId']

        with self._lock:
            if session_id in self._active_sessions:
                return  # Already handling this session

        monitor_id = job.get('shinobiMonitorId')
        duration = job.get('durationMinutes', 120)
        camera_id = job.get('cameraId')
        local_stop_at = record_start = time.time()
        try:
            local_stop_at = record_start + (float(duration) * 60)
        except Exception:
            local_stop_at = record_start + (120 * 60)

        log.info(f"Starting recording: session={session_id} "
                 f"monitor={monitor_id} duration={duration}min")

        hls_output_dir = os.path.join(HLS_DIR, session_id)
        os.makedirs(hls_output_dir, exist_ok=True)

        try:
            _ensure_monitor_watching(monitor_id)
            rtsp_url = get_monitor_rtsp_url(monitor_id)
            if not rtsp_url:
                raise RuntimeError(f"Could not resolve RTSP URL for monitor {monitor_id}")

            manifest_path = os.path.join(hls_output_dir, 'manifest.m3u8')
            segment_pattern = os.path.join(hls_output_dir, 'seg_%06d.ts')
            ffmpeg_cmd = [
                'ffmpeg',
                '-hide_banner',
                '-loglevel', 'warning',
                '-rtsp_transport', 'tcp',
                '-i', rtsp_url,
                '-codec', 'copy',
                '-f', 'hls',
                '-hls_time', str(SEGMENT_DURATION_SECONDS),
                '-hls_playlist_type', 'event',
                '-hls_segment_filename', segment_pattern,
                manifest_path,
            ]

            proc = subprocess.Popen(
                ffmpeg_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            time.sleep(3)
            if proc.poll() is not None:
                stderr = ''
                try:
                    stderr = proc.stderr.read().decode('utf-8', errors='replace')[-1000:]
                except Exception:
                    pass
                raise RuntimeError(f"ffmpeg exited immediately: {stderr or proc.returncode}")

            recording_info = self._try_register_hls_recording(session_id)
            recording_id = recording_info.get('recording_id') if recording_info else None
            file_id = recording_info.get('file_id') if recording_info else None
            r2_prefix = f"proxy/{recording_id}" if recording_id else None

            with self._lock:
                self._active_sessions[session_id] = {
                    'sessionId': session_id,
                    'cameraId': camera_id,
                    'shinobiMonitorId': monitor_id,
                    'startedAt': datetime.now(timezone.utc).isoformat(),
                    'recordStartTime': record_start,
                    'durationMinutes': duration,
                    'localStopAt': local_stop_at,
                    'ffmpegProc': proc,
                    'hlsDir': hls_output_dir,
                    'recordingId': recording_id,
                    'fileId': file_id,
                    'r2Prefix': r2_prefix,
                    'seenSegments': set(),
                    'segmentSizes': {},
                }

            watcher = threading.Thread(
                target=self._segment_watcher_loop,
                args=(session_id,),
                daemon=True,
                name=f"hls-watch-{session_id[:8]}",
            )
            watcher.start()
            with self._lock:
                if session_id in self._active_sessions:
                    self._active_sessions[session_id]['watcherThread'] = watcher

            self._update_session_status(session_id, 'running')
            log.info(f"Live HLS capture started: session={session_id} pid={proc.pid}")
        except Exception as e:
            log.error(f"Failed to start live HLS recording: {e}")
            self._update_session_status(session_id, 'failed', str(e))

    def _handle_stop_job(self, job):
        """Handle a 'stop' recording job — stop ffmpeg and keep/upload HLS files."""
        session_id = job['sessionId']
        monitor_id = job.get('shinobiMonitorId')

        with self._lock:
            session = self._active_sessions.pop(session_id, None)

        if not session and not monitor_id:
            return

        if not monitor_id:
            monitor_id = session.get('shinobiMonitorId') if session else None

        if monitor_id:
            stop_recording(monitor_id)

        log.info(f"Recording stopped: session={session_id}")
        self._stop_ffmpeg_session(session_id, session, mark_uploading=True)

    def _segment_watcher_loop(self, session_id):
        """Watch live HLS output and enqueue finalized segments without blocking recording."""
        log.info(f"HLS watcher started: session={session_id}")
        while not self._stop_event.is_set():
            with self._lock:
                session = self._active_sessions.get(session_id)
            if not session:
                break

            try:
                if not session.get('recordingId'):
                    self._ensure_session_registered(session_id, session)
                self._scan_session_segments(session_id, session)
            except Exception as e:
                log.warning(f"HLS watcher error for {session_id}: {e}")

            self._stop_event.wait(SEGMENT_WATCH_INTERVAL)

        log.info(f"HLS watcher stopped: session={session_id}")

    def _scan_session_segments(self, session_id, session):
        """Enqueue closed .ts segments. If offline/unregistered, keep files local."""
        hls_dir = session.get('hlsDir')
        recording_id = session.get('recordingId')
        file_id = session.get('fileId')
        r2_prefix = session.get('r2Prefix')
        if not hls_dir or not os.path.isdir(hls_dir):
            return 0

        seen = session.setdefault('seenSegments', set())
        sizes = session.setdefault('segmentSizes', {})
        enqueued = 0
        cfg = get_config()
        proxy_bucket = cfg.get('r2BucketProxy', 'coachingreview-proxy')

        for filename in sorted(os.listdir(hls_dir)):
            if not filename.endswith('.ts') or filename in seen:
                continue

            path = os.path.join(hls_dir, filename)
            try:
                current_size = os.path.getsize(path)
            except OSError:
                continue

            previous_size = sizes.get(filename)
            sizes[filename] = current_size
            if previous_size is None or current_size != previous_size or current_size <= 0:
                continue

            if not recording_id or not file_id or not r2_prefix:
                # No cloud record yet. Leave the closed segment on disk and try
                # registration again later; recording itself keeps running.
                continue

            segment_file_id = f"_noreport_{file_id}_{filename}"
            r2_key = f"{r2_prefix}/{filename}"
            if self._upload_queue.enqueue(session_id, segment_file_id, path, r2_key, proxy_bucket):
                seen.add(filename)
                enqueued += 1
                log.info(f"Enqueued HLS segment: session={session_id} file={filename}")

        return enqueued

    def _stop_ffmpeg_session(self, session_id, session, mark_uploading=True):
        """Stop local HLS capture. Upload may continue later if the internet is down."""
        if not session:
            return

        proc = session.get('ffmpegProc')
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                log.warning(f"ffmpeg did not exit cleanly for {session_id}; killing")
                proc.kill()
                proc.wait(timeout=5)
            except Exception as e:
                log.warning(f"Failed to stop ffmpeg for {session_id}: {e}")

        # Give ffmpeg a moment to write the final segment and #EXT-X-ENDLIST.
        time.sleep(2)

        self._ensure_session_registered(session_id, session)
        self._scan_session_segments(session_id, session)

        hls_dir = session.get('hlsDir')
        total_size = self._hls_total_size(hls_dir)
        with self._lock:
            self._hls_uploads[session_id] = {
                'file_id': session.get('fileId'),
                'recording_id': session.get('recordingId'),
                'r2_prefix': session.get('r2Prefix'),
                'total_size': total_size,
                'hls_dir': hls_dir,
                'mp4_paths': [],
                'needs_registration': not bool(session.get('recordingId')),
                'manifest_enqueued': False,
                'session': session,
            }

        if session.get('recordingId'):
            self._enqueue_final_manifest(session_id, session)
            with self._lock:
                if session_id in self._hls_uploads:
                    self._hls_uploads[session_id]['manifest_enqueued'] = True

        if mark_uploading:
            self._update_session_status(session_id, 'uploading')

    def _ensure_session_registered(self, session_id, session):
        """Try to create the cloud Recording. Failure is non-fatal/offline-safe."""
        if session.get('recordingId'):
            return True

        recording_info = self._try_register_hls_recording(session_id)
        if not recording_info:
            return False

        session['recordingId'] = recording_info['recording_id']
        session['fileId'] = recording_info['file_id']
        session['r2Prefix'] = f"proxy/{recording_info['recording_id']}"
        log.info(f"Cloud recording registered: session={session_id} recording={session['recordingId']}")
        return True

    def _try_register_hls_recording(self, session_id):
        recording_info = self._register_recording(session_id, [{
            'filename': 'manifest.m3u8',
            'size': 0,
            'format': 'hls',
        }])
        if not recording_info:
            return None

        files = recording_info.get('files', [])
        file_id = files[0].get('id') if files else f"hls_{session_id}"
        return {
            'recording_id': recording_info.get('id'),
            'file_id': file_id,
        } if recording_info.get('id') else None

    def _enqueue_final_manifest(self, session_id, session):
        hls_dir = session.get('hlsDir')
        file_id = session.get('fileId')
        r2_prefix = session.get('r2Prefix')
        if not hls_dir or not file_id or not r2_prefix:
            return False

        # Catch any segment that stabilized only after the last scan.
        for _ in range(2):
            self._scan_session_segments(session_id, session)
            time.sleep(1)

        manifest_path = os.path.join(hls_dir, 'manifest.m3u8')
        if not os.path.exists(manifest_path):
            log.error(f"Manifest not found for session {session_id}: {manifest_path}")
            return False

        cfg = get_config()
        proxy_bucket = cfg.get('r2BucketProxy', 'coachingreview-proxy')
        return bool(self._upload_queue.enqueue(
            session_id,
            file_id,
            manifest_path,
            f"{r2_prefix}/manifest.m3u8",
            proxy_bucket,
        ))

    def _hls_total_size(self, hls_dir):
        if not hls_dir or not os.path.isdir(hls_dir):
            return 0
        total = 0
        for filename in os.listdir(hls_dir):
            path = os.path.join(hls_dir, filename)
            if os.path.isfile(path) and (filename.endswith('.ts') or filename.endswith('.m3u8')):
                try:
                    total += os.path.getsize(path)
                except OSError:
                    pass
        return total

    # ── Upload Loop ───────────────────────────────────────────────────────────

    def _upload_loop(self):
        """Run the upload queue processor."""
        self._upload_queue.process_queue(stop_event=self._stop_event)

    # ── Cloud API Helpers ─────────────────────────────────────────────────────

    def _send_heartbeat(self):
        """Send heartbeat to cloud API."""
        cfg = get_config()
        api_url = cfg.get('apiUrl')
        device_id = cfg.get('deviceId')
        device_token = cfg.get('deviceToken')

        if not all([api_url, device_id, device_token]):
            return

        url = f"{api_url}/devices/{device_id}/heartbeat"
        data = json.dumps({
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }).encode()

        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Device-Token', device_token)

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
        except Exception:
            pass  # Heartbeat failure is non-critical

    def _update_session_status(self, session_id, status, fail_reason=None):
        """Update session status on the cloud API."""
        cfg = get_config()
        api_url = cfg.get('apiUrl')
        device_token = cfg.get('deviceToken')

        if not api_url or not device_token:
            return

        url = f"{api_url}/sessions/{session_id}/status"
        payload = {'status': status}
        if fail_reason:
            payload['failReason'] = fail_reason

        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Device-Token', device_token)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except Exception as e:
            log.error(f"Failed to update session status: {e}")

    def _complete_recording(self, recording_id, size_bytes=0):
        """Mark recording as ready on the cloud API.
        This sets recording.status=ready, recording.proxyManifestKey,
        and also sets session.status=ready in the same transaction."""
        cfg = get_config()
        api_url = cfg.get('apiUrl')
        device_token = cfg.get('deviceToken')

        if not api_url or not device_token:
            return

        url = f"{api_url}/recordings/{recording_id}/complete-upload"
        payload = {}
        if size_bytes:
            payload['sizeBytes'] = size_bytes

        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Device-Token', device_token)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                log.info(f"Recording {recording_id} marked as ready: {result}")
        except Exception as e:
            log.error(f"Failed to complete recording {recording_id}: {e}")
            # Fallback: try updating session status directly
            # (won't fix recording but at least session status is correct)

    def _register_recording(self, session_id, videos):
        """Register a recording with the cloud API."""
        cfg = get_config()
        api_url = cfg.get('apiUrl')
        device_token = cfg.get('deviceToken')

        if not api_url or not device_token:
            return None

        url = f"{api_url}/recordings"
        files_data = []
        for v in videos:
            entry = {'filename': v['filename'], 'sizeBytes': v['size']}
            if 'format' in v:
                entry['format'] = v['format']
            if 'segmentCount' in v:
                entry['segmentCount'] = v['segmentCount']
            files_data.append(entry)
        payload = {'sessionId': session_id, 'files': files_data}
        data = json.dumps(payload).encode()

        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Device-Token', device_token)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            log.error(f"Failed to register recording: {e}")
            return None
