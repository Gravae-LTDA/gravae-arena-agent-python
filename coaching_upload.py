"""
Coaching Review - SQLite-backed upload queue for R2 multipart uploads.
Supports resume after restart, throttling, and progress reporting.
"""
import json
import os
import sqlite3
import time
import traceback
import urllib.request
import urllib.error
from datetime import datetime, timezone

from coaching_s3 import S3Client
from coaching_config import get_config

try:
    from gravae_logging import get_logger
    log = get_logger('upload')
except ImportError:
    import logging
    log = logging.getLogger('upload')

DB_PATH = "/var/lib/gravae-coaching/uploads.db"
DEFAULT_PART_SIZE = 16 * 1024 * 1024  # 16 MB
DEFAULT_THROTTLE = 2 * 1024 * 1024    # 2 MB/s
MAX_RETRIES = 50
RETRY_DELAYS = [30, 60, 120, 240, 480]  # Exponential backoff


def _init_db():
    """Initialize SQLite database with upload tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS uploads (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        file_id TEXT NOT NULL,
        local_path TEXT NOT NULL,
        r2_key TEXT NOT NULL,
        r2_bucket TEXT NOT NULL,
        upload_id TEXT,
        total_bytes INTEGER,
        uploaded_bytes INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending',
        retry_count INTEGER DEFAULT 0,
        last_error TEXT,
        created_at TEXT,
        updated_at TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS upload_parts (
        upload_row_id TEXT NOT NULL,
        part_number INTEGER NOT NULL,
        etag TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        PRIMARY KEY (upload_row_id, part_number),
        FOREIGN KEY (upload_row_id) REFERENCES uploads(id)
    )''')
    conn.commit()
    return conn


def _get_db():
    """Get a database connection (thread-local recommended)."""
    return _init_db()


def _content_type_for(path):
    """Determine Content-Type based on file extension."""
    if path.endswith('.m3u8'):
        return 'application/vnd.apple.mpegurl'
    elif path.endswith('.ts'):
        return 'video/mp2t'
    elif path.endswith('.mp4'):
        return 'video/mp4'
    return 'application/octet-stream'


def _report_progress(file_id, progress, status='uploading'):
    """Report upload progress to the cloud API."""
    if file_id.startswith('_noreport_'):
        return
    cfg = get_config()
    api_url = cfg.get('apiUrl')
    device_token = cfg.get('deviceToken')
    if not api_url or not device_token:
        return

    url = f"{api_url}/uploads/{file_id}/progress"
    data = json.dumps({'progress': progress, 'status': status}).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Device-Token', device_token)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        log.warning(f"Failed to report progress: {e}")


def _report_complete(file_id, r2_key, size_bytes):
    """Report upload completion to the cloud API."""
    if file_id.startswith('_noreport_'):
        return
    cfg = get_config()
    api_url = cfg.get('apiUrl')
    device_token = cfg.get('deviceToken')
    if not api_url or not device_token:
        return

    url = f"{api_url}/uploads/{file_id}/complete"
    data = json.dumps({'r2Key': r2_key, 'sizeBytes': size_bytes}).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Device-Token', device_token)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        log.info(f"Reported completion: {file_id}")
    except Exception as e:
        log.warning(f"Failed to report completion: {e}")


class UploadQueue:
    """Manages file uploads to R2 with resume support."""

    def __init__(self):
        self._s3 = None

    def _get_s3(self):
        """Lazily create S3 client from config."""
        if self._s3 is None:
            cfg = get_config()
            endpoint = cfg.get('r2Endpoint')
            access_key = cfg.get('r2AccessKeyId')
            secret_key = cfg.get('r2SecretAccessKey')
            if not all([endpoint, access_key, secret_key]):
                raise Exception("R2 credentials not configured")
            self._s3 = S3Client(endpoint, access_key, secret_key)
        return self._s3

    def enqueue(self, session_id, file_id, local_path, r2_key, r2_bucket=None):
        """Add a file to the upload queue."""
        cfg = get_config()
        bucket = r2_bucket or cfg.get('r2BucketMaster', 'coachingreview-master')

        if not os.path.exists(local_path):
            log.warning(f"File not found: {local_path}")
            return None

        total_bytes = os.path.getsize(local_path)
        now = datetime.now(timezone.utc).isoformat()
        upload_id = f"upload_{session_id}_{file_id}_{int(time.time())}"

        db = _get_db()
        try:
            db.execute(
                '''INSERT OR REPLACE INTO uploads
                   (id, session_id, file_id, local_path, r2_key, r2_bucket,
                    total_bytes, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)''',
                (upload_id, session_id, file_id, local_path, r2_key, bucket,
                 total_bytes, now, now)
            )
            db.commit()
            log.info(f"Enqueued: {os.path.basename(local_path)} -> {r2_key} ({total_bytes} bytes)")
            return upload_id
        finally:
            db.close()

    def get_queue_status(self, detailed=False):
        """Get current queue status. Returns summary by default, full list if detailed=True."""
        db = _get_db()
        try:
            # Always get counts for summary
            counts = db.execute(
                '''SELECT status, COUNT(*) FROM uploads GROUP BY status'''
            ).fetchall()
            summary = {
                'total': 0, 'pending': 0, 'uploading': 0,
                'completed': 0, 'failed': 0, 'running': True,
            }
            for status, count in counts:
                summary['total'] += count
                if status in summary:
                    summary[status] = count

            if not detailed:
                return summary

            # Full list with details
            rows = db.execute(
                '''SELECT id, session_id, file_id, r2_key, status,
                          total_bytes, uploaded_bytes, retry_count, last_error
                   FROM uploads ORDER BY created_at'''
            ).fetchall()
            summary['items'] = [{
                'id': r[0], 'sessionId': r[1], 'fileId': r[2],
                'r2Key': r[3], 'status': r[4],
                'totalBytes': r[5], 'uploadedBytes': r[6],
                'retryCount': r[7], 'lastError': r[8],
            } for r in rows]
            return summary
        finally:
            db.close()

    def process_queue(self, stop_event=None):
        """Process pending uploads. Runs continuously until stopped.
        Fixed: retry delay no longer blocks the entire queue. Failed items
        are skipped until their retry delay has elapsed."""
        log.info("Upload queue processor started")

        # Track when each failed upload can be retried (row_id -> timestamp)
        _retry_after = {}
        _last_status_log = 0

        while True:
            if stop_event and stop_event.is_set():
                log.info("Upload queue processor stopping")
                break

            try:
                db = _get_db()
                try:
                    rows = db.execute(
                        '''SELECT id, session_id, file_id, local_path, r2_key,
                                  r2_bucket, upload_id, total_bytes, uploaded_bytes,
                                  retry_count
                           FROM uploads
                           WHERE status IN ('pending', 'uploading')
                           ORDER BY created_at
                           LIMIT 10'''
                    ).fetchall()
                finally:
                    db.close()
            except Exception as e:
                log.error(f"Database error reading queue: {e}")
                time.sleep(10)
                continue

            if not rows:
                time.sleep(5)
                continue

            # Log queue status periodically (every 60s)
            now = time.time()
            if now - _last_status_log > 60:
                log.info(f"Queue: {len(rows)} pending items")
                _last_status_log = now

            # Find next item that's ready (not in retry cooldown)
            processed_any = False
            for row in rows:
                row_id = row[0]

                # Check if this item is in retry cooldown
                retry_time = _retry_after.get(row_id, 0)
                if now < retry_time:
                    continue  # Skip, try next item

                (row_id, session_id, file_id, local_path, r2_key,
                 r2_bucket, multipart_id, total_bytes, uploaded_bytes,
                 retry_count) = row

                try:
                    log.info(f"Uploading: {os.path.basename(local_path)} "
                             f"({total_bytes} bytes, retry={retry_count})",
                             extra={"r2_key": r2_key, "session_id": session_id})
                    self._process_upload(
                        row_id, session_id, file_id, local_path, r2_key,
                        r2_bucket, multipart_id, total_bytes, uploaded_bytes
                    )
                    # Success - remove from retry tracking
                    _retry_after.pop(row_id, None)
                    processed_any = True
                    break  # Process one at a time, then re-check queue
                except Exception as e:
                    log.error(f"Upload failed: {os.path.basename(local_path)} - {e}",
                              extra={"r2_key": r2_key, "retry": retry_count,
                                     "traceback": traceback.format_exc()[-500:]})
                    # Set retry cooldown WITHOUT blocking the thread
                    delay_idx = min(retry_count, len(RETRY_DELAYS) - 1)
                    delay = RETRY_DELAYS[delay_idx]
                    _retry_after[row_id] = now + delay
                    self._mark_retry_no_sleep(row_id, str(e), retry_count)
                    # Continue to try next item in queue

            if not processed_any:
                # All items are in retry cooldown or queue is empty
                time.sleep(5)

    def _process_upload(self, row_id, session_id, file_id, local_path,
                        r2_key, r2_bucket, multipart_id, total_bytes, uploaded_bytes):
        """Process a single upload with multipart."""
        cfg = get_config()
        part_size = cfg.get('uploadPartSizeBytes', DEFAULT_PART_SIZE)
        throttle = cfg.get('uploadThrottleBytesPerSec', DEFAULT_THROTTLE)

        if not os.path.exists(local_path):
            self._mark_failed(row_id, "File not found on disk")
            return

        s3 = self._get_s3()
        actual_size = os.path.getsize(local_path)

        content_type = _content_type_for(local_path)

        # For small files (< part_size), use simple PUT
        if actual_size < part_size:
            self._update_status(row_id, 'uploading')
            _report_progress(file_id, 0.0)

            with open(local_path, 'rb') as f:
                data = f.read()

            s3.put_object(r2_bucket, r2_key, data, content_type=content_type)
            self._mark_completed(row_id, actual_size)
            _report_progress(file_id, 1.0, 'completed')
            _report_complete(file_id, r2_key, actual_size)
            return

        # Multipart upload
        db = _get_db()

        # Resume or start new multipart upload
        if not multipart_id:
            multipart_id = s3.create_multipart_upload(r2_bucket, r2_key, content_type=content_type)
            db.execute(
                "UPDATE uploads SET upload_id = ?, status = 'uploading', updated_at = ? WHERE id = ?",
                (multipart_id, datetime.now(timezone.utc).isoformat(), row_id)
            )
            db.commit()

        # Get already completed parts
        completed_parts = {}
        try:
            rows = db.execute(
                "SELECT part_number, etag, size_bytes FROM upload_parts WHERE upload_row_id = ?",
                (row_id,)
            ).fetchall()
            for p in rows:
                completed_parts[p[0]] = (p[0], p[1])
                uploaded_bytes += p[2]
        finally:
            db.close()

        # Calculate total parts
        total_parts = (actual_size + part_size - 1) // part_size

        with open(local_path, 'rb') as f:
            for part_num in range(1, total_parts + 1):
                if part_num in completed_parts:
                    f.seek(part_num * part_size)  # Skip already uploaded parts
                    continue

                offset = (part_num - 1) * part_size
                f.seek(offset)
                chunk = f.read(part_size)
                if not chunk:
                    break

                # Upload part
                etag = s3.upload_part(r2_bucket, r2_key, multipart_id, part_num, chunk)

                # Save part to DB
                db = _get_db()
                try:
                    db.execute(
                        "INSERT OR REPLACE INTO upload_parts (upload_row_id, part_number, etag, size_bytes) VALUES (?, ?, ?, ?)",
                        (row_id, part_num, etag, len(chunk))
                    )
                    uploaded_bytes += len(chunk)
                    progress = uploaded_bytes / actual_size if actual_size > 0 else 0
                    db.execute(
                        "UPDATE uploads SET uploaded_bytes = ?, updated_at = ? WHERE id = ?",
                        (uploaded_bytes, datetime.now(timezone.utc).isoformat(), row_id)
                    )
                    db.commit()
                finally:
                    db.close()

                # Report progress
                progress = uploaded_bytes / actual_size if actual_size > 0 else 0
                _report_progress(file_id, round(progress, 3))

                log.debug(f"Part {part_num}/{total_parts} "
                          f"({int(progress * 100)}%) - {os.path.basename(r2_key)}")

                # Throttle
                if throttle > 0:
                    sleep_time = len(chunk) / throttle
                    time.sleep(sleep_time)

        # Complete multipart upload
        db = _get_db()
        try:
            all_parts = db.execute(
                "SELECT part_number, etag FROM upload_parts WHERE upload_row_id = ? ORDER BY part_number",
                (row_id,)
            ).fetchall()
        finally:
            db.close()

        parts = [(p[0], p[1]) for p in all_parts]
        s3.complete_multipart_upload(r2_bucket, r2_key, multipart_id, parts)

        self._mark_completed(row_id, actual_size)
        _report_progress(file_id, 1.0, 'completed')
        _report_complete(file_id, r2_key, actual_size)

    def _update_status(self, row_id, status):
        db = _get_db()
        try:
            db.execute(
                "UPDATE uploads SET status = ?, updated_at = ? WHERE id = ?",
                (status, datetime.now(timezone.utc).isoformat(), row_id)
            )
            db.commit()
        finally:
            db.close()

    def _mark_completed(self, row_id, size_bytes):
        db = _get_db()
        try:
            db.execute(
                "UPDATE uploads SET status = 'completed', uploaded_bytes = ?, updated_at = ? WHERE id = ?",
                (size_bytes, datetime.now(timezone.utc).isoformat(), row_id)
            )
            db.commit()
            log.info(f"Upload completed: {row_id}")
        finally:
            db.close()

    def _mark_failed(self, row_id, error):
        db = _get_db()
        try:
            db.execute(
                "UPDATE uploads SET status = 'failed', last_error = ?, updated_at = ? WHERE id = ?",
                (error, datetime.now(timezone.utc).isoformat(), row_id)
            )
            db.commit()
            log.error(f"Upload FAILED permanently: {row_id} - {error}")
        finally:
            db.close()

    def _mark_retry(self, row_id, error, current_retry):
        """Legacy retry method that sleeps (kept for compatibility)."""
        self._mark_retry_no_sleep(row_id, error, current_retry)
        if current_retry < MAX_RETRIES:
            delay_idx = min(current_retry, len(RETRY_DELAYS) - 1)
            time.sleep(RETRY_DELAYS[delay_idx])

    def _mark_retry_no_sleep(self, row_id, error, current_retry):
        """Mark upload for retry WITHOUT sleeping (non-blocking)."""
        if current_retry >= MAX_RETRIES:
            self._mark_failed(row_id, f"Max retries exceeded. Last: {error}")
            return

        delay_idx = min(current_retry, len(RETRY_DELAYS) - 1)
        delay = RETRY_DELAYS[delay_idx]

        db = _get_db()
        try:
            db.execute(
                '''UPDATE uploads SET retry_count = ?, last_error = ?,
                   updated_at = ? WHERE id = ?''',
                (current_retry + 1, error, datetime.now(timezone.utc).isoformat(), row_id)
            )
            db.commit()
        finally:
            db.close()

        log.warning(f"Retry {current_retry + 1}/{MAX_RETRIES} in {delay}s for {row_id}: {error}")

    def enqueue_hls(self, session_id, file_id, hls_dir, r2_prefix, r2_bucket=None):
        """Enqueue all HLS files (segments + manifest) for upload.
        Segments use _noreport_ prefix to skip per-file API reporting.
        The manifest uses the real file_id for API completion reporting.
        """
        cfg = get_config()
        bucket = r2_bucket or cfg.get('r2BucketMaster', 'coachingreview-master')

        files = sorted(os.listdir(hls_dir))
        segments = [f for f in files if f.endswith('.ts')]
        manifests = [f for f in files if f.endswith('.m3u8')]

        enqueued = 0

        # Enqueue segments first (no individual API reporting)
        for seg in segments:
            local_path = os.path.join(hls_dir, seg)
            r2_key = f"{r2_prefix}/{seg}"
            seg_file_id = f"_noreport_{file_id}_{seg}"
            if self.enqueue(session_id, seg_file_id, local_path, r2_key, bucket):
                enqueued += 1

        # Enqueue manifest last (uses real file_id for API reporting)
        for m in manifests:
            local_path = os.path.join(hls_dir, m)
            r2_key = f"{r2_prefix}/{m}"
            if self.enqueue(session_id, file_id, local_path, r2_key, bucket):
                enqueued += 1

        log.info(f"Enqueued HLS: {len(segments)} segments + "
                 f"{len(manifests)} manifest(s) = {enqueued} files")
        return enqueued

    def get_session_progress(self, session_id):
        """Get upload progress for a session (completed/total files)."""
        db = _get_db()
        try:
            total = db.execute(
                "SELECT COUNT(*) FROM uploads WHERE session_id = ?",
                (session_id,)
            ).fetchone()[0]
            completed = db.execute(
                "SELECT COUNT(*) FROM uploads WHERE session_id = ? AND status = 'completed'",
                (session_id,)
            ).fetchone()[0]
            failed = db.execute(
                "SELECT COUNT(*) FROM uploads WHERE session_id = ? AND status = 'failed'",
                (session_id,)
            ).fetchone()[0]
            return {
                'total': total,
                'completed': completed,
                'failed': failed,
                'progress': completed / total if total > 0 else 0,
            }
        finally:
            db.close()
