"""Durable direct-upload spool. One worker; no permanent object-storage keys."""

import argparse
from datetime import datetime, timezone
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.request
from urllib.parse import quote, urlsplit

from media_mode import direct_enabled
from adaptive_upload import AdaptiveBandwidth, upload_file
from video_completion_webhook import start_completion_server


class QueueFull(Exception):
    pass


class PermanentUploadError(Exception):
    pass


def open_writer_inodes(proc_root="/proc"):
    """Fail closed if descriptor visibility is incomplete; never enqueue an open writer."""
    writers = set()
    for process in Path(proc_root).iterdir():
        if not process.name.isdigit():
            continue
        try:
            for fd in (process / "fd").iterdir():
                try:
                    info = (process / "fdinfo" / fd.name).read_text()
                    flags = next(int(line.split()[1], 8) for line in info.splitlines()
                                 if line.startswith("flags:"))
                    if flags & os.O_ACCMODE != os.O_RDONLY:
                        stat = fd.stat()
                        writers.add((stat.st_dev, stat.st_ino))
                except FileNotFoundError:
                    continue  # Descriptor/process closed during the scan.
        except FileNotFoundError:
            continue
    return writers


def reject_internal_credentials(config):
    if any(key in config for key in ("EXTERNAL_KEY", "externalKey", "ARENA_DEVICE_WEBHOOK_TOKEN", "webhookToken")):
        raise ValueError("SHARED_BACKEND_TOKEN_FORBIDDEN")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UploadQueue:
    def __init__(self, root, max_items=1000, max_bytes=8 * 1024**3, min_free=2 * 1024**3):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.spool = self.root / "spool"
        self.spool.mkdir(exist_ok=True, mode=0o700)
        self.max_items, self.max_bytes, self.min_free = max_items, max_bytes, min_free
        self.db_path = self.root / "queue.sqlite3"
        with closing(self.connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, source TEXT NOT NULL, spool TEXT NOT NULL,
                    monitor_id TEXT NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL DEFAULT 0, created REAL NOT NULL,
                    updated REAL NOT NULL, error TEXT, receipt TEXT
                );
                CREATE INDEX IF NOT EXISTS jobs_due ON jobs(state,next_attempt,created);
            """)

    def connect(self):
        db = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=10000")
        return db

    def enqueue(self, source, monitor_id, device_id):
        source = Path(source).resolve(strict=True)
        stat = source.stat()
        if not source.is_file() or stat.st_size == 0:
            raise ValueError("EMPTY_OR_INVALID_FILE")
        identity = json.dumps([device_id, monitor_id, source.name, stat.st_size, stat.st_mtime_ns])
        job_id = hashlib.sha256(identity.encode()).hexdigest()
        destination = self.spool / (job_id + source.suffix)
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone():
                    db.execute("COMMIT")
                    return job_id
                count, size = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(size),0) FROM jobs WHERE state!='completed'"
                ).fetchone()
                if (count >= self.max_items or size + stat.st_size > self.max_bytes or
                        shutil.disk_usage(self.root).free < self.min_free):
                    raise QueueFull("QUEUE_CAPACITY_OR_DISK_RESERVE")
                # A hard link keeps the finalized clip alive if Shinobi retention removes its name.
                # Cross-filesystem spools are rejected instead of copying a large file in the producer.
                if not destination.exists():
                    os.link(source, destination)
                directory = os.open(self.spool, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                now = time.time()
                db.execute("INSERT INTO jobs(id,source,spool,monitor_id,size,mtime_ns,created,updated) "
                           "VALUES(?,?,?,?,?,?,?,?)",
                           (job_id, str(source), str(destination), monitor_id, stat.st_size,
                            stat.st_mtime_ns, now, now))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return job_id

    def recover(self):
        with closing(self.connect()) as db:
            db.execute("UPDATE jobs SET state='retry',error='WORKER_RESTARTED',updated=? "
                       "WHERE state='uploading'", (time.time(),))
            # Recover a crash after completion was committed but before spool unlink.
            for row in db.execute("SELECT spool FROM jobs WHERE state='completed'"):
                Path(row[0]).unlink(missing_ok=True)

    def claim(self, selected_ids=None):
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            selection = "" if selected_ids is None else " AND id IN (" + ",".join("?" for _ in selected_ids) + ")"
            row = db.execute("SELECT * FROM jobs WHERE state IN ('pending','retry','fail_reporting') "
                             "AND next_attempt<=?" + selection + " ORDER BY created LIMIT 1",
                             (time.time(), *(selected_ids or []))).fetchone()
            if row:
                state = "fail_reporting" if row["state"] == "fail_reporting" else "uploading"
                db.execute("UPDATE jobs SET state=?,attempts=attempts+1,updated=? WHERE id=?",
                           (state, time.time(), row["id"]))
            db.execute("COMMIT")
            return dict(row) if row else None

    def step(self, deliver, selected_ids=None):
        job = self.claim(selected_ids)
        if not job:
            return False
        try:
            receipt = json.loads(job["receipt"]) if job["receipt"] else None
            if job["state"] != "fail_reporting" and (not receipt or receipt.get("stage") == "upload_pending"):
                stat = Path(job["spool"]).stat()
                if stat.st_size != job["size"] or stat.st_mtime_ns != job["mtime_ns"]:
                    raise PermanentUploadError("SOURCE_CHANGED_AFTER_ENQUEUE")
            # Receipt persistence separates object upload from backend confirmation.
            def save_receipt(value):
                with closing(self.connect()) as db:
                    db.execute("UPDATE jobs SET receipt=?,updated=? WHERE id=?",
                               (json.dumps(value), time.time(), job["id"]))
            if job["state"] == "fail_reporting":
                deliver.report_failure(job, receipt, save_receipt)
                with closing(self.connect()) as db:
                    db.execute("UPDATE jobs SET state='failed',updated=? WHERE id=?", (time.time(), job["id"]))
                return True
            deliver(job, receipt, save_receipt)
            with closing(self.connect()) as db:
                db.execute("UPDATE jobs SET state='completed',error=NULL,updated=? WHERE id=?",
                           (time.time(), job["id"]))
            Path(job["spool"]).unlink(missing_ok=True)
        except Exception as error:
            attempts = job["attempts"] + 1
            delay = min(900, 15 * 2 ** min(attempts - 1, 6) * random.uniform(0.8, 1.2))
            permanent = isinstance(error, (FileNotFoundError, PermanentUploadError))
            state = "failed" if permanent else "retry"
            if job["state"] == "fail_reporting" or (permanent and hasattr(deliver, "report_failure")):
                state = "fail_reporting"
            with closing(self.connect()) as db:
                db.execute("UPDATE jobs SET state=?,error=?,next_attempt=?,updated=? WHERE id=?",
                           (state, job.get("error") if job["state"] == "fail_reporting" else getattr(error, "upload_code", type(error).__name__),
                            time.time() + delay, time.time(), job["id"]))
        return True

    def status(self):
        with closing(self.connect()) as db:
            counts = dict(db.execute("SELECT state,COUNT(*) FROM jobs GROUP BY state").fetchall())
            size, oldest = db.execute("SELECT COALESCE(SUM(size),0),MIN(created) FROM jobs "
                                      "WHERE state!='completed'").fetchone()
            next_retry = db.execute("SELECT MIN(next_attempt) FROM jobs WHERE state='retry'").fetchone()[0]
        return {"counts": counts, "backlogBytes": size,
                "nextRetryAt": next_retry,
                "oldestPendingSeconds": round(time.time() - oldest) if oldest else 0,
                "diskFreeBytes": shutil.disk_usage(self.root).free,
                "maxItems": self.max_items, "maxBytes": self.max_bytes,
                "maxConcurrentUploads": 1}


class BackendDelivery:
    def __init__(self, config):
        self.config = config
        self.bandwidth = AdaptiveBandwidth(config) if config.get("adaptiveUploadEnabled") else None
        reject_internal_credentials(config)
        self.base = config["backendUrl"].rstrip("/")
        if urlsplit(self.base).scheme != "https":
            raise ValueError("HTTPS_BACKEND_REQUIRED")

    def token(self):
        if self.config.get("deviceClientConfig"):
            path = Path(self.config["deviceClientConfig"])
            if path.stat().st_mode & 0o077:
                raise ValueError("DEVICE_TOKEN_FILE_NOT_PRIVATE")
            settings = json.loads(path.read_text())
            reject_internal_credentials(settings)
            if settings.get("arenaId") != self.config.get("arenaId") or self.identity(settings) != self.identity(self.config):
                raise ValueError("DEVICE_TOKEN_IDENTITY_MISMATCH")
            return settings["deviceToken"]
        return self.config.get("deviceGatewayToken") or self.config["deviceToken"]

    @staticmethod
    def identity(config):
        official = [config[key] for key in ("mediaDeviceId", "shinobiId") if config.get(key)]
        if official and any(value != official[0] for value in official):
            raise ValueError("MEDIA_DEVICE_IDENTITY_CONFLICT")
        value = official[0] if official else config.get("deviceId")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("MEDIA_DEVICE_IDENTITY_REQUIRED")
        return value

    def live_active(self):
        return bool(self.config.get("liveActiveFile") and Path(self.config["liveActiveFile"]).exists())

    def report_failure(self, job, receipt, save_receipt):
        if not receipt:
            ticket = self.post("/internal/original-videos", self.metadata(job), job["id"])
            receipt = {"originalVideoId": ticket["originalVideoId"], "objectKey": ticket["objectKey"], "stage": "upload_pending"}
            save_receipt(receipt)
        video_id = quote(str(receipt["originalVideoId"]), safe="")
        self.post("/internal/original-videos/" + video_id + "/upload-fail",
                  {"errorCode": job.get("error") or "LOCAL_UPLOAD_FAILED",
                   "errorMessage": "Falha terminal no arquivo local; recuperacao operacional necessaria"}, job["id"])

    def metadata(self, job):
        binding = self.config.get("cameraBindings", {}).get(job["monitor_id"])
        if not binding:
            raise PermanentUploadError("CAMERA_BINDING_REQUIRED")
        if self.config.get("groupKey") and binding.get("blockSlug") and binding.get("cameraSlug"):
            identity = {"groupKey": self.config["groupKey"],
                        "blockSlug": binding["blockSlug"], "cameraSlug": binding["cameraSlug"]}
        elif binding.get("blockId") and binding.get("cameraId"):
            identity = {"arenaId": self.config["arenaId"],
                        "blockId": binding["blockId"], "cameraId": binding["cameraId"]}
        else:
            raise PermanentUploadError("CAMERA_BINDING_REQUIRED")
        # Persisted file mtime is a stable fallback; retries must not use the current time.
        recorded_at = datetime.fromtimestamp(job["mtime_ns"] / 1e9, timezone.utc)
        return {
            **identity,
            "mediaDeviceId": self.identity(self.config),
            "shinobiId": self.identity(self.config),
            "monitorId": job["monitor_id"], "sourceFileName": Path(job["source"]).name,
            "recordedAt": recorded_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "sizeBytes": job["size"], "contentType": "video/mp4",
        }

    def post(self, path, payload, job_id):
        request = urllib.request.Request(self.base + path, json.dumps(payload).encode(),
                                        {"Content-Type": "application/json",
                                         "Authorization": "Bearer " + self.token(),
                                         "Idempotency-Key": job_id}, method="POST")
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                raw = response.read(1024 * 1024)
                return json.loads(raw) if raw else {}
        except TimeoutError as error:
            error.upload_code = "BACKEND_CONFIRM_TIMEOUT" if path.endswith("upload-complete") else "BACKEND_REQUEST_TIMEOUT"
            raise

    def __call__(self, job, receipt, save_receipt):
        if not direct_enabled(self.config):
            raise OSError("UPLOAD_WAITING_DIRECT")
        if self.live_active() and not self.bandwidth:
            raise OSError("UPLOAD_PAUSED_FOR_LIVE")
        if not receipt or receipt.get("stage") == "upload_pending":
            checksum = hashlib.sha256()
            with open(job["spool"], "rb") as source:
                for chunk in iter(lambda: source.read(256 * 1024), b""):
                    checksum.update(chunk)
            metadata = self.metadata(job)
            metadata["checksum"] = checksum.hexdigest()
            ticket = self.post("/internal/original-videos", metadata, job["id"])
            if receipt and receipt["originalVideoId"] != ticket["originalVideoId"]:
                raise PermanentUploadError("ORIGINAL_VIDEO_ID_CHANGED")
            receipt = {"originalVideoId": ticket["originalVideoId"], "objectKey": ticket["objectKey"], "stage": "upload_pending"}
            save_receipt(receipt)
            if ticket.get("method", "PUT") != "PUT":
                raise PermanentUploadError("UNSUPPORTED_UPLOAD_METHOD")
            url = ticket["uploadUrl"]
            if urlsplit(url).scheme != "https":
                raise PermanentUploadError("HTTPS_UPLOAD_REQUIRED")
            rate = int(self.config.get("uploadBytesPerSecond", 256 * 1024))
            if self.config.get("liveActiveFile") and Path(self.config["liveActiveFile"]).exists():
                rate = min(rate, int(self.config.get("liveUploadBytesPerSecond", 64 * 1024)))
            # Pass the signed URL on stdin, not in the process argument list or logs.
            escaped = url.replace("\\", "\\\\").replace('"', '\\"')
            if "\n" in escaped or "\r" in escaped:
                raise PermanentUploadError("INVALID_UPLOAD_URL")
            headers = ticket.get("headers", {"Content-Type": "video/mp4"})
            if not isinstance(headers, dict):
                raise PermanentUploadError("INVALID_UPLOAD_HEADERS")
            header_args = []
            for key, value in headers.items():
                if (not isinstance(key, str) or not isinstance(value, str) or
                        not key or ":" in key or any(c in key + value for c in "\r\n\x00")):
                    raise PermanentUploadError("INVALID_UPLOAD_HEADERS")
                header_args.extend(["--header", key + ": " + value])
            if self.bandwidth:
                upload_file(url, job["spool"], job["size"], headers, self.bandwidth,
                            self.live_active, self.config.get("uploadActiveFile"), allowed=lambda: direct_enabled(self.config))
            else:
                process = subprocess.Popen(
                    ["curl", "--silent", "--fail", "--proto", "=https", "--connect-timeout", "15",
                     "--max-time", "1800", "--limit-rate", str(max(1024, rate)),
                     "--upload-file", job["spool"], *header_args, "--config", "-"],
                    text=True, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    process.stdin.write('url = "' + escaped + '"\n')
                    process.stdin.close()
                    deadline = time.monotonic() + 1810
                    while process.poll() is None:
                        if self.live_active():
                            raise OSError("UPLOAD_PAUSED_FOR_LIVE")
                        if time.monotonic() >= deadline:
                            raise TimeoutError("UPLOAD_TIMEOUT")
                        time.sleep(0.25)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
                if process.returncode:
                    raise OSError("UPLOAD_FAILED")
            receipt = {"originalVideoId": ticket["originalVideoId"], "objectKey": ticket["objectKey"], "stage": "uploaded"}
            save_receipt(receipt)
        video_id = quote(str(receipt["originalVideoId"]), safe="")
        if not direct_enabled(self.config):
            raise OSError("UPLOAD_WAITING_DIRECT")
        self.post("/internal/original-videos/" + video_id + "/upload-complete",
                  {"objectKey": receipt["objectKey"], "sizeBytes": job["size"]}, job["id"])


def accept_completion(config, payload, collect_file):
    if not direct_enabled(config):
        return "ignored-not-direct"
    monitor, filename = payload.get("monitorId"), payload.get("filename")
    if payload.get("groupKey") != config.get("groupKey") or monitor not in config.get("watchDirectories", {}):
        raise ValueError("MONITOR_NOT_ALLOWED")
    if (not isinstance(filename, str) or not filename.endswith(".mp4") or
            any(c in filename for c in "/\\\x00") or filename in (".", "..")):
        raise ValueError("INVALID_FILENAME")
    folder = Path(config["watchDirectories"][monitor]).resolve()
    return collect_file(folder / filename, monitor, notified=True)


def serve(config):
    reject_internal_credentials(config)
    queue = UploadQueue(config["queueDir"], config.get("maxItems", 1000),
                        config.get("maxBytes", 8 * 1024**3), config.get("minFreeBytes", 2 * 1024**3))
    lock = open(queue.root / "worker.lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if config.get("uploadActiveFile"):
        Path(config["uploadActiveFile"]).unlink(missing_ok=True)
    queue.recover()
    enabled = bool(config.get("uploadsEnabled") and config.get("backendUrl") and
                   (config.get("deviceToken") or config.get("deviceGatewayToken") or config.get("deviceClientConfig")))
    deliver = BackendDelivery(config) if enabled else None
    scan_interval = max(1, min(3600, float(config.get("scanIntervalSeconds", 300 if config.get("completionWebhook") else 3))))
    collector_state = {"lastError": None, "lastScanAt": None, "scanIntervalSeconds": scan_interval}

    wake = threading.Event()

    def collect_file(path, monitor, notified=False, writers=None):
        if not direct_enabled(config):
            return "ignored-not-direct"
        path = Path(path)
        if path.is_symlink():
            raise ValueError("SYMLINK_SOURCE_FORBIDDEN")
        if not path.exists():
            with closing(queue.connect()) as db:
                row = db.execute("SELECT id FROM jobs WHERE source=? AND monitor_id=? AND state='completed' ORDER BY created DESC LIMIT 1",
                                 (str(path), monitor)).fetchone()
            if row:
                return row[0]
            raise FileNotFoundError("SOURCE_NOT_FOUND")
        stat = path.stat()
        if not path.is_file() or stat.st_mtime < config.get("collectSince", time.time()):
            raise ValueError("SOURCE_OUTSIDE_COLLECTION_WINDOW")
        identity = json.dumps([config.get("queueIdentity", config["deviceId"]), monitor, path.name,
                               stat.st_size, stat.st_mtime_ns])
        job_id = hashlib.sha256(identity.encode()).hexdigest()
        with closing(queue.connect()) as db:
            if db.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone():
                return job_id
        if not notified and time.time() - stat.st_mtime < config.get("settleSeconds", 30):
            return None
        if config.get("requireClosedFile", False):
            if writers is None:
                writers = open_writer_inodes()
            if (stat.st_dev, stat.st_ino) in writers:
                raise OSError("SOURCE_STILL_OPEN")
        checked = subprocess.run(["ffprobe", "-v", "quiet", "-show_entries", "format=duration", "-of", "json", str(path)],
                                 capture_output=True, timeout=10)
        after = path.stat()
        if checked.returncode or (stat.st_size, stat.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise OSError("SOURCE_NOT_FINALIZED")
        job_id = queue.enqueue(path, monitor, config.get("queueIdentity", config["deviceId"]))
        wake.set()
        return job_id

    def accept_notification(payload):
        return accept_completion(config, payload, collect_file)

    webhook_thread = None
    if config.get("completionWebhook"):
        _, webhook_thread = start_completion_server(config, accept_notification, collector_state)
        collector_state["mode"] = "WEBHOOK_WITH_RECONCILIATION"

    def collect():
        while True:
            collector_state["lastError"] = None
            try:
                writers = open_writer_inodes() if config.get("requireClosedFile", False) else set()
                for monitor, folder in config.get("watchDirectories", {}).items():
                    with os.scandir(folder) as entries:
                        for entry in entries:
                            if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(".mp4"):
                                continue
                            if entry.stat().st_mtime < config.get("collectSince", time.time()):
                                continue
                            try:
                                collect_file(entry.path, monitor, writers=writers)
                            except (OSError, ValueError) as error:
                                collector_state["lastError"] = type(error).__name__
            except Exception as error:
                collector_state["lastError"] = type(error).__name__
            collector_state["lastScanAt"] = time.time()
            time.sleep(scan_interval)

    def report():
        while True:
            status = queue.status()
            status.update(checkedAt=time.time(), delivery="PAUSED_LIVE" if deliver and deliver.live_active() else "ENABLED" if enabled else "WAITING_BACKEND",
                          collector=dict(collector_state))
            if deliver and deliver.bandwidth:
                deliver.bandwidth.set_live(deliver.live_active())
                status["bandwidth"] = deliver.bandwidth.status()
                status["delivery"] = "PAUSED_DEGRADED_LINK" if deliver.bandwidth.paused else "REDUCED_LIVE" if deliver.live_active() else "ENABLED"
            status["directUploadAllowed"] = direct_enabled(config)
            if not status["directUploadAllowed"]:
                status["delivery"] = "WAITING_DIRECT"
            temporary = queue.root / "status.tmp"
            temporary.write_text(json.dumps(status, indent=2) + "\n")
            temporary.replace(queue.root / "status.json")
            time.sleep(5)

    collector = threading.Thread(target=collect, daemon=True, name="direct-collector")
    reporter = threading.Thread(target=report, daemon=True, name="direct-status")
    collector.start()
    reporter.start()
    while True:
        if not collector.is_alive() or not reporter.is_alive() or (webhook_thread and not webhook_thread.is_alive()):
            raise RuntimeError("QUEUE_BACKGROUND_THREAD_STOPPED")
        if not direct_enabled(config) or not deliver or (deliver.live_active() and not deliver.bandwidth) or not queue.step(deliver, config.get("selectedJobIds")):
            wake.wait(2)
            wake.clear()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("command", choices=["serve", "status", "enqueue"])
    parser.add_argument("--file")
    parser.add_argument("--monitor")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    if args.command == "serve":
        serve(config)
    else:
        queue = UploadQueue(config["queueDir"], config.get("maxItems", 1000),
                            config.get("maxBytes", 8 * 1024**3), config.get("minFreeBytes", 2 * 1024**3))
        if args.command == "enqueue":
            print(queue.enqueue(args.file, args.monitor, config.get("queueIdentity", config["deviceId"])))
        else:
            print(json.dumps(queue.status(), indent=2))


if __name__ == "__main__":
    main()
