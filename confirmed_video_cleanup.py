"""Delete local Shinobi recordings only after durable backend upload confirmation."""

import argparse
import fcntl
import json
from pathlib import Path
import re
import sqlite3
import stat
import time
import urllib.request
from urllib.parse import quote, unquote, urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def delete_url(client, monitor, filename, bases=None):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.mp4", filename):
        raise ValueError("NON_SHINOBI_RECORDING_NAME")
    explicit = (bases or {}).get(monitor)
    url = urlsplit(explicit or client["monitors"][monitor]["hlsManifest"])
    parts = url.path.strip("/").split("/")
    if (url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost", "::1")
            or url.username or url.password or url.query or url.fragment
            or len(parts) != (4 if explicit else 5)
            or parts[1] != ("videos" if explicit else "hls") or unquote(parts[3]) != monitor):
        raise ValueError("LOCAL_SHINOBI_SOURCE_REQUIRED")
    return (url.scheme + "://" + url.netloc + "/" + parts[0] + "/videos/" + parts[2]
            + "/" + quote(monitor, safe="") + "/" + quote(filename, safe="") + "/delete")


def request_delete(url):
    # Do not expose local API credentials through process arguments or logs.
    with urllib.request.build_opener(NoRedirect()).open(url, timeout=15) as response:
        result = json.load(response)
    if result.get("ok") is False and result.get("msg") == "No such file":
        return False
    if result.get("ok") is not True:
        raise ValueError("SHINOBI_DELETE_NOT_CONFIRMED")
    return True


def clean(config, client, delete=request_delete):
    root = Path(config["queueDir"])
    with sqlite3.connect("file:" + str(root / "queue.sqlite3") + "?mode=rw", uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("CREATE TABLE IF NOT EXISTS source_cleanup "
                   "(job_id TEXT PRIMARY KEY, completed_at REAL, error TEXT)")
        jobs = db.execute("SELECT j.* FROM jobs j LEFT JOIN source_cleanup c ON c.job_id=j.id "
                          "WHERE j.state='completed' AND c.completed_at IS NULL").fetchall()
        summary = {"deleted": 0, "alreadyAbsent": 0, "preserved": 0}
        for job in jobs:
            try:
                receipt = json.loads(job["receipt"] or "{}")
                if receipt.get("stage") != "uploaded" or not receipt.get("originalVideoId"):
                    raise ValueError("UPLOAD_CONFIRMATION_REQUIRED")
                source = Path(job["source"])
                allowed = Path(config["watchDirectories"][job["monitor_id"]]).resolve()
                if source.parent.resolve() != allowed:
                    raise ValueError("SOURCE_OUTSIDE_MONITOR_DIRECTORY")
                exists = source.exists() or source.is_symlink()
                if exists:
                    info = source.lstat()
                    if (not stat.S_ISREG(info.st_mode) or info.st_size != job["size"]
                            or info.st_mtime_ns != job["mtime_ns"]):
                        raise ValueError("SOURCE_CHANGED_AFTER_UPLOAD")
                # The native API removes the recording's database row as well as its file.
                deleted = delete(delete_url(client, job["monitor_id"], source.name, config.get("localVideoDeleteBases")))
                if deleted is False and exists:
                    raise ValueError("SHINOBI_RECORD_MISSING_LOCAL_FILE_PRESENT")
                for _ in range(20):
                    if not source.exists():
                        break
                    time.sleep(0.25)
                if source.exists() or source.is_symlink():
                    raise ValueError("SHINOBI_DELETE_PENDING")
                db.execute("INSERT OR REPLACE INTO source_cleanup VALUES(?,?,NULL)",
                           (job["id"], time.time()))
                summary["deleted" if exists else "alreadyAbsent"] += 1
            except Exception as error:
                # Persist only a safe category, never an exception containing a credential URL.
                code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[A-Z_]+", str(error)) else type(error).__name__
                db.execute("INSERT OR REPLACE INTO source_cleanup VALUES(?,NULL,?)", (job["id"], code))
                summary["preserved"] += 1
            db.commit()
        return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    if config.get("deleteLocalAfterUpload") is not True:
        return
    client_path = Path(config["deviceClientConfig"])
    if client_path.stat().st_mode & 0o077:
        raise ValueError("DEVICE_CONFIG_NOT_PRIVATE")
    client = json.loads(client_path.read_text())
    if (client.get("mediaDeviceId") != config.get("mediaDeviceId")
            or client.get("arenaId") != config.get("arenaId")):
        raise ValueError("DEVICE_IDENTITY_MISMATCH")
    with open(Path(config["queueDir"]) / "cleanup.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(clean(config, client)))


if __name__ == "__main__":
    main()
