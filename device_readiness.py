"""Bounded local media probes. Results never contain camera URLs or credentials."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def resource_checks(config):
    checks = {}
    try:
        usage = shutil.disk_usage(config.get("shmPath", "/dev/shm"))
        checks.update(shmFreeBytes=usage.free,
                      shmReady=usage.free >= config.get("minShmFreeBytes", 128 * 1024**2))
    except OSError:
        checks["shmReady"] = False
    try:
        memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        available = int(memory["MemAvailable"].split()[0]) * 1024
        checks.update(memoryAvailableBytes=available,
                      memoryReady=available >= config.get("minMemoryFreeBytes", 256 * 1024**2))
        load = os.getloadavg()[0] / max(1, os.cpu_count() or 1)
        checks.update(cpuLoadPerCore=round(load, 3),
                      cpuReady=load <= config.get("maxLoadPerCore", 1.5))
    except (OSError, KeyError, ValueError):
        checks.update(memoryReady=False, cpuReady=False)
    try:
        retained = {}
        scanned = 0
        processes = 0
        deadline = time.monotonic() + 2
        for proc in Path(config.get("procPath", "/proc")).glob("[0-9]*"):
            try:
                command = (proc / "cmdline").read_bytes().split(b"\0")
                if not any(b"/home/Shinobi/camera.js" in argument.split() for argument in command):
                    continue
                processes += 1
                for fd in (proc / "fd").iterdir():
                    scanned += 1
                    if scanned > 20000 or time.monotonic() > deadline:
                        raise TimeoutError("DESCRIPTOR_SCAN_LIMIT")
                    try:
                        target = str(fd.readlink())
                        if target.startswith("/dev/shm/") and target.endswith(" (deleted)"):
                            stat = fd.stat()
                            retained[(stat.st_dev, stat.st_ino)] = stat.st_blocks * 512
                    except FileNotFoundError:
                        continue
            except FileNotFoundError:
                continue
        size = sum(retained.values())
        checks.update(shinobiDeletedOpenFiles=len(retained), shinobiDeletedOpenBytes=size,
                      shinobiProcessCount=processes, shinobiProcessReady=processes > 0,
                      shinobiDescriptorsReady=processes > 0 and size < config.get("maxDeletedOpenBytes", 64 * 1024**2))
    except OSError:
        checks["shinobiDescriptorsReady"] = False
    return checks


def hls_check(manifest, probe=True):
    result = {"ready": False, "errorCode": "HLS_UNAVAILABLE"}
    try:
        manifest = Path(manifest)
        if time.time() - manifest.stat().st_mtime > 30 or manifest.stat().st_size > 1024 * 1024:
            return dict(result, errorCode="HLS_STALE_OR_OVERSIZED")
        lines = manifest.read_text().splitlines()
        if not lines or lines[0] != "#EXTM3U":
            return dict(result, errorCode="HLS_INVALID_MANIFEST")
        names = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
        if len(names) < 2:
            return dict(result, errorCode="HLS_INSUFFICIENT_SEGMENTS")
        segments = []
        for name in names[-3:]:
            path = (manifest.parent / name).resolve()
            if path.parent != manifest.parent.resolve() or path.suffix != ".ts":
                return dict(result, errorCode="HLS_INVALID_SEGMENT_PATH")
            stat = path.stat()
            if stat.st_size == 0 or stat.st_size % 188:
                return dict(result, errorCode="HLS_TRUNCATED_SEGMENT")
            if time.time() - stat.st_mtime > 60:
                return dict(result, errorCode="HLS_STALE_SEGMENT")
            segments.append(path)
        if probe:
            checked = subprocess.run([
                "nice", "-n", "15", "ffprobe", "-threads", "1", "-v", "error", "-err_detect", "explode", "-read_intervals", "%+2",
                "-select_streams", "v:0", "-show_entries", "frame=width,height", "-of", "json",
                str(segments[-1]),
            ], capture_output=True, timeout=8)
            frames = json.loads(checked.stdout or b"{}").get("frames", [])
            if checked.returncode or checked.stderr.strip() or not frames:
                return dict(result, errorCode="HLS_DECODE_FAILED")
        return {"ready": True, "errorCode": None, "segmentsChecked": len(segments)}
    except subprocess.TimeoutExpired:
        return dict(result, errorCode="HLS_PROBE_TIMEOUT")
    except (OSError, ValueError):
        return result


class HlsReadinessCache:
    """Check segment freshness every call; bound expensive decode checks separately."""
    def __init__(self, interval=300, retry_interval=60):
        self.interval = max(60, min(900, float(interval)))
        self.retry_interval = max(30, min(self.interval, float(retry_interval)))
        self.results = {}

    def check(self, manifest):
        key = str(manifest)
        light = hls_check(manifest, probe=False)
        if not light['ready']:
            self.results.pop(key, None)
            return dict(light, decodeCheckedAt=None, decodeAgeSeconds=None)
        now = time.monotonic()
        cached = self.results.get(key)
        interval = self.interval if cached and cached['result']['ready'] else self.retry_interval
        if cached is None or now - cached['at'] >= interval:
            result = hls_check(manifest, probe=True)
            cached = {'at': time.monotonic(), 'checkedAt': time.time(), 'result': result}
            self.results[key] = cached
        return dict(cached['result'], decodeCheckedAt=cached['checkedAt'],
                    decodeAgeSeconds=round(max(0, time.monotonic()-cached['at']), 1))


def public_direct_status(path='/var/lib/gravae-device-client/status.json'):
    """Read diagnostics only; never expose the enrollment/config files."""
    import json
    import re
    from pathlib import Path
    try:
        file = Path(path)
        if file.stat().st_size > 1024 * 1024:
            raise ValueError('status too large')
        data = json.loads(file.read_text())
        result = {key: data.get(key) for key in (
            'agentVersion', 'publisherActive', 'activeStreamCount', 'directModeValid', 'directModeExpiresAt',
            'configSyncOk', 'lastConfigSyncAt', 'checkedAt', 'status', 'vpnReady', 'gatewayConnected',
            'shinobiProcessReady', 'shinobiDescriptorsReady', 'ffmpegReady', 'uploaderReady')}
        result['activeStreams'] = [{key: item[key] for key in ('streamId', 'monitorId')
                                    if isinstance(item.get(key), str) and re.fullmatch(r'[\w-]{1,128}', item[key])}
                                   for item in data.get('activeStreams', [])[:100] if isinstance(item, dict)]
        failure = data.get('lastPublisherFailure')
        result['lastPublisherFailure'] = None
        if isinstance(failure, dict):
            result['lastPublisherFailure'] = {key: value for key, value in failure.items()
                if (key in ('streamId', 'monitorId', 'errorCode', 'causeCode', 'failureStage', 'occurredAt', 'agentVersion')
                    and isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:TZ+-]{1,128}', value))
                or (key in ('exitCode', 'signal') and (value is None or type(value) is int))}
        error = data.get('lastConfigSyncError')
        result['lastConfigSyncError'] = None if not error else {
            'errorCode': 'CONFIG_SYNC_FAILED',
            'message': 'Nao foi possivel sincronizar a configuracao oficial',
            **({'httpStatus': error['httpStatus']} if isinstance(error, dict) and isinstance(error.get('httpStatus'), int) else {})}
        result['stale'] = time.time() - file.stat().st_mtime > 45
        if result['stale']:
            result.update(status='UNKNOWN', directModeValid=False, configSyncOk=False)
        return result
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'UNKNOWN', 'stale': True, 'directModeValid': False, 'configSyncOk': False}
