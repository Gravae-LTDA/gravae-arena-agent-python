"""Paced HTTPS uploads with latency feedback and reduced bandwidth during live."""

import http.client
import json
import math
import os
from pathlib import Path
import socket
import threading
import time
from urllib.parse import urlsplit


class AdaptiveBandwidth:
    def __init__(self, config):
        self.maximum = max(65536, int(config.get("uploadBytesPerSecond", 10 * 1024**2)))
        self.minimum = min(self.maximum, max(16384, int(config.get("uploadMinimumBytesPerSecond", 65536))))
        self.rate = min(self.maximum, max(self.minimum, int(config.get("uploadInitialBytesPerSecond", 1024**2))))
        self.lock = threading.Lock()
        self.baseline = None
        self.latency = None
        self.observed = 0
        self.measured_at = None
        self.active = False
        self.reason = "INITIAL_LIMIT"
        self.paused = False
        self.live = False
        self.live_maximum = max(self.minimum, int(config.get("liveUploadBytesPerSecond", 2 * 1024**2)))
        self.live_fraction = max(0.05, min(0.5, float(config.get("liveUploadFraction", 0.2))))
        self.slow_samples = 0
        self.congested_samples = 0
        self.last_reduction = float("-inf")
        self.severe_samples = 0
        self.recovery_samples = 0
        self.hold_until = 0
        self.state_path = Path(config["queueDir"]) / "bandwidth-state.json" if config.get("queueDir") else None
        if self.state_path and self.state_path.exists():
            try:
                state = json.loads(self.state_path.read_text())
                if 0 <= time.time() - state["savedAt"] < 300 and math.isfinite(state["rate"]):
                    self.rate = min(self.maximum, max(self.minimum, state["rate"]))
            except (OSError, ValueError, KeyError, TypeError):
                pass

    def observe(self, latency, throughput, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            self.observed = max(0, throughput)
            self.measured_at = time.time()
            self.latency = latency
            if latency is not None:
                self.baseline = latency if self.baseline is None else min(self.baseline, latency)
            latency_budget = max(0.10, (self.baseline or 0) * 1.5 + 0.03) if self.live else max(0.15, (self.baseline or 0) * 2 + 0.05)
            congested = latency is None or latency > latency_budget
            self.congested_samples = self.congested_samples + 1 if congested else 0
            severe = latency is None or latency > self.baseline * 3 + 0.15
            self.severe_samples = self.severe_samples + 1 if severe else 0
            self.recovery_samples = self.recovery_samples + 1 if not congested else 0
            if self.severe_samples >= 2:
                self.paused = True
                self.reason = "LINK_SEVERELY_DEGRADED"
            if self.paused:
                if self.recovery_samples >= 2:
                    self.paused = False
                    self.rate = self.minimum
                    self.hold_until = now + 5
                    self.reason = "RECOVERING_LINK"
                return
            effective = self._limit()
            slow = throughput > 0 and throughput < effective * 0.65
            self.slow_samples = self.slow_samples + 1 if slow else 0
            if congested:
                if self.congested_samples < 2 or now - self.last_reduction < 15:
                    self.reason = "VERIFYING_LATENCY_DEGRADATION"
                    return
                self.last_reduction = now
                self.rate = max(self.minimum, self.rate * 0.6)
                self.reason = "LATENCY_OR_CONNECTION_DEGRADED"
                self.hold_until = now + 15
            elif slow:
                if self.slow_samples < 2 or now - self.last_reduction < 10:
                    self.reason = "VERIFYING_OBSERVED_THROUGHPUT"
                    return
                self.last_reduction = now
                factor = self.live_fraction if self.live else 1
                self.rate = max(self.minimum, min(self.rate, throughput * 0.85 / factor))
                self.reason = "LIMITED_BY_OBSERVED_THROUGHPUT"
                self.hold_until = now + 10
            elif now >= self.hold_until and throughput >= effective * 0.8:
                self.rate = min(self.maximum, self.rate * 1.2)
                self.reason = "HEALTHY_GRADUAL_INCREASE"
            else:
                self.reason = "HOLDING_HEADROOM"

    def set_live(self, value):
        with self.lock:
            self.live = value

    def _limit(self):
        return min(self.rate, self.live_maximum, max(self.minimum, self.rate * self.live_fraction)) if self.live else self.rate

    def limit(self):
        with self.lock:
            return 0 if self.paused else self._limit()

    def status(self):
        with self.lock:
            return {"mode": "ADAPTIVE", "maximumBytesPerSecond": self.maximum,
                    "effectiveBytesPerSecond": 0 if self.paused else round(self._limit()),
                    "observedBytesPerSecond": round(self.observed),
                    "measuredAt": self.measured_at, "transferActive": self.active,
                    "latencyMs": round(self.latency * 1000, 1) if self.latency is not None else None,
                    "liveActive": self.live,
                    "reason": "LINK_SEVERELY_DEGRADED" if self.paused else "REDUCED_DURING_LIVE" if self.live else self.reason}

    def persist(self):
        if self.state_path:
            temporary = self.state_path.with_suffix('.tmp')
            temporary.write_text(json.dumps({"rate": self.rate, "savedAt": time.time()}))
            os.chmod(temporary, 0o600)
            temporary.replace(self.state_path)


def probe_latency(host, port):
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=2):
            return time.monotonic() - started
    except OSError:
        return None


def upload_file(url, path, size, headers, bandwidth, live_active, busy_file=None,
                connection_factory=http.client.HTTPSConnection, probe=probe_latency, allowed=lambda: True):
    if not allowed():
        raise OSError("UPLOAD_WAITING_DIRECT")
    target = urlsplit(url)
    if target.scheme != "https" or not target.hostname or target.username or target.password or target.fragment:
        raise ValueError("INVALID_HTTPS_UPLOAD_URL")
    bandwidth.set_live(live_active())
    bandwidth.active = True
    connection = connection_factory(target.hostname, target.port or 443, timeout=10)
    done = threading.Event()
    counter = [0]
    busy = Path(busy_file) if busy_file else None

    def watch_live():
        while not done.wait(0.1):
            bandwidth.set_live(live_active())

    def sample_network():
        previous_time, previous_bytes = time.monotonic(), counter[0]
        while not done.wait(3):
            latency = probe(target.hostname, target.port or 443)
            now = time.monotonic()
            sent = counter[0]
            if not done.is_set() and counter[0] < size:
                bandwidth.observe(latency, (sent - previous_bytes) / max(0.001, now - previous_time))
            previous_time, previous_bytes = now, sent

    watcher = threading.Thread(target=watch_live, daemon=True, name="upload-live-priority")
    sampler = threading.Thread(target=sample_network, daemon=True, name="upload-bandwidth")
    phase = "CONNECT"
    try:
        if busy:
            busy.write_text(str(os.getpid()))
            os.chmod(busy, 0o600)
        watcher.start()
        initial_latency = probe(target.hostname, target.port or 443)
        bandwidth.observe(initial_latency, 0)
        connection.connect()
        connection.sock.settimeout(30)
        phase = "SEND"
        connection.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        request_path = target.path or "/"
        if target.query:
            request_path += "?" + target.query
        connection.putrequest("PUT", request_path, skip_accept_encoding=True)
        connection.putheader("Content-Length", str(size))
        for name, value in headers.items():
            if name.lower() in ("content-length", "transfer-encoding", "host"):
                raise ValueError("UNSUPPORTED_UPLOAD_HEADER")
            connection.putheader(name, value)
        connection.endheaders()
        sampler.start()
        next_send = time.monotonic()
        deadline = time.monotonic() + 1800
        with open(path, "rb") as source:
            while True:
                chunk = source.read(32768)
                if not chunk:
                    break
                bandwidth.set_live(live_active())
                while time.monotonic() < next_send:
                    if not allowed():
                        raise OSError("UPLOAD_WAITING_DIRECT")
                    time.sleep(max(0, min(0.1, next_send - time.monotonic())))
                while bandwidth.limit() == 0:
                    if not allowed():
                        raise OSError("UPLOAD_WAITING_DIRECT")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("DEGRADED_LINK_UPLOAD_TIMEOUT")
                    time.sleep(0.1)
                if time.monotonic() >= deadline:
                    raise TimeoutError("UPLOAD_TIMEOUT")
                if not allowed():
                    raise OSError("UPLOAD_WAITING_DIRECT")
                connection.send(chunk)
                counter[0] += len(chunk)
                rate = max(bandwidth.minimum, bandwidth.limit())
                next_send = max(next_send + len(chunk) / rate, time.monotonic())
        if counter[0] != size:
            raise ValueError("UPLOAD_SIZE_CHANGED")
        phase = "RESPONSE"
        response = connection.getresponse()
        response.read(4096)
        if not 200 <= response.status < 300:
            raise OSError("R2_UPLOAD_HTTP_" + str(response.status))
    except TimeoutError as error:
        error.upload_code = "R2_" + phase + "_TIMEOUT"
        raise
    finally:
        done.set()
        bandwidth.active = False
        connection.close()
        if watcher.ident:
            watcher.join(timeout=1)
        if sampler.ident:
            sampler.join(timeout=3)
        if busy:
            busy.unlink(missing_ok=True)
        bandwidth.persist()
