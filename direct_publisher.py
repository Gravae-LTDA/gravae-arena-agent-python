"""Bounded RTMP startup retries without blocking gateway health or command handling."""
import re
import subprocess
import threading
import time


def safe_stderr(line, secrets):
    for secret in sorted((str(s) for s in secrets if s), key=len, reverse=True):
        line = line.replace(secret, '[redacted]')
    line = re.sub(r'(?:rtmps?|https?|rtsp|tcp|tls|udp)://[^\s\x00]+', '[endpoint]', line)
    return ''.join(c for c in line if c.isprintable())[:400]


def failure_code(text):
    text = text.lower()
    for fragment, code in [('connection refused', 'RTMP_CONNECTION_REFUSED'),
                           ('name or service not known', 'RTMP_DNS_FAILED'),
                           ('failed to resolve', 'RTMP_DNS_FAILED'),
                           ('timed out', 'RTMP_TIMEOUT'),
                           ('handshake', 'RTMP_HANDSHAKE_FAILED'),
                           ('broken pipe', 'RTMP_CONNECTION_CLOSED'),
                           ('invalid data found', 'MEDIA_INPUT_INVALID'),
                           ('does not contain any stream', 'MEDIA_INPUT_EMPTY')]:
        if fragment in text:
            return code
    return 'FFMPEG_PUBLISHER_FAILED'


class RetryingPublisher:
    """Popen-like lifetime: remains running during retry; STOP cancels all attempts."""
    def __init__(self, argv, secrets, log, metadata, duration, retry_seconds=60, retry_interval=2,
                 factory=subprocess.Popen):
        self.argv, self.secrets, self.log, self.metadata = argv, secrets, log, metadata
        self.duration, self.retry_seconds, self.retry_interval = duration, retry_seconds, retry_interval
        self.factory = factory
        self.child = None
        self.returncode = None
        self.cancel = threading.Event()
        self.finished = threading.Event()
        self.media_started = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name='direct-publisher')
        self.thread.start()

    @property
    def pid(self):
        return self.child.pid if self.child else None

    def poll(self):
        return self.returncode if self.finished.is_set() else None

    def _run(self):
        deadline = time.monotonic() + min(self.duration, self.retry_seconds)
        end = time.monotonic() + self.duration
        attempt = 0
        try:
            while not self.cancel.is_set() and time.monotonic() < deadline:
                attempt += 1
                self.log('publisher.attempt', **self.metadata, attempt=attempt)
                self.child = self.factory(self.argv, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                errors = []
                def stderr():
                    for line in self.child.stderr:
                        clean = safe_stderr(line, self.secrets)
                        errors.append(clean)
                        del errors[:-12]
                        self.log('publisher.stderr', **self.metadata, attempt=attempt,
                                 errorCode=failure_code(clean), stderr=clean)
                def progress():
                    for line in self.child.stdout:
                        if line.startswith('out_time_us='):
                            try:
                                if int(line.split('=', 1)[1]) > 0 and not self.media_started.is_set():
                                    self.media_started.set()
                                    self.log('publisher.media_started', **self.metadata, attempt=attempt)
                            except ValueError:
                                pass
                readers = [threading.Thread(target=stderr, daemon=True), threading.Thread(target=progress, daemon=True)]
                for reader in readers: reader.start()
                while self.child.poll() is None:
                    if self.cancel.wait(.1) or time.monotonic() >= end or (not self.media_started.is_set() and time.monotonic() >= deadline):
                        self._stop_child()
                        break
                for reader in readers: reader.join(timeout=2)
                self.child.stdout.close()
                self.child.stderr.close()
                code = self.child.returncode
                self.log('publisher.attempt_exited', **self.metadata, attempt=attempt,
                         exitCode=code, errorCode=failure_code(' '.join(errors)))
                if self.cancel.is_set() or self.media_started.is_set():
                    self.returncode = code if code is not None else -15
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0: break
                self.log('publisher.retry', **self.metadata, attempt=attempt,
                         exitCode=code, retrySeconds=min(self.retry_interval, remaining))
                if self.cancel.wait(min(self.retry_interval, remaining)): break
            if self.returncode is None:
                self.returncode = -15 if self.cancel.is_set() else (self.child.returncode if self.child and self.child.returncode else 1)
                if not self.cancel.is_set():
                    self.log('publisher.start_failed', **self.metadata, exitCode=self.returncode,
                             errorCode='PUBLISHER_START_RETRY_EXHAUSTED')
        except Exception as error:
            self.returncode = 1
            self.log('publisher.start_failed', **self.metadata, exceptionType=type(error).__name__,
                     errorCode='PUBLISHER_EXECUTION_FAILED')
        finally:
            self._stop_child()
            self.finished.set()

    def _stop_child(self):
        child = self.child
        if child is not None and child.poll() is None:
            child.terminate()
            try: child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)

    def terminate(self):
        self.cancel.set()

    def kill(self):
        self.cancel.set()
        self._stop_child()

    def wait(self, timeout=None):
        if not self.finished.wait(timeout):
            raise subprocess.TimeoutExpired('direct-publisher', timeout)
        return self.returncode
