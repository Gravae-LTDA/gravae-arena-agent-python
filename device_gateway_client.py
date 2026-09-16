"""Staging device client; command outcomes survive restart independently of uploads."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import random
import queue
import shutil
import signal
import sqlite3
import subprocess
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
import uuid

from device_readiness import hls_check, resource_checks, HlsReadinessCache
from device_event_outbox import EventOutbox
from direct_publisher import RetryingPublisher
from media_mode import direct_enabled
from arena_config_sync import fetch_snapshot, save_mode

AGENT_VERSION = Path(__file__).with_name("VERSION").read_text().strip()


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def media_identity(config):
    official = [config[key] for key in ("mediaDeviceId", "shinobiId") if config.get(key)]
    if official and any(value != official[0] for value in official):
        raise ValueError("MEDIA_DEVICE_IDENTITY_CONFLICT")
    value = official[0] if official else config.get("deviceId")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("MEDIA_DEVICE_IDENTITY_REQUIRED")
    return value


def identity_fields(config):
    value = media_identity(config)
    return {"arenaId": config["arenaId"], "mediaDeviceId": value, "shinobiId": value}


def operational_log(event, **fields):
    # Never log command payloads, RTMP URLs/keys, tokens or raw exception messages.
    allowed = {"commandId", "commandType", "streamId", "monitorId", "errorCode",
               "exceptionType", "pid", "exitCode", "retrySeconds", "attempt", "stderr",
               "signal", "causeCode", "failureStage"}
    print(json.dumps({"event": event, "occurredAt": timestamp(), "agentVersion": AGENT_VERSION,
                      **{key: value[:400] if isinstance(value, str) else value
                         for key, value in fields.items()
                         if key in allowed and isinstance(value, (str, int, float, type(None)))}}), flush=True)


class GatewayConnection:
    """One reconnect owner, with a fresh Socket.IO/Engine.IO client per attempt."""
    def __init__(self, config, factory, register):
        self.config, self.factory, self.register = config, factory, register
        self.client = None
        self.lock = threading.Lock()

    def is_connected(self):
        with self.lock:
            return self.client is not None and self.client.connected

    def close(self):
        with self.lock:
            previous, self.client = self.client, None
        if previous is not None:
            try:
                # Also disconnect partially connected clients, not only connected namespaces.
                previous.disconnect()
            except Exception as error:
                operational_log("gateway.disconnect_failed", exceptionType=type(error).__name__)
            finally:
                try:
                    previous.eio.disconnect(abort=True)
                except Exception as error:
                    operational_log("gateway.transport_cleanup_failed", exceptionType=type(error).__name__)

    def connect(self):
        self.close()
        client = self.factory(reconnection=False, logger=False, engineio_logger=False)
        with self.lock:
            self.client = client
        self.register(client)
        try:
            client.connect(self.config["gatewayUrl"], transports=["websocket"], namespaces=["/devices"],
                           auth={**identity_fields(self.config), "token": self.config["deviceToken"],
                                 "agentVersion": AGENT_VERSION}, wait_timeout=15)
        except Exception:
            self.close()
            raise


AGENT_VERSION = Path(__file__).with_name("VERSION").read_text().strip()


class CommandError(Exception):
    pass


class DeviceRuntime:
    def __init__(self, config):
        if any(key in config for key in ("EXTERNAL_KEY", "externalKey", "ARENA_DEVICE_WEBHOOK_TOKEN", "webhookToken")):
            raise ValueError("SHARED_BACKEND_TOKEN_FORBIDDEN")
        self.config = config
        media_identity(config)
        self.root = Path(config["stateDir"])
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock_file = (self.root / "runtime.lock").open("a")
        fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.lock = threading.RLock()
        self.streams = {}
        self.config_sync_ok = False
        self.last_config_sync_at = None
        self.last_config_sync_error = None
        self.hls_health = HlsReadinessCache(config.get("hlsDecodeIntervalSeconds", 300),
                                            config.get("hlsDecodeRetrySeconds", 60))
        self.connected = False
        self.marker = Path(config.get("liveActiveFile", "/run/gravae-live.active"))
        self.marker.unlink(missing_ok=True)
        self.outbox = EventOutbox(self.root / "commands.sqlite3")
        with closing(self.db()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS commands "
                       "(id TEXT PRIMARY KEY, result TEXT NOT NULL)")
            rows = db.execute("SELECT id,result FROM commands").fetchall()
            for command_id, encoded in rows:
                result = json.loads(encoded)
                if result["event"] == "pending":
                    result.update(event="command.failed", errorCode="DEVICE_RESTARTED",
                                  errorMessage="Comando interrompido por reinicio do agent",
                                  commandId=command_id, eventId=str(uuid.uuid4()), occurredAt=timestamp())
                    db.execute("UPDATE commands SET result=? WHERE id=?",
                               (json.dumps(result), command_id))
                if result.get("eventId"):
                    self.outbox.put(result["event"], self.envelope(result), db)

    def envelope(self, result):
        return dict({key: value for key, value in result.items() if key != "event"},
                    **identity_fields(self.config))

    def db(self):
        db = sqlite3.connect(self.root / "commands.sqlite3", timeout=10, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def config_diagnostics(self):
        expires = None
        try:
            value = json.loads(Path(self.config.get("mediaModeFile", "/var/lib/gravae-device-client/media-mode.json")).read_text())
            if value.get("arenaId") == self.config["arenaId"] and value.get("mediaDeviceId") == media_identity(self.config):
                expires = datetime.fromtimestamp(value["expiresAt"], timezone.utc).isoformat().replace("+00:00", "Z")
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            pass
        return {"directModeValid": direct_enabled(self.config), "directModeExpiresAt": expires,
                "configSyncOk": self.config_sync_ok, "lastConfigSyncAt": self.last_config_sync_at,
                "lastConfigSyncError": self.last_config_sync_error}

    def readiness(self):
        with self.lock:
            slots = list(self.streams.values())
            active_streams = [{"streamId": sid, "monitorId": slot["monitorId"]} for sid, slot in self.streams.items() if slot["process"].poll() is None]
        checks = {"agentVersion": AGENT_VERSION, "gatewayConnected": self.connected,
                  "ffmpegReady": shutil.which("ffmpeg") is not None,
                  "diskReady": shutil.disk_usage(self.root).free >= self.config.get("minFreeBytes", 2 * 1024**3),
                  "publisherActive": any(slot["process"].poll() is None for slot in slots),
                  "liveInput": "SHINOBI_HLS",
                  "activeStreamCount": sum(slot["process"].poll() is None for slot in slots),
                  "activeMonitors": [slot["monitorId"] for slot in slots if slot["process"].poll() is None]}
        checks["activeStreams"] = active_streams
        checks.update(self.config_diagnostics())
        checks.update(resource_checks(self.config))
        checks["eventsPending"] = self.outbox.count()
        try:
            checks["clockReady"] = subprocess.run(
                ["timedatectl", "show", "--property=NTPSynchronized", "--value"],
                capture_output=True, text=True, timeout=3).stdout.strip() == "yes"
        except (OSError, subprocess.TimeoutExpired):
            checks["clockReady"] = False
        try:
            status = json.loads(Path(self.config["queueStatusFile"]).read_text())
            checks["uploaderReady"] = status.get("delivery") in ("ENABLED", "PAUSED_LIVE", "REDUCED_LIVE", "WAITING_DIRECT") and time.time() - status["checkedAt"] < 30
            checks["uploaderPausedForLive"] = status.get("delivery") == "PAUSED_LIVE"
            checks["uploaderReducedForLive"] = status.get("delivery") == "REDUCED_LIVE"
            checks["uploaderPausedForDegradedLink"] = status.get("delivery") == "PAUSED_DEGRADED_LINK"
            if "bandwidth" in status:
                checks["uploadBandwidth"] = status["bandwidth"]
            checks["queuePending"] = sum(n for state, n in status["counts"].items() if state != "completed")
        except (OSError, ValueError, KeyError):
            checks["uploaderReady"] = False
        try:
            result = subprocess.run(["wg", "show", "wg0", "latest-handshakes"],
                                    capture_output=True, text=True, timeout=3)
            times = [int(line.split()[1]) for line in result.stdout.splitlines()]
            checks["vpnReady"] = bool(times) and time.time() - max(times) < 180
        except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
            checks["vpnReady"] = False
        monitors = self.config.get("monitors", {})
        active = self.config.get("activeMonitorIds", list(monitors))
        checks["bindingsReady"] = bool(active) and all(mid in monitors for mid in active)
        for monitor in active:
            binding = monitors.get(monitor)
            if not binding:
                checks["hlsReady:" + monitor] = False
                continue
            result = self.hls_health.check(binding["hlsManifest"])
            checks["hlsReady:" + monitor] = result["ready"]
            checks["hlsError:" + monitor] = result["errorCode"]
            checks["hlsDecodeAgeSeconds:" + monitor] = result["decodeAgeSeconds"]
            checks["hlsDecodeCheckedAt:" + monitor] = result["decodeCheckedAt"]
        checks["hlsDecodeIntervalSeconds"] = self.hls_health.interval
        # Do not advertise overall READY while end-to-end uploader enrollment is pending.
        checks["status"] = "READY" if all(value for key, value in checks.items()
                                                if key.endswith("Ready") or key.startswith("hlsReady:")) and self.connected and self.config_sync_ok else "DEGRADED"
        return checks

    def execute(self, command):
        if not isinstance(command, dict):
            raise CommandError("INVALID_COMMAND")
        command_id = command.get("commandId")
        if not isinstance(command_id, str) or not command_id or len(command_id) > 128:
            raise CommandError("INVALID_COMMAND_ID")
        result = {"commandId": command_id, "commandType": command.get("type"),
                  "streamId": command.get("streamId"), "event": "command.failed"}
        with self.lock:
            try:
                matches = media_identity(command) == media_identity(self.config)
            except ValueError:
                matches = False
            if not matches or command.get("arenaId") != self.config["arenaId"]:
                return dict(result, errorCode="DEVICE_IDENTITY_MISMATCH", errorMessage="Identidade do device invalida")
            with closing(self.db()) as db:
                previous = db.execute("SELECT result FROM commands WHERE id=?", (command_id,)).fetchone()
                if previous:
                    saved = json.loads(previous[0])
                    saved.setdefault("eventId", str(uuid.uuid4()))
                    saved.setdefault("occurredAt", timestamp())
                    db.execute("UPDATE commands SET result=? WHERE id=?", (json.dumps(saved), command_id))
                    self.outbox.put(saved["event"], self.envelope(saved), db)
                    return saved
                if self.outbox.count() >= self.config.get("maxPendingEvents", 1000):
                    raise CommandError("EVENT_OUTBOX_FULL")
                try:
                    expires = datetime.fromisoformat(command["expiresAt"].replace("Z", "+00:00"))
                    if expires.tzinfo is None:
                        raise ValueError("Timezone required")
                    if expires.timestamp() <= time.time():
                        raise CommandError("DEVICE_COMMAND_EXPIRED")
                    if command.get("type") not in ("READINESS_CHECK", "STREAM_START", "STREAM_STOP", "ARENA_CONFIG_SYNC"):
                        raise CommandError("UNSUPPORTED_COMMAND")
                    db.execute("INSERT INTO commands VALUES(?,?)", (command_id, json.dumps(dict(result, event="pending"))))
                    payload = command.get("payload") or {}
                    if not isinstance(payload, dict):
                        raise CommandError("INVALID_PAYLOAD")
                    result["monitorId"] = payload.get("monitorId")
                    if command["type"] == "ARENA_CONFIG_SYNC":
                        if not isinstance(payload.get("configPath"), str):
                            raise CommandError("ARENA_CONFIG_SYNC_FAILED")
                        self.sync_config(payload.get("configPath"))
                    elif command["type"] == "READINESS_CHECK":
                        result["readiness"] = self.readiness()
                    elif command["type"] == "STREAM_START":
                        self.start(command["streamId"], payload, command_id=command_id)
                        result["publisherStarted"] = True
                    elif command["type"] == "STREAM_STOP":
                        if self.streams and command.get("streamId") not in self.streams:
                            raise CommandError("STREAM_ID_MISMATCH")
                        self.stop(command.get("streamId"))
                    result["event"] = "command.ack"
                except (CommandError, KeyError, ValueError, TypeError, OSError) as error:
                    result.update(errorCode=str(error) if isinstance(error, CommandError) else "INVALID_COMMAND",
                                  errorMessage={
                                      "DIRECT_MODE_REQUIRED": "Modo DIRECT local ausente, invalido ou expirado",
                                      "MONITOR_NOT_FOUND": "Monitor nao cadastrado na configuracao local",
                                      "SHINOBI_SOURCE_UNAVAILABLE": "HLS local do Shinobi indisponivel ou invalido",
                                      "RTMP_PUBLISH_FAILED": "Falha ao iniciar a publicacao RTMP/RTMPS",
                                      "ARENA_CONFIG_SYNC_FAILED": "Falha ao sincronizar a configuracao oficial",
                                  }.get(str(error), "Comando nao aceito pelo agent"))
                    if isinstance(error, CommandError) and hasattr(error, "publisher_details"):
                        result.update(error.publisher_details)
                if result.get("errorCode") == "ARENA_CONFIG_SYNC_FAILED":
                    result["configSyncError"] = self.last_config_sync_error
                result.update(eventId=str(uuid.uuid4()), occurredAt=timestamp())
                if result["event"] == "command.ack" and command.get("type") == "STREAM_START":
                    if result.get("streamId") in self.streams:
                        self.streams[result["streamId"]]["command"] = dict(result)
                db.execute("BEGIN IMMEDIATE")
                try:
                    db.execute("INSERT OR REPLACE INTO commands VALUES(?,?)", (command_id, json.dumps(result)))
                    self.outbox.put(result["event"], self.envelope(result), db)
                    db.execute("COMMIT")
                except Exception:
                    db.execute("ROLLBACK")
                    raise
            return result

    def sync_config(self, config_path=None):
        try:
            snapshot = fetch_snapshot(self.config, config_path)
            with self.lock:
                if snapshot['mediaMode'] == 'LEGACY':
                    # Close the upload gate before stopping publishers. Keep files/queue.
                    save_mode(self.config, 'LEGACY')
                    self.stop()
                else:
                    active = [b['monitorId'] for b in snapshot['bindings'] if b.get('isActive') is True]
                    if len(active) != len(set(active)) or any(mid not in self.config.get('monitors', {}) for mid in active):
                        raise ValueError('Unknown local monitor')
                    self.config['activeMonitorIds'] = active
                    for stream_id, slot in list(self.streams.items()):
                        if slot['monitorId'] not in active:
                            self.stop(stream_id)
                    save_mode(self.config, 'DIRECT')
                    self.readiness()
            self.config_sync_ok = True
            self.last_config_sync_at = timestamp()
            self.last_config_sync_error = None
            return snapshot['mediaMode']
        except Exception as error:
            self.config_sync_ok = False
            self.last_config_sync_error = {"errorCode": "CONFIG_SYNC_FAILED",
                                           "message": "Nao foi possivel buscar ou aplicar a configuracao oficial"}
            if isinstance(error, HTTPError):
                self.last_config_sync_error["httpStatus"] = error.code
            raise CommandError('ARENA_CONFIG_SYNC_FAILED') from None

    def start(self, stream_id, payload, command_id=None):
        if not direct_enabled(self.config):
            raise CommandError("DIRECT_MODE_REQUIRED")
        if "activeMonitorIds" in self.config and payload.get("monitorId") not in self.config["activeMonitorIds"]:
            raise CommandError("MONITOR_NOT_FOUND")
        if not isinstance(stream_id, str) or not stream_id:
            raise CommandError("STREAM_ID_REQUIRED")
        if stream_id in self.streams:
            raise CommandError("STREAM_ALREADY_EXISTS")
        if any(slot["monitorId"] == payload.get("monitorId") for slot in self.streams.values()):
            raise CommandError("MONITOR_PUBLISHER_BUSY")
        binding = self.config.get("monitors", {}).get(payload.get("monitorId"))
        if not binding:
            raise CommandError("MONITOR_NOT_FOUND")
        source = binding.get("hlsManifest")
        if not isinstance(source, str) or not source.startswith('/') or any(ord(c) < 32 for c in source):
            raise CommandError("SHINOBI_SOURCE_UNAVAILABLE")
        destination = payload.get("rtmpUrl", "")
        url = urlsplit(destination)
        if (url.scheme not in ("rtmp", "rtmps") or not url.hostname or any(c.isspace() or ord(c) < 32 for c in destination)
                or url.username or url.password or url.query or url.fragment or url.port == 0):
            raise CommandError("PUBLISHER_DESTINATION_DENIED")
        key = payload.get("streamKey")
        if not isinstance(key, str) or not key or any(c in key for c in "\r\n\x00/?#"):
            raise CommandError("INVALID_STREAM_KEY")
        duration = payload.get("durationSeconds", 43200)
        if isinstance(duration, bool) or not isinstance(duration, int) or not 1 <= duration <= 43200:
            raise CommandError("INVALID_STREAM_DURATION")
        resources = resource_checks(self.config)
        if not resources.get("cpuReady", True) or not resources.get("memoryReady", True):
            raise CommandError("DEVICE_RESOURCE_DEGRADED")
        if not hls_check(source).get("ready"):
            raise CommandError("SHINOBI_SOURCE_UNAVAILABLE")
        self.marker.touch(mode=0o600)
        process = None
        try:
            operational_log("publisher.starting", streamId=stream_id, monitorId=payload.get("monitorId"))
            argv = [
                "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-nostats",
                "-progress", "pipe:1", "-protocol_whitelist", "file,crypto,data",
                "-fflags", "+igndts", "-i", source,
                "-map", "0:v:0", "-map", "0:a?", "-c", "copy",
                "-t", str(duration), "-rw_timeout", "5000000", "-f", "flv",
                destination.rstrip("/") + "/" + key,
            ]
            process = RetryingPublisher(argv, [destination, key, source],
                operational_log, {"commandId": command_id, "streamId": stream_id, "monitorId": payload.get("monitorId")}, duration)

            self.streams[stream_id] = {"process": process, "monitorId": payload["monitorId"],
                                       "deadline": time.monotonic() + duration, "command": None}
        except Exception:
            if process is not None:
                process.terminate()
                process.wait(timeout=5)
            if not self.streams:
                self.marker.unlink(missing_ok=True)
            raise
        time.sleep(1)
        if process.poll() is not None or not process.child_running():
            operational_log("publisher.start_failed", streamId=stream_id, monitorId=payload.get("monitorId"),
                            exitCode=process.returncode)
            details = dict(process.last_failure)
            self.stop(stream_id)
            error = CommandError("RTMP_PUBLISH_FAILED")
            error.publisher_details = details
            raise error
        operational_log("publisher.prepared", streamId=stream_id, monitorId=payload.get("monitorId"), pid=process.pid)

    def stop(self, stream_id=None):
        targets = list(self.streams) if stream_id is None else [stream_id]
        for target in targets:
            slot = self.streams.get(target)
            if slot is None:
                continue
            process = slot["process"]
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            del self.streams[target]
            operational_log("publisher.stopped", streamId=target, monitorId=slot["monitorId"])
        if not self.streams:
            self.marker.unlink(missing_ok=True)

    def reap_publishers(self):
        with self.lock:
            for stream_id, slot in list(self.streams.items()):
                process = slot["process"]
                exited = process.poll() is not None
                if not exited and time.monotonic() < slot["deadline"]:
                    continue
                if exited and time.monotonic() < slot["deadline"] and slot["command"]:
                    failed = dict(slot["command"], event="command.failed", eventId=str(uuid.uuid4()),
                                  occurredAt=timestamp(), errorCode="RTMP_PUBLISH_FAILED", publisherStarted=False,
                                  agentVersion=AGENT_VERSION,
                                  errorMessage="Publisher encerrou antes do prazo", **process.last_failure)
                    with closing(self.db()) as db:
                        db.execute("BEGIN IMMEDIATE")
                        db.execute("UPDATE commands SET result=? WHERE id=?", (json.dumps(failed), failed["commandId"]))
                        self.outbox.put("command.failed", self.envelope(failed), db)
                        db.execute("COMMIT")
                    operational_log("publisher.exited", streamId=stream_id, monitorId=slot["monitorId"], exitCode=process.returncode)
                self.stop(stream_id)


class CommandInbox:
    """Transport receipt is separate from serialized operational execution."""
    def __init__(self, runtime, stopping):
        self.runtime, self.stopping = runtime, stopping
        self.pending = queue.Queue(maxsize=64)

    def receive(self, command):
        try:
            self.pending.put_nowait(dict(command))
        except queue.Full:
            return {"accepted": False, "errorCode": "COMMAND_QUEUE_FULL", "commandId": command.get("commandId")}
        return {"accepted": True, "received": True, "commandId": command.get("commandId")}

    def run(self):
        while not self.stopping.is_set():
            try:
                command = self.pending.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                result = self.runtime.execute(command)
                operational_log(result["event"], **{key: result.get(key) for key in
                                ("commandId", "commandType", "streamId", "monitorId", "errorCode")})
            except Exception as error:
                operational_log("command.execution_failed", commandId=command.get("commandId"),
                                exceptionType=type(error).__name__)
            finally:
                self.pending.task_done()


def serve(config):
    import socketio
    runtime = DeviceRuntime(config)
    stopping = threading.Event()
    inbox = CommandInbox(runtime, stopping)
    threading.Thread(target=inbox.run, daemon=True, name="device-commands").start()

    def emit(event, payload):
        envelope = dict(payload, eventId=str(uuid.uuid4()), occurredAt=timestamp(),
                        **identity_fields(config))
        with connection.lock:
            client = connection.client
            if client is not None and client.connected:
                client.emit(event, envelope, namespace="/devices")

    def register(client):
        @client.on("connect", namespace="/devices")
        def connected():
            if connection.client is client:
                runtime.connected = True
                operational_log("gateway.connected")

        @client.on("disconnect", namespace="/devices")
        def disconnected(*_):
            if connection.client is client:
                runtime.connected = False
                operational_log("gateway.disconnected")

        @client.on("command", namespace="/devices")
        def command_received(command):
            if connection.client is not client:
                return {"accepted": False, "errorCode": "STALE_GATEWAY_CONNECTION"}
            if not isinstance(command, dict):
                return {"accepted": False, "errorCode": "INVALID_COMMAND"}
            metadata = {key: command.get(key) for key in ("commandId", "streamId")}
            metadata["commandType"] = command.get("type")
            operational_log("command.received", **metadata)
            return inbox.receive(command)

    connection = GatewayConnection(config, socketio.Client, register)

    def health_loop():
        previous_health = 0
        while not stopping.wait(1):
            with runtime.lock:
                if runtime.streams and not direct_enabled(runtime.config):
                    runtime.stop()
            runtime.reap_publishers()
            if time.monotonic() - previous_health < 15:
                continue
            previous_health = time.monotonic()
            status = runtime.readiness()
            status["checkedAt"] = timestamp()
            target = runtime.root / "status.tmp"
            target.write_text(json.dumps(status, indent=2) + "\n")
            target.replace(runtime.root / "status.json")
            try:
                emit("readiness.ready" if status["status"] == "READY" else "readiness.degraded", status)
            except (OSError, socketio.exceptions.SocketIOError):
                pass

    def send_confirmed(event, envelope):
        received = threading.Event()
        response = []
        def acknowledged(*args):
            response.extend(args)
            received.set()
        with connection.lock:
            client = connection.client
            if client is None or not client.connected:
                return None
            client.emit(event, envelope, namespace="/devices", callback=acknowledged)
        received.wait(8)
        ack = response[0] if response else None
        if not isinstance(ack, dict) or ack.get("accepted") is not True or ack.get("eventId") != envelope.get("eventId"):
            # Never log the backend error body, command payload or credentials.
            print(json.dumps({"event": "event.ack_pending", "eventType": event,
                              "callbackReceived": received.is_set(),
                              "accepted": isinstance(ack, dict) and ack.get("accepted") is True,
                              "eventIdMatches": isinstance(ack, dict) and ack.get("eventId") == envelope.get("eventId"),
                              "ackKeys": sorted(ack) if isinstance(ack, dict) else []}), flush=True)
        return ack

    def event_loop():
        while not stopping.wait(1):
            if connection.is_connected():
                runtime.outbox.step(send_confirmed)

    def config_loop():
        while not stopping.is_set():
            try:
                runtime.sync_config()
            except CommandError:
                operational_log("config.sync_failed", errorCode="ARENA_CONFIG_SYNC_FAILED")
            stopping.wait(60)

    def heartbeat_loop():
        while not stopping.wait(15):
            try:
                emit("device.heartbeat", {"agentVersion": AGENT_VERSION})
            except (OSError, socketio.exceptions.SocketIOError):
                pass

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.set())
    config_thread = threading.Thread(target=config_loop, name="device-config", daemon=True)
    config_thread.start()
    thread = threading.Thread(target=health_loop, name="device-health", daemon=True)
    thread.start()
    events = threading.Thread(target=event_loop, name="device-events", daemon=True)
    events.start()
    heartbeat = threading.Thread(target=heartbeat_loop, name="device-heartbeat", daemon=True)
    heartbeat.start()
    try:
        delay = 1
        while not stopping.is_set():
            if not thread.is_alive() or not events.is_alive() or not heartbeat.is_alive():
                raise RuntimeError("HEALTH_WORKER_STOPPED")
            if not config.get("deviceToken"):
                stopping.wait(10)
                continue
            try:
                if not connection.is_connected():
                    runtime.connected = False
                    connection.connect()
                delay = 1
                stopping.wait(5)
            except (OSError, ValueError, socketio.exceptions.SocketIOError) as error:
                runtime.connected = False
                operational_log("gateway.connect_failed", exceptionType=type(error).__name__, retrySeconds=delay)
                stopping.wait(delay * random.uniform(0.8, 1.2))
                delay = min(60, delay * 2)
    finally:
        stopping.set()
        connection.close()
        with runtime.lock:
            runtime.stop()


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("action", choices=["serve", "check"], default="serve", nargs="?")
    args = parser.parse_args()
    settings = json.loads(Path(args.config).read_text())
    if args.action == "check":
        print(json.dumps(DeviceRuntime(settings).readiness(), indent=2))
    else:
        serve(settings)
