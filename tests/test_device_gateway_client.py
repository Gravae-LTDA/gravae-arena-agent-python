from datetime import datetime, timedelta, timezone
from contextlib import closing
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from device_gateway_client import DeviceRuntime


class DeviceCommandTests(unittest.TestCase):
    def test_internal_key_is_rejected_before_runtime_initialization(self):
        with self.assertRaisesRegex(ValueError, "SHARED_BACKEND_TOKEN_FORBIDDEN"):
            DeviceRuntime({"EXTERNAL_KEY": "internal"})

    def setUp(self):
        gate = patch("device_gateway_client.direct_enabled", return_value=True)
        gate.start(); self.addCleanup(gate.stop)
        health = patch.object(DeviceRuntime, "readiness", return_value={"status": "READY"})
        health.start(); self.addCleanup(health.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = DeviceRuntime({"stateDir": str(self.root), "deviceId": "device",
                                      "arenaId": "arena", "liveActiveFile": str(self.root / "live")})
        self.addCleanup(self.runtime.lock_file.close)

    def command(self, kind="READINESS_CHECK"):
        return {"commandId": "command", "deviceId": "device", "arenaId": "arena",
                "type": kind, "streamId": "stream", "payload": {},
                "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()}

    def test_duplicate_start_does_not_spawn_twice(self):
        command = self.command("STREAM_START")
        with patch.object(self.runtime, "start") as start:
            first = self.runtime.execute(command)
            second = self.runtime.execute(command)
        self.assertEqual(first["event"], "command.ack")
        self.assertEqual(second, first)
        start.assert_called_once()

    def test_expired_command_is_not_executed(self):
        command = self.command("STREAM_START")
        command["expiresAt"] = "2020-01-01T00:00:00Z"
        with patch.object(self.runtime, "start") as start:
            result = self.runtime.execute(command)
        self.assertEqual(result["errorCode"], "DEVICE_COMMAND_EXPIRED")
        start.assert_not_called()

    def test_wrong_device_cannot_replay_ack(self):
        command = self.command()
        self.runtime.execute(command)
        command["deviceId"] = "other"
        self.assertEqual(self.runtime.execute(command)["errorCode"], "DEVICE_IDENTITY_MISMATCH")

    def test_media_identity_overrides_external_serial(self):
        self.runtime.config.update(mediaDeviceId="shinobi", shinobiId="shinobi")
        command = self.command()
        command.update(mediaDeviceId="shinobi", shinobiId="shinobi", deviceId="external-serial")
        with patch.object(self.runtime, "readiness", return_value={}):
            result = self.runtime.execute(command)
        self.assertEqual(result["event"], "command.ack")
        self.assertEqual(self.runtime.envelope(result)["mediaDeviceId"], "shinobi")
        self.assertNotIn("deviceId", self.runtime.envelope(result))

    def test_conflicting_official_ids_are_rejected(self):
        command = self.command()
        command.update(mediaDeviceId="device", shinobiId="other")
        self.assertEqual(self.runtime.execute(command)["errorCode"], "DEVICE_IDENTITY_MISMATCH")

    def test_external_serial_does_not_authenticate_migrated_device(self):
        self.runtime.config["mediaDeviceId"] = "shinobi"
        self.assertEqual(self.runtime.execute(self.command())["errorCode"], "DEVICE_IDENTITY_MISMATCH")

    def test_unknown_monitor_fails(self):
        self.assertEqual(self.runtime.execute(self.command("STREAM_START"))["errorCode"], "MONITOR_NOT_FOUND")

    def test_stop_cannot_stop_another_stream(self):
        self.runtime.streams["other"] = {}
        self.assertEqual(self.runtime.execute(self.command("STREAM_STOP"))["errorCode"], "STREAM_ID_MISMATCH")

    def test_crash_inflight_is_persisted_as_failure(self):
        with closing(self.runtime.db()) as db:
            db.execute("INSERT INTO commands VALUES(?,?)", ("command", json.dumps({"event": "pending"})))
        self.runtime.lock_file.close()
        restarted = DeviceRuntime(self.runtime.config)
        self.addCleanup(restarted.lock_file.close)
        self.assertEqual(restarted.execute(self.command())["errorCode"], "DEVICE_RESTARTED")

    def test_dynamic_destination_uses_exact_command_and_copy(self):
        manifest = self.root / "s.m3u8"
        manifest.write_text("#EXTM3U\n")
        self.runtime.config.update(monitors={"camera": {"hlsManifest": str(manifest), "rtspUrl": "rtsp://camera.local/feed"}},
                                   publisherHosts=["old-host"])
        command = self.command("STREAM_START")
        command["payload"] = {"monitorId": "camera", "rtmpUrl": "rtmp://203.0.113.77:1935/live/", "streamKey": "new-stream"}
        with patch('device_gateway_client.hls_check', return_value={"ready": True}), \
             patch('device_gateway_client.resource_checks', return_value={"shmReady": True,"shinobiDescriptorsReady": True}), \
             patch('device_gateway_client.time.sleep'), \
             patch('device_gateway_client.RetryingPublisher') as publisher:
            publisher.return_value.poll.return_value = None
            publisher.return_value.pid = 123
            result = self.runtime.execute(command)
            args = publisher.call_args.args[0]
            self.assertEqual(args[-1], 'rtmp://203.0.113.77:1935/live/new-stream')
            self.assertEqual(args[args.index('-c')+1], 'copy')
            self.assertNotIn('-r', args)
            self.assertNotIn('-re', args)
            self.assertEqual(args[args.index('-i')+1], str(manifest))
            self.assertNotIn('-rtsp_transport', args)
            self.assertTrue(result['publisherStarted'])
            self.assertEqual(result['event'], 'command.ack')

    def test_backoff_after_source_failure_never_acks(self):
        manifest = self.root / 's.m3u8'
        manifest.write_text('#EXTM3U\n')
        self.runtime.config['monitors'] = {'camera': {'hlsManifest': str(manifest)}}
        command = self.command('STREAM_START')
        command['payload'] = {'monitorId': 'camera', 'rtmpUrl': 'rtmp://203.0.113.77/live', 'streamKey': 'secret'}
        with patch('device_gateway_client.hls_check', return_value={'ready': True}), patch('device_gateway_client.resource_checks', return_value={}), patch('device_gateway_client.time.sleep'), patch('device_gateway_client.RetryingPublisher') as factory:
            process = factory.return_value
            process.poll.return_value = None
            process.child_running.return_value = False
            process.last_failure = {'causeCode': 'MEDIA_SOURCE_ACCESS_DENIED', 'failureStage': 'SOURCE', 'exitCode': 8, 'signal': None}
            result = self.runtime.execute(command)
        self.assertEqual(result['event'], 'command.failed')
        self.assertEqual(result['causeCode'], 'MEDIA_SOURCE_ACCESS_DENIED')
        self.assertEqual(result['errorCode'], 'RTMP_PUBLISH_FAILED')
        self.assertNotIn('secret', json.dumps(result))
        process.terminate.assert_called_once()

    def test_missing_shinobi_source_does_not_fallback_to_camera_rtsp(self):
        self.runtime.config['monitors'] = {'camera': {'rtspUrl': 'rtsp://camera.local/feed'}}
        command = self.command('STREAM_START')
        command['payload'] = {'monitorId': 'camera', 'rtmpUrl': 'rtmp://worker/live', 'streamKey': 'stream'}
        with patch('device_gateway_client.hls_check') as hls, \
             patch('device_gateway_client.resource_checks', return_value={'cpuReady': True, 'memoryReady': True, 'shinobiDescriptorsReady': False, 'shmReady': False}), \
             patch('device_gateway_client.time.sleep'), \
             patch('device_gateway_client.RetryingPublisher') as publisher:
            publisher.return_value.poll.return_value = None
            publisher.return_value.pid = 123
            self.assertEqual(self.runtime.execute(command)['errorCode'], 'SHINOBI_SOURCE_UNAVAILABLE')
            publisher.assert_not_called()
            hls.assert_not_called()

    def test_destination_is_restricted(self):
        manifest = self.root / "s.m3u8"
        manifest.write_text("#EXTM3U\n")
        self.runtime.config["monitors"] = {"camera": {"hlsManifest": str(manifest), "rtspUrl": "rtsp://camera.local/feed"}}
        command = self.command("STREAM_START")
        command["payload"] = {"monitorId": "camera", "rtmpUrl": "https://untrusted/live", "streamKey": "key"}
        self.assertEqual(self.runtime.execute(command)["errorCode"], "PUBLISHER_DESTINATION_DENIED")


if __name__ == "__main__":
    unittest.main()
