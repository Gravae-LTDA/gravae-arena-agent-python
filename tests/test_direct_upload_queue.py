from contextlib import closing
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from unittest.mock import Mock
from urllib.error import URLError

from direct_upload_queue import BackendDelivery, PermanentUploadError, QueueFull, UploadQueue, reject_internal_credentials


class BackendContractTests(unittest.TestCase):
    def test_internal_credentials_are_rejected_even_when_empty(self):
        for key in ("EXTERNAL_KEY", "externalKey", "ARENA_DEVICE_WEBHOOK_TOKEN", "webhookToken"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "SHARED_BACKEND_TOKEN_FORBIDDEN"):
                reject_internal_credentials({key: ""})

    def setUp(self):
        gate = patch("direct_upload_queue.direct_enabled", return_value=True)
        gate.start()
        self.addCleanup(gate.stop)
        self.delivery = BackendDelivery({
            "backendUrl": "https://backend.example", "arenaId": "arena", "deviceId": "device",
            "cameraBindings": {"monitor": {"blockId": "block", "cameraId": "camera"}},
        })
        self.job = {"monitor_id": "monitor", "mtime_ns": 1700000000123000000,
                    "source": "/clips/clip.mp4", "size": 10, "id": "job"}

    def test_metadata_matches_backend_and_is_stable(self):
        value = self.delivery.metadata(self.job)
        self.assertEqual(value["recordedAt"], "2023-11-14T22:13:20.123Z")
        self.assertEqual(value["sourceFileName"], "clip.mp4")
        self.assertEqual(value["blockId"], "block")
        self.assertEqual(value["cameraId"], "camera")
        self.assertEqual(self.delivery.metadata(self.job), value)
        self.assertNotIn("filename", value)

    def test_unknown_monitor_rejected(self):
        self.job["monitor_id"] = "unknown"
        with self.assertRaises(PermanentUploadError):
            self.delivery.metadata(self.job)

    def test_upload_uses_official_identity_without_changing_file_identity(self):
        before = self.delivery.metadata(self.job)
        self.delivery.config.update(mediaDeviceId="shinobi", shinobiId="shinobi")
        after = self.delivery.metadata(self.job)
        self.assertEqual(after["mediaDeviceId"], "shinobi")
        self.assertEqual(after["shinobiId"], "shinobi")
        self.assertEqual(after["recordedAt"], before["recordedAt"])
        self.assertEqual(after["sourceFileName"], before["sourceFileName"])

    def test_slug_identity_preferred_without_internal_uuids(self):
        self.delivery.config.update(groupKey="ArenaTeste", cameraBindings={
            "monitor": {"blockSlug": "cancha01", "cameraSlug": "camera02"}})
        value = self.delivery.metadata(self.job)
        self.assertEqual(value["groupKey"], "ArenaTeste")
        self.assertEqual(value["blockSlug"], "cancha01")
        self.assertEqual(value["cameraSlug"], "camera02")
        self.assertNotIn("blockId", value)
        self.assertNotIn("arenaId", value)

    def test_partial_slug_binding_without_legacy_identity_rejected(self):
        self.delivery.config.update(groupKey="ArenaTeste", cameraBindings={
            "monitor": {"blockSlug": "cancha01"}})
        with self.assertRaises(PermanentUploadError):
            self.delivery.metadata(self.job)

    def test_receipt_only_retries_confirmation(self):
        with patch.object(self.delivery, "post", return_value={}) as post:
            self.delivery(self.job, {"originalVideoId": "original", "objectKey": "key"},
                          lambda _: self.fail("Already uploaded"))
        self.assertEqual(post.call_args.args[0], "/internal/original-videos/original/upload-complete")

    def test_live_pauses_before_any_backend_request(self):
        with patch.object(self.delivery, "live_active", return_value=True), patch.object(self.delivery, "post") as post:
            with self.assertRaises(OSError):
                self.delivery(self.job, None, lambda _: None)
            post.assert_not_called()

    def test_terminal_failure_uses_original_id(self):
        with patch.object(self.delivery, "post", return_value={}) as post:
            self.delivery.report_failure(self.job, {"originalVideoId": "original"}, lambda _: None)
        self.assertEqual(post.call_args.args[0], "/internal/original-videos/original/upload-fail")

    def test_expired_ticket_is_renewed_with_same_original(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "clip.mp4"
            source.write_bytes(b"video")
            self.job["spool"] = str(source)
            ticket = {"originalVideoId": "original", "objectKey": "key", "uploadUrl": "https://r2.example/object"}
            failed = Mock(returncode=22, stdin=io.StringIO())
            failed.poll.return_value = 22
            success = Mock(returncode=0, stdin=io.StringIO())
            success.poll.return_value = 0
            receipts = []
            with patch.object(self.delivery, "post", return_value=ticket) as post, patch(
                    "direct_upload_queue.subprocess.Popen", side_effect=[failed, success]):
                with self.assertRaises(OSError):
                    self.delivery(self.job, None, receipts.append)
                self.assertEqual(receipts[-1]["stage"], "upload_pending")
                self.delivery(self.job, receipts[-1], receipts.append)
            self.assertEqual([call.args[0] for call in post.call_args_list], [
                "/internal/original-videos", "/internal/original-videos",
                "/internal/original-videos/original/upload-complete"])
            self.assertEqual(receipts[-1]["stage"], "uploaded")

    def test_live_start_terminates_inflight_upload(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "clip.mp4"
            source.write_bytes(b"video")
            self.job["spool"] = str(source)
            process = Mock(stdin=io.StringIO())
            process.poll.return_value = None
            ticket = {"originalVideoId": "original", "objectKey": "key", "uploadUrl": "https://r2.example/object"}
            with patch.object(self.delivery, "post", return_value=ticket), patch.object(
                    self.delivery, "live_active", side_effect=[False, False, True]), patch(
                    "direct_upload_queue.subprocess.Popen", return_value=process):
                with self.assertRaisesRegex(OSError, "PAUSED_FOR_LIVE"):
                    self.delivery(self.job, None, lambda _: None)
            process.terminate.assert_called_once()

    def test_reads_individual_token_from_private_device_config(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "device.json"
            path.write_text(json.dumps({"deviceId": "device", "arenaId": "arena", "deviceToken": "individual"}))
            path.chmod(0o600)
            self.delivery.config["deviceClientConfig"] = str(path)
            self.assertEqual(self.delivery.token(), "individual")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                self.delivery.token()


class DurableQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.queue = UploadQueue(self.root / "queue", min_free=0)

    def enqueue(self, name="clip.mp4"):
        source = self.root / name
        source.write_bytes(b"test-video")
        return source, self.queue.enqueue(source, "camera02", "staging")

    def test_burst_deduplicates_and_survives_restart(self):
        for index in range(100):
            source, job_id = self.enqueue(str(index) + ".mp4")
            self.assertEqual(self.queue.enqueue(source, "camera02", "staging"), job_id)
        reopened = UploadQueue(self.root / "queue", min_free=0)
        self.assertEqual(reopened.status()["counts"], {"pending": 100})
        seen = []
        while reopened.step(lambda job, receipt, save: seen.append(job["id"])):
            pass
        self.assertEqual(len(set(seen)), 100)
        self.assertEqual(reopened.status()["counts"], {"completed": 100})

    def test_selected_jobs_do_not_drain_old_fixtures(self):
        self.enqueue("old.mp4")
        _, selected = self.enqueue("selected.mp4")
        seen = []
        self.queue.step(lambda job, *_: seen.append(job["id"]), [selected])
        self.assertEqual(seen, [selected])
        self.assertEqual(self.queue.status()["counts"], {"completed": 1, "pending": 1})
        self.assertFalse(self.queue.step(lambda *_: self.fail("No selection"), []))

    def test_spool_survives_source_retention(self):
        source, job_id = self.enqueue()
        source.unlink()
        job = self.queue.claim()
        self.assertEqual(job["id"], job_id)
        self.assertEqual(Path(job["spool"]).read_bytes(), b"test-video")

    def test_failed_job_does_not_block_next_clip(self):
        self.enqueue("a.mp4")
        self.enqueue("b.mp4")
        def fail(*args):
            raise OSError("network unavailable")
        self.queue.step(fail)
        seen = []
        self.queue.step(lambda job, receipt, save: seen.append(Path(job["source"]).name))
        self.assertEqual(seen, ["b.mp4"])
        self.assertEqual(self.queue.status()["counts"], {"completed": 1, "retry": 1})

    def test_restart_recovers_inflight_job(self):
        _, job_id = self.enqueue()
        self.queue.claim()
        reopened = UploadQueue(self.root / "queue", min_free=0)
        reopened.recover()
        self.assertEqual(reopened.claim()["id"], job_id)

    def test_lost_confirmation_does_not_repeat_object_upload(self):
        self.enqueue()
        uploads = []
        def deliver(job, receipt, save):
            if not receipt:
                uploads.append(job["id"])
                save({"originalVideoId": "original-1"})
                raise OSError("confirmation unavailable")
            self.assertEqual(receipt["originalVideoId"], "original-1")
        self.queue.step(deliver)
        with closing(self.queue.connect()) as db:
            db.execute("UPDATE jobs SET next_attempt=0")
        self.queue.step(deliver)
        self.assertEqual(len(uploads), 1)
        self.assertEqual(self.queue.status()["counts"], {"completed": 1})

    def test_capacity_rejection_preserves_source(self):
        self.queue.max_items = 1
        self.enqueue("a.mp4")
        with self.assertRaises(QueueFull):
            self.enqueue("b.mp4")
        self.assertTrue((self.root / "b.mp4").exists())
        self.assertEqual(self.queue.status()["counts"], {"pending": 1})

    def test_long_internet_outage_never_exhausts_retries(self):
        self.enqueue()
        def offline(*args):
            raise URLError("internet disconnected")
        for _ in range(30):
            with closing(self.queue.connect()) as db:
                db.execute("UPDATE jobs SET next_attempt=0")
            self.queue.step(offline)
        self.assertEqual(self.queue.status()["counts"], {"retry": 1})
        next_retry = self.queue.status()["nextRetryAt"]
        self.assertGreater(next_retry, time.time())
        self.assertLessEqual(next_retry, time.time() + 900)
        reopened = UploadQueue(self.root / "queue", min_free=0)
        reopened.recover()
        self.assertEqual(reopened.status()["nextRetryAt"], next_retry)
        self.assertFalse(reopened.step(lambda *args: self.fail("Backoff must be respected")))
        with closing(reopened.connect()) as db:
            db.execute("UPDATE jobs SET next_attempt=0")
        resumed = []
        reopened.step(lambda job, receipt, save: resumed.append(job["id"]))
        self.assertEqual(len(resumed), 1)
        self.assertEqual(reopened.status()["counts"], {"completed": 1})

    def test_missing_spool_is_reported_for_manual_recovery(self):
        _, job_id = self.enqueue()
        with closing(self.queue.connect()) as db:
            spool = db.execute("SELECT spool FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
        Path(spool).unlink()
        self.queue.step(lambda *args: self.fail("Missing video cannot be uploaded"))
        self.assertEqual(self.queue.status()["counts"], {"failed": 1})

    def test_failure_notification_survives_network_outage_and_restart(self):
        _, job_id = self.enqueue()
        with closing(self.queue.connect()) as db:
            spool = db.execute("SELECT spool FROM jobs WHERE id=?", (job_id,)).fetchone()[0]
        Path(spool).unlink()
        delivery = Mock()
        delivery.report_failure.side_effect = OSError("offline")
        self.queue.step(delivery)
        with closing(self.queue.connect()) as db:
            db.execute("UPDATE jobs SET next_attempt=0")
        self.queue.step(delivery)
        self.assertEqual(self.queue.status()["counts"], {"fail_reporting": 1})
        self.queue.claim()
        self.queue.recover()
        with closing(self.queue.connect()) as db:
            db.execute("UPDATE jobs SET next_attempt=0")
        delivery.report_failure.side_effect = None
        self.queue.step(delivery)
        self.assertEqual(self.queue.status()["counts"], {"failed": 1})
        delivery.assert_not_called()


if __name__ == "__main__":
    unittest.main()
