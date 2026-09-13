import json
from pathlib import Path
import tempfile
import unittest

from confirmed_video_cleanup import clean
from direct_upload_queue import UploadQueue


class ConfirmedCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source = root / "2026-09-12T20-39-23.mp4"
        self.source.write_bytes(b"recording")
        self.queue = UploadQueue(root / "queue", min_free=0)
        self.job = self.queue.enqueue(self.source, "monitor", "device")
        self.config = {"queueDir": str(root / "queue"), "watchDirectories": {"monitor": str(root)}}
        self.client = {"monitors": {"monitor": {"hlsManifest": "http://127.0.0.1:8080/key/hls/group/monitor/s.m3u8"}}}

    def complete(self):
        def deliver(job, receipt, save):
            save({"stage": "uploaded", "originalVideoId": "original"})
        self.queue.step(deliver)

    def test_only_confirmed_upload_deleted_and_history_preserved(self):
        self.complete()
        calls = []
        def delete(url):
            calls.append(url)
            self.source.unlink()
        self.assertEqual(clean(self.config, self.client, delete)["deleted"], 1)
        self.assertEqual(clean(self.config, self.client, delete)["deleted"], 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith('/videos/group/monitor/2026-09-12T20-39-23.mp4/delete'))
        self.assertEqual(self.queue.status()["counts"], {"completed": 1})

    def test_upload_without_backend_confirmation_preserved(self):
        def failed_confirmation(job, receipt, save):
            save({"stage": "uploaded", "originalVideoId": "original"})
            raise OSError("backend unavailable")
        self.queue.step(failed_confirmation)
        clean(self.config, self.client, lambda _: self.fail("must not delete"))
        self.assertTrue(self.source.exists())

    def test_changed_file_preserved(self):
        self.complete()
        self.source.write_bytes(b"new recording at same path")
        result = clean(self.config, self.client, lambda _: self.fail("must not delete"))
        self.assertEqual(result["preserved"], 1)
        self.assertTrue(self.source.exists())

    def test_delete_failure_never_requeues_upload(self):
        self.complete()
        def fail(_):
            raise OSError("api unavailable")
        self.assertEqual(clean(self.config, self.client, fail)["preserved"], 1)
        self.assertEqual(self.queue.status()["counts"], {"completed": 1})
        self.assertTrue(self.source.exists())

    def test_local_manifest_uses_explicit_local_api(self):
        self.complete()
        self.client['monitors']['monitor']['hlsManifest'] = '/dev/shm/streams/group/monitor/s.m3u8'
        self.config['localVideoDeleteBases'] = {'monitor': 'http://127.0.0.1:8080/key/videos/group/monitor'}
        self.assertEqual(clean(self.config, self.client, lambda _: self.source.unlink())['deleted'], 1)

    def test_already_removed_record_is_idempotent(self):
        self.complete()
        self.source.unlink()
        self.assertEqual(clean(self.config, self.client, lambda _: False)['alreadyAbsent'], 1)
        self.assertEqual(clean(self.config, self.client, lambda _: self.fail('already clean'))['preserved'], 0)

    def test_missing_database_record_does_not_delete_local_file(self):
        self.complete()
        self.assertEqual(clean(self.config, self.client, lambda _: False)['preserved'], 1)
        self.assertTrue(self.source.exists())

    def test_symlink_and_nonlocal_endpoint_preserved(self):
        self.complete()
        self.source.unlink()
        self.source.symlink_to(Path(self.temp.name) / 'other')
        self.assertEqual(clean(self.config, self.client, lambda _: self.fail("must not delete"))["preserved"], 1)
        self.source.unlink()
        self.client['monitors']['monitor']['hlsManifest'] = 'http://external.example/key/hls/group/monitor/s.m3u8'
        self.assertEqual(clean(self.config, self.client, lambda _: self.fail("must not delete"))["preserved"], 1)


if __name__ == '__main__':
    unittest.main()
