from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from device_readiness import hls_check, resource_checks


class MediaReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "s.m3u8"
        self.manifest.write_text("#EXTM3U\n#EXTINF:2,\ns1.ts\n#EXTINF:2,\ns2.ts\n")
        for name in ("s1.ts", "s2.ts"):
            (self.root / name).write_bytes(b"x" * 188)

    def test_valid_shape_still_requires_decoder(self):
        with patch("device_readiness.subprocess.run", return_value=SimpleNamespace(
                returncode=0, stdout=b'{"frames":[{"width":1920}]}', stderr=b"")):
            self.assertTrue(hls_check(self.manifest)["ready"])
        with patch("device_readiness.subprocess.run", return_value=SimpleNamespace(
                returncode=0, stdout=b'{"frames":[]}', stderr=b"")):
            self.assertEqual(hls_check(self.manifest)["errorCode"], "HLS_DECODE_FAILED")

    def test_empty_and_truncated_segments_rejected(self):
        for size in (0, 4096):
            (self.root / "s2.ts").write_bytes(b"x" * size)
            self.assertEqual(hls_check(self.manifest)["errorCode"], "HLS_TRUNCATED_SEGMENT")

    def test_segment_cannot_escape_monitor_directory(self):
        self.manifest.write_text("#EXTM3U\n../secret.ts\ns2.ts\n")
        self.assertEqual(hls_check(self.manifest)["errorCode"], "HLS_INVALID_SEGMENT_PATH")

    def test_low_shm_is_not_ready(self):
        with patch("device_readiness.shutil.disk_usage", return_value=SimpleNamespace(free=1)):
            checks = resource_checks({"procPath": str(self.root)})
        self.assertFalse(checks["shmReady"])

    def test_shinobi_process_title_is_recognized(self):
        proc = self.root / "123"
        proc.mkdir()
        (proc / "cmdline").write_bytes(b"node /home/Shinobi/camera.js\0")
        (proc / "fd").mkdir()
        result = resource_checks({"procPath": str(self.root)})
        self.assertTrue(result["shinobiProcessReady"])
        self.assertEqual(result["shinobiProcessCount"], 1)

    def test_absent_shinobi_is_not_healthy(self):
        result = resource_checks({"procPath": str(self.root)})
        self.assertFalse(result["shinobiDescriptorsReady"])


if __name__ == "__main__":
    unittest.main()
