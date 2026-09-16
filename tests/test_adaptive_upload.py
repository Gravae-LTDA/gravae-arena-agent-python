import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from adaptive_upload import AdaptiveBandwidth, upload_file


class AdaptiveBandwidthTests(unittest.TestCase):
    def test_activity_marker_remains_until_last_transfer_finishes(self):
        with tempfile.TemporaryDirectory() as root:
            busy = Path(root) / "active"
            b = self.make()
            for _ in range(4):
                b.begin_transfer(busy)
            for _ in range(3):
                b.end_transfer(busy)
                self.assertTrue(busy.exists())
                self.assertTrue(b.status()["transferActive"])
            b.end_transfer(busy)
            self.assertFalse(busy.exists())
            self.assertFalse(b.status()["transferActive"])

    def test_transfers_share_one_pacing_budget_including_live(self):
        b = self.make()
        clock, sent = [0.0], []
        def sleep(seconds):
            clock[0] += seconds
        with patch("adaptive_upload.time.monotonic", side_effect=lambda: clock[0]), \
                patch("adaptive_upload.time.sleep", side_effect=sleep):
            for _ in range(4):
                b.send_chunk(lambda chunk: sent.append(clock[0]), b"x" * 32768, lambda: True, 10)
            self.assertAlmostEqual(sent[-1], 3 * 32768 / b.limit())
            b.set_live(True)
            for _ in range(2):
                b.send_chunk(lambda chunk: sent.append(clock[0]), b"x" * 32768, lambda: True, 10)
            self.assertAlmostEqual(sent[-1] - sent[-2], 32768 / b.limit())

    def test_sampling_uses_aggregate_bytes_once_per_interval(self):
        b = self.make()
        b.sample_at, b.sample_bytes, b.total_sent = 0, 0, 4000
        with patch("adaptive_upload.time.monotonic", return_value=4), patch.object(b, "observe") as observe:
            for _ in range(4):
                b.sample(lambda *_: .02, "example", 443)
        observe.assert_called_once_with(.02, 1000)

    def make(self):
        return AdaptiveBandwidth({'uploadBytesPerSecond': 10 * 1024**2,
                                  'uploadInitialBytesPerSecond': 1024**2})

    def test_healthy_link_increases_gradually_and_respects_maximum(self):
        b = self.make()
        before = b.limit()
        b.observe(.02, before, now=0)
        self.assertGreater(b.limit(), before)
        for i in range(100):
            b.observe(.02, b.limit(), now=i + 1)
        self.assertEqual(b.limit(), b.maximum)

    def test_moderate_congestion_reduces_without_pausing(self):
        b = self.make()
        b.observe(.02, 0, now=0)
        before = b.limit()
        b.observe(.17, before, now=1)
        self.assertEqual(b.limit(), before)
        b.observe(.17, before, now=2)
        self.assertGreater(b.limit(), 0)
        self.assertLess(b.limit(), before)

    def test_latency_jitter_does_not_collapse_upload_rate(self):
        b = self.make()
        b.observe(.028, 0, now=0)
        initial = b.limit()
        for i, latency in enumerate([.17, .028, .10, .039, .17, .065, .10, .029]):
            b.observe(latency, b.limit(), now=(i + 1) * 3)
        self.assertGreaterEqual(b.limit(), initial)
        self.assertFalse(b.paused)

    def test_only_sustained_severe_degradation_pauses_and_recovers(self):
        b = self.make()
        b.observe(.02, 0, now=0)
        b.observe(None, 0, now=1)
        self.assertGreater(b.limit(), 0)
        b.observe(None, 0, now=2)
        self.assertEqual(b.limit(), 0)
        b.observe(.02, 0, now=3)
        self.assertEqual(b.limit(), 0)
        b.observe(.02, 0, now=4)
        self.assertEqual(b.limit(), b.minimum)

    def test_live_reduces_but_never_pauses_a_healthy_upload(self):
        b = self.make()
        normal = b.limit()
        b.set_live(True)
        self.assertEqual(b.limit(), normal * .2)
        self.assertFalse(b.paused)
        b.set_live(False)
        self.assertEqual(b.limit(), normal)

    def test_slow_throughput_reduces_estimate(self):
        b = self.make()
        before = b.limit()
        b.observe(.02, before * .3, now=0)
        self.assertEqual(b.limit(), before)
        b.observe(.02, before * .3, now=3)
        self.assertLess(b.limit(), before)
        self.assertGreaterEqual(b.limit(), b.minimum)

    def test_isolated_slow_samples_do_not_reduce_rate(self):
        b = self.make()
        initial = b.limit()
        b.observe(.03, initial * .4, now=0)
        b.observe(.03, initial * .7, now=3)
        b.observe(.03, initial * .4, now=6)
        self.assertEqual(b.limit(), initial)

    def test_sustained_slow_link_reduction_has_cooldown(self):
        b = self.make()
        b.observe(.03, 100000, now=0)
        b.observe(.03, 100000, now=3)
        reduced = b.limit()
        b.observe(.03, 10000, now=6)
        self.assertEqual(b.limit(), reduced)



class UploadTransportTests(unittest.TestCase):
    def test_streaming_put_preserves_content_length_and_live_does_not_abort(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'clip.mp4'
            data = b'video' * 15000
            source.write_bytes(data)
            live = [False]
            sent = bytearray()
            connection = Mock()
            def send(chunk):
                sent.extend(chunk)
                live[0] = True
            connection.send.side_effect = send
            connection.getresponse.return_value.status = 200
            b = AdaptiveBandwidth({})
            busy = root / 'upload.active'
            upload_file('https://r2.example/clip?signature=secret', source, len(data),
                        {'Content-Type': 'video/mp4'}, b, lambda: live[0], busy,
                        connection_factory=lambda *a, **k: connection, probe=lambda *a: .02)
            self.assertEqual(bytes(sent), data)
            connection.putheader.assert_any_call('Content-Length', str(len(data)))
            connection.putrequest.assert_called_once_with('PUT', '/clip?signature=secret', skip_accept_encoding=True)
            self.assertFalse(busy.exists())
            self.assertFalse(b.paused)
            self.assertTrue(b.live)
            connection.close.assert_called_once()

    def test_pacing_counts_time_already_spent_sending(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'clip.mp4'
            source.write_bytes(b'x' * (32768 * 3))
            clock = [0.0]
            connection = Mock()
            connection.getresponse.return_value.status = 200
            def send(chunk):
                clock[0] += 0.03
            def sleep(seconds):
                clock[0] += seconds
            connection.send.side_effect = send
            with patch('adaptive_upload.time.monotonic', side_effect=lambda: clock[0]), \
                    patch('adaptive_upload.time.sleep', side_effect=sleep):
                upload_file('https://r2.example/clip', source, source.stat().st_size, {},
                            AdaptiveBandwidth({}), lambda: False,
                            connection_factory=lambda *a, **k: connection, probe=lambda *a: .02)
            self.assertLess(clock[0], 0.10)  # Old limiter incorrectly took ~0.1525 seconds.
            self.assertEqual(connection.send.call_count, 3)

    def test_redirect_does_not_forward_signed_request(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'clip.mp4'
            source.write_bytes(b'video')
            connection = Mock()
            connection.getresponse.return_value.status = 307
            with self.assertRaisesRegex(OSError, 'R2_UPLOAD_HTTP_307'):
                upload_file('https://r2.example/clip', source, 5, {}, AdaptiveBandwidth({}), lambda: False,
                            connection_factory=lambda *a, **k: connection, probe=lambda *a: .02)
            connection.putrequest.assert_called_once()


if __name__ == '__main__':
    unittest.main()
