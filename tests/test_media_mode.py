import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from media_mode import direct_enabled
from direct_upload_queue import BackendDelivery, accept_completion

class MediaModeTests(unittest.TestCase):
    def test_webhook_does_not_collect_in_legacy_or_unknown_mode(self):
        with patch('direct_upload_queue.direct_enabled', return_value=False), patch('pathlib.Path.stat') as stat:
            collect = unittest.mock.Mock()
            self.assertEqual(accept_completion({}, {'monitorId': 'm', 'filename': 'video.mp4'}, collect), 'ignored-not-direct')
            collect.assert_not_called()
            stat.assert_not_called()

    def test_webhook_collects_only_allowed_monitor_in_direct(self):
        with tempfile.TemporaryDirectory() as tmp, patch('direct_upload_queue.direct_enabled', return_value=True):
            collect = unittest.mock.Mock(return_value='job')
            config = {'groupKey': 'arena', 'watchDirectories': {'m': tmp}}
            self.assertEqual(accept_completion(config, {'groupKey': 'arena', 'monitorId': 'm', 'filename': 'video.mp4'}, collect), 'job')
            collect.assert_called_once_with(Path(tmp).resolve()/'video.mp4', 'm', notified=True)
    def test_gate_requires_fresh_direct_confirmation_and_matching_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'mode.json'
            config = {'mediaModeFile': str(path), 'mediaDeviceId': 'shinobi', 'arenaId': 'arena'}
            self.assertFalse(direct_enabled(config))
            good = {'mode': 'DIRECT', 'mediaDeviceId': 'shinobi', 'arenaId': 'arena', 'confirmedAt': time.time()-1, 'expiresAt': time.time()+110}
            path.write_text(json.dumps(good)); self.assertTrue(direct_enabled(config))
            for changes in [{'mode': 'LEGACY'}, {'arenaId': 'other'}, {'mediaDeviceId': 'other'}, {'expiresAt': 0}, {'expiresAt': time.time()+500}, {'confirmedAt': time.time()+10}]:
                path.write_text(json.dumps({**good, **changes})); self.assertFalse(direct_enabled(config))
            path.write_text('corrupt'); self.assertFalse(direct_enabled(config))

    def test_direct_delivery_never_requests_ticket_in_legacy(self):
        delivery = BackendDelivery({'backendUrl': 'https://backend.test', 'mediaModeFile': '/nonexistent/mode.json'})
        with patch.object(delivery, 'post') as post:
            with self.assertRaisesRegex(OSError, 'UPLOAD_WAITING_DIRECT'):
                delivery({}, None, lambda value: None)
            post.assert_not_called()

if __name__ == '__main__': unittest.main()
