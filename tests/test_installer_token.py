import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
from direct_installer import gateway_token_ready, install_gateway_token, InstallError


class TokenRecovery(unittest.TestCase):
    data = {'arenaId': 'arena', 'backendUrl': 'https://api.gravae.io'}
    config = {'arenaId': 'arena', 'mediaDeviceId': 'shinobi', 'deviceToken': 'private-token'}

    def test_valid_token_stays_on_raspberry(self):
        with patch('direct_installer.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(json.dumps({'arenaId': 'arena', 'mediaDeviceId': 'shinobi'}).encode())
            self.assertTrue(gateway_token_ready(self.data, self.config))
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, 'https://api.gravae.io/internal/media-devices/shinobi/config')

    def test_only_rejected_credentials_request_rotation(self):
        for code in (401, 403, 429, 500, 302):
            with self.subTest(code=code), patch('direct_installer.urllib.request.build_opener') as opener:
                opener.return_value.open.side_effect = urllib.error.HTTPError('url', code, 'error', {}, io.BytesIO(b''))
                if code in (401, 403):
                    self.assertFalse(gateway_token_ready(self.data, self.config))
                else:
                    with self.assertRaisesRegex(InstallError, 'BACKEND_UNAVAILABLE'):
                        gateway_token_ready(self.data, self.config)

    def test_mismatched_snapshot_is_rejected(self):
        with patch('direct_installer.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = io.BytesIO(b'{"arenaId":"other","mediaDeviceId":"shinobi"}')
            with self.assertRaisesRegex(InstallError, 'IDENTITY_MISMATCH'):
                gateway_token_ready(self.data, self.config)

    def test_atomic_rotation_preserves_config_and_root_only_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'device-client.json'
            current = {**self.config, 'queueStatusFile': '/existing/status.json'}
            install_gateway_token(path, current, {'deviceGatewayToken': 'new-token'})
            saved = json.loads(path.read_text())
            self.assertEqual(saved['deviceToken'], 'new-token')
            self.assertEqual(saved['queueStatusFile'], '/existing/status.json')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_missing_token_is_not_a_successful_rotation(self):
        with self.assertRaises(InstallError):
            install_gateway_token('/unused', dict(self.config), {'mediaDeviceId': 'shinobi'})
