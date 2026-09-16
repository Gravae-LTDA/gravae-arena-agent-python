import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from datetime import datetime, timedelta, timezone
from device_gateway_client import DeviceRuntime
from arena_config_sync import fetch_snapshot, ConfigSyncError
from media_mode import direct_enabled

class ConfigSyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.config = dict(stateDir=self.tmp.name, mediaModeFile=str(Path(self.tmp.name)/'mode.json'), liveActiveFile=str(Path(self.tmp.name)/'live'), mediaDeviceId='shinobi', arenaId='arena', backendUrl='https://api.test', deviceToken='private', monitors={'camera':{}})
        self.runtime = DeviceRuntime(self.config); self.addCleanup(self.runtime.lock_file.close)
    def command(self):
        return dict(commandId='sync',type='ARENA_CONFIG_SYNC',mediaDeviceId='shinobi',arenaId='arena',expiresAt=(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat(),payload={'mediaMode':'DIRECT','configPath':'/internal/media-devices/shinobi/config'})
    def snapshot(self, mode):
        return dict(mediaMode=mode,mediaDeviceId='shinobi',arenaId='arena',bindings=[{'monitorId':'camera','isActive':True}])
    def test_snapshot_not_payload_decides_mode_and_ack_repeats_without_refetch(self):
        with patch('device_gateway_client.fetch_snapshot',return_value=self.snapshot('LEGACY')) as fetch, patch.object(self.runtime,'stop') as stop:
            first=self.runtime.execute(self.command()); second=self.runtime.execute(self.command())
        self.assertEqual(first['event'],'command.ack'); self.assertEqual(first,second)
        fetch.assert_called_once(); stop.assert_called_once(); self.assertFalse(direct_enabled(self.config))
    def test_failed_fetch_never_acks(self):
        with patch('device_gateway_client.fetch_snapshot',side_effect=OSError('private-secret')):
            result=self.runtime.execute(self.command())
        self.assertEqual(result['event'],'command.failed'); self.assertEqual(result['errorCode'],'ARENA_CONFIG_SYNC_FAILED')
        self.assertNotIn('private-secret',json.dumps(result))
    def test_direct_updates_active_bindings_and_checks_readiness(self):
        with patch('device_gateway_client.fetch_snapshot',return_value=self.snapshot('DIRECT')),patch.object(self.runtime,'readiness',return_value={}) as health:
            result=self.runtime.execute(self.command())
        self.assertEqual(result['event'],'command.ack'); self.assertTrue(direct_enabled(self.config)); health.assert_called_once()
        self.assertEqual(self.config['activeMonitorIds'],['camera'])
    def test_legacy_blocks_publisher_before_ffmpeg(self):
        with patch('device_gateway_client.fetch_snapshot',return_value=self.snapshot('LEGACY')): self.runtime.sync_config()
        with patch('device_gateway_client.RetryingPublisher') as publisher:
            with self.assertRaisesRegex(Exception,'DIRECT_MODE_REQUIRED'): self.runtime.start('live',{'monitorId':'camera'})
        publisher.assert_not_called()
    def test_sync_http_failure_reports_status_without_secret_body(self):
        from urllib.error import HTTPError
        with patch('device_gateway_client.fetch_snapshot', side_effect=HTTPError('https://secret',403,'secret',{},None)):
            result = self.runtime.execute(self.command())
        diagnostics = self.runtime.config_diagnostics()
        self.assertFalse(diagnostics['configSyncOk'])
        self.assertEqual(diagnostics['lastConfigSyncError']['httpStatus'],403)
        self.assertNotIn('secret',json.dumps(diagnostics))
        self.assertEqual(result['event'],'command.failed')

    def test_successful_legacy_sync_is_valid_preparation_but_not_direct(self):
        with patch('device_gateway_client.fetch_snapshot',return_value=self.snapshot('LEGACY')):
            self.runtime.sync_config()
        diagnostics = self.runtime.config_diagnostics()
        self.assertTrue(diagnostics['configSyncOk'])
        self.assertFalse(diagnostics['directModeValid'])
        self.assertIsNotNone(diagnostics['lastConfigSyncAt'])
        self.assertIsNotNone(diagnostics['directModeExpiresAt'])

    def test_no_token_to_arbitrary_config_path_or_redirect(self):
        with patch('arena_config_sync.urllib.request.build_opener') as opener:
            for path in ['https://other.test/config','/internal/media-devices/other/config','//other.test']:
                with self.assertRaises(ConfigSyncError): fetch_snapshot(self.config,path)
        opener.assert_not_called()
    def test_snapshot_identity_checked(self):
        response=Mock(); response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        response.read.return_value=json.dumps({**self.snapshot('DIRECT'),'mediaDeviceId':'other'}).encode()
        with patch('arena_config_sync.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value=response
            with self.assertRaises(ConfigSyncError): fetch_snapshot(self.config)

    def test_official_config_identifies_agent_without_changing_auth(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps(self.snapshot('DIRECT')).encode()
        with patch('arena_config_sync.urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(fetch_snapshot(self.config)['mediaMode'], 'DIRECT')
        request = opener.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://api.test/internal/media-devices/shinobi/config')
        self.assertEqual(request.get_header('Authorization'), 'Bearer private')
        self.assertEqual(request.get_header('User-agent'), 'Gravae-Agent/' + Path('VERSION').read_text().strip())
        self.assertEqual(request.get_header('Accept'), 'application/json')
