import base64
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile
import json
from direct_installer import bindings, wg_config, InstallError
from direct_installer import configure_v4, configure_http_agent, reload_http_agent, media_identity, camera_sources

class InstallerSafety(unittest.TestCase):
    def enrollment(self):
        return dict(vpnIp='10.89.100.10', allowedIps=['10.89.0.0/16'], hubPublicKey=base64.b64encode(bytes(32)).decode(), hubEndpoint='35.198.58.45:51820')
    def test_no_full_tunnel(self):
        e = self.enrollment(); e['allowedIps'] = ['0.0.0.0/0']
        with self.assertRaises(InstallError): wg_config(e, 'staging', 'private')
    def test_environment_isolation(self):
        with self.assertRaises(InstallError): wg_config(self.enrollment(), 'prod', 'private')
    def test_no_config_injection(self):
        e = self.enrollment(); e['hubEndpoint'] = 'host:22\nPostUp=reboot'
        with self.assertRaises(InstallError): wg_config(e, 'staging', 'private')
    def test_only_expected_subnet(self):
        result = wg_config(self.enrollment(), 'staging', 'private')
        self.assertIn('Address = 10.89.100.10/32', result)
        self.assertIn('PersistentKeepalive = 25', result)
    def test_no_path_traversal_in_camera(self):
        with self.assertRaises(InstallError): bindings([dict(blockSlug='../etc', cameraSlug='camera01', monitorId='m')])
    def test_empty_cameras_never_ready(self):
        with self.assertRaises(InstallError): bindings([])
    def test_duplicate_cameras_rejected(self):
        m = dict(blockSlug='quadra01', cameraSlug='camera01', monitorId='quadra01_camera01')
        with self.assertRaises(InstallError): bindings([m, m])

    def test_official_identity_overrides_external_serial(self):
        self.assertEqual(media_identity({'deviceId': 'pitunnel', 'mediaDeviceId': 'shinobi', 'shinobiId': 'shinobi'}), 'shinobi')
        with self.assertRaises(InstallError): media_identity({'mediaDeviceId': 'a', 'shinobiId': 'b'})

    def test_v4_preserves_queue_identity_and_enables_adaptive_webhook(self):
        writes = {}
        data = {'deviceId': 'shinobi', 'groupKey': 'arena', 'shinobiKey': 'local-key', 'monitors': [{'monitorId': 'quadra01_camera01'}]}
        current = {'deviceId': 'old-queue-id', 'monitors': {}}
        cfg = {'deviceId': 'old-queue-id', 'queueDir': '/preserved', 'collectSince': 123}
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'shinobi_upload_hook.js').write_text('// hook')
            with patch('direct_installer.camera_sources', return_value={'quadra01_camera01': {'rtspUrl': 'rtsp://camera/video'}}), patch('direct_installer.atomic', side_effect=lambda path, value: writes.update({str(path): value})):
                configure_v4(data, current, cfg, Path(tmp))
        self.assertEqual(cfg['queueDir'], '/preserved')
        self.assertEqual(cfg['collectSince'], 123)
        self.assertEqual(cfg['queueIdentity'], 'old-queue-id')
        self.assertEqual(cfg['mediaDeviceId'], 'shinobi')
        self.assertTrue(cfg['adaptiveUploadEnabled'])
        self.assertTrue(cfg['requireClosedFile'])
        self.assertEqual(cfg['scanIntervalSeconds'], 300)
        self.assertEqual(current['hlsDecodeIntervalSeconds'], 300)
        self.assertEqual(json.loads(writes['/etc/gravae/shinobi-upload-hook.json'])['token'], cfg['completionWebhook']['token'])
        self.assertIn('gravae-confirmed-video-cleanup.timer', ' '.join(writes))

    def test_missing_camera_source_blocks_installation(self):
        with patch('direct_installer.urllib.request.urlopen') as request:
            request.return_value.__enter__.return_value.read.return_value = b'[]'
            with self.assertRaises(InstallError): camera_sources({'shinobiKey': 'k', 'groupKey': 'g', 'monitors': [{'monitorId': 'm'}]})

if __name__ == '__main__': unittest.main()

class HttpAgentIdentity(unittest.TestCase):
    def test_unchanged_identity_does_not_require_restart(self):
        with patch('direct_installer.Path.exists', return_value=True), patch('direct_installer.read', return_value={'shinobiGroupKey':'ArenaTeste','shinobiApiKey':'local'}), patch('direct_installer.atomic') as write:
            self.assertFalse(configure_http_agent({'groupKey':'ArenaTeste','shinobiKey':'local'}))
            write.assert_not_called()

    def test_reload_requires_controlled_version_and_only_restarts_http(self):
        with patch('direct_installer.http_agent_version', return_value='4.0.1'), patch('direct_installer.Path.exists', return_value=False), patch('direct_installer.atomic') as write, patch('direct_installer.run') as run:
            reload_http_agent()
            self.assertEqual([c.args[0] for c in run.call_args_list], [['systemctl','daemon-reload'],['systemctl','restart','gravae-agent']])
            self.assertIn('GRAVAE_STARTUP_REPAIRS=disabled', write.call_args_list[-1].args[1])
        with patch('direct_installer.http_agent_version', return_value='3.7.7'), patch('direct_installer.run') as run:
            with self.assertRaises(InstallError): reload_http_agent()
            run.assert_not_called()

    def test_preserves_existing_agent_fields_without_installing_backend_secret(self):
        writes = {}
        with patch('direct_installer.Path.exists', return_value=True), patch('direct_installer.read', return_value={'deviceId':'external','mediaMode':'LEGACY'}), patch('direct_installer.atomic', side_effect=lambda p,v:writes.update({str(p):json.loads(v)})):
            configure_http_agent({'groupKey':'ArenaTeste','shinobiKey':'local','externalKey':'never-copy'})
        self.assertEqual(writes['/etc/gravae/device.json'], {'deviceId':'external','mediaMode':'LEGACY','shinobiGroupKey':'ArenaTeste','shinobiApiKey':'local'})
    def test_rejects_another_shinobi_group_before_writing(self):
        with patch('direct_installer.Path.exists', return_value=True), patch('direct_installer.read', return_value={'shinobiGroupKey':'other'}), patch('direct_installer.atomic') as write:
            with self.assertRaises(InstallError): configure_http_agent({'groupKey':'ArenaTeste','shinobiKey':'local'})
            write.assert_not_called()


class OpsKeyInstall(unittest.TestCase):
    def test_adds_key_without_replacing_existing_support_keys(self):
        from direct_installer import install_ops_key
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / '.ssh'; folder.mkdir(); target = folder / 'authorized_keys'
            target.write_text('ssh-ed25519 ZXhpc3Rpbmc= support\n')
            data = {'opsSshUser': 'gravae', 'opsPublicKey': 'ssh-ed25519 bmV3'}
            with patch('pwd.getpwnam', return_value=SimpleNamespace(pw_dir=tmp, pw_uid=1, pw_gid=1)), patch('direct_installer.os.chown'):
                install_ops_key(data); install_ops_key(data)
            self.assertEqual(target.read_text().count('ssh-ed25519 bmV3'), 1)
            self.assertIn('support', target.read_text())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
    def test_rejects_key_options_and_shell_in_user(self):
        from direct_installer import install_ops_key
        for data in [{'opsSshUser':'gravae;reboot','opsPublicKey':'ssh-ed25519 bmV3'}, {'opsSshUser':'gravae','opsPublicKey':'command="exec" ssh-ed25519 bmV3'}]:
            with self.assertRaises(InstallError): install_ops_key(data)
