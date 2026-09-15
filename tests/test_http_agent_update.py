import unittest
from unittest.mock import patch, MagicMock
from direct_installer import update_agent, InstallError

class AgentUpdateTests(unittest.TestCase):
    def setUp(self):
        for name, kwargs in [('identity', {}), ('Path.exists', {'return_value': False}), ('Path.read_text', {'return_value': '4.0.6'}), ('time.sleep', {}), ('atomic', {}), ('run', {})]:
            mock = patch('direct_installer.' + name, **kwargs)
            mock.start(); self.addCleanup(mock.stop)

    def test_current_or_newer_agent_is_not_restarted(self):
        for version in ['4.0.6', '4.1.0']:
            with patch('direct_installer.http_agent_version', return_value=version), patch('direct_installer.urllib.request.urlopen') as request:
                self.assertEqual(update_agent({'serial': 's'}), {'agentVersion': version, 'updated': False})
                request.assert_not_called()

    def test_waits_through_restart_before_returning_success(self):
        response = MagicMock(); response.__enter__.return_value.read.return_value = b'{"success":true}'
        with patch('direct_installer.http_agent_version', side_effect=['4.0.5', OSError('restarting'), '4.0.5', '4.0.6']), patch('direct_installer.urllib.request.urlopen', return_value=response) as request:
            self.assertEqual(update_agent({'serial': 's'}), {'agentVersion': '4.0.6', 'updated': True})
            self.assertEqual(request.call_args.args[0].get_method(), 'POST')
            self.assertEqual(request.call_args.args[0].full_url, 'http://127.0.0.1:8888/update/perform')

    def test_live_blocks_restart(self):
        with patch('direct_installer.Path.exists', return_value=True), patch('direct_installer.http_agent_version') as version:
            with self.assertRaisesRegex(InstallError, 'LIVE_IN_PROGRESS'): update_agent({'serial': 's'})
            version.assert_not_called()

    def test_future_bundle_version_is_used_without_changing_installer(self):
        response = MagicMock(); response.__enter__.return_value.read.return_value = b'{"success":true}'
        with patch('direct_installer.Path.read_text', return_value='4.0.7'), patch('direct_installer.http_agent_version', side_effect=['4.0.6', '4.0.7']), patch('direct_installer.urllib.request.urlopen', return_value=response):
            self.assertEqual(update_agent({'serial': 's'})['agentVersion'], '4.0.7')

    def test_unconfirmed_update_times_out(self):
        response = MagicMock(); response.__enter__.return_value.read.return_value = b'{"success":true}'
        with patch('direct_installer.http_agent_version', return_value='3.7.8'), patch('direct_installer.urllib.request.urlopen', return_value=response), patch('direct_installer.time.monotonic', side_effect=[0, 181]):
            with self.assertRaisesRegex(InstallError, 'AGENT_UPDATE_FAILED'): update_agent({'serial': 's'})

if __name__ == '__main__': unittest.main()
