import ast
import re
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock


class NetworkRead(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'gravae_agent.py'
        nodes = [n for n in ast.parse(path.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'networkmanager_ipv4_method']
        self.process = Mock(TimeoutExpired=subprocess.TimeoutExpired)
        scope = {'re': re, 'subprocess': self.process}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), scope)
        self.read = scope['networkmanager_ipv4_method']

    def test_active_profile_uuid_and_method_are_read_only(self):
        uuid = '12345678-1234-1234-1234-123456789abc'
        self.process.run.side_effect = [Mock(returncode=0, stdout=uuid+'\n'), Mock(returncode=0, stdout='auto\n')]
        self.assertEqual(self.read('eth0'), 'auto')
        self.assertEqual(self.process.run.call_args.args[0], ['nmcli','-g','ipv4.method','connection','show','uuid',uuid])
        self.assertTrue(all('show' in c.args[0] for c in self.process.run.call_args_list))

    def test_inactive_or_unmanaged_interface_is_unknown_not_static(self):
        self.process.run.return_value = Mock(returncode=0, stdout='--\n')
        self.assertIsNone(self.read('wg0'))
        self.assertEqual(self.process.run.call_count, 1)

    def test_failed_command_does_not_claim_dhcp(self):
        self.process.run.return_value = Mock(returncode=1, stdout='auto')
        self.assertIsNone(self.read('eth0'))

    def test_timeout_is_unknown(self):
        self.process.run.side_effect = subprocess.TimeoutExpired('nmcli', 5)
        self.assertIsNone(self.read('eth0'))
