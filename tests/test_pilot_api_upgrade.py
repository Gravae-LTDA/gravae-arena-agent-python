import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('pilot_api_upgrade', Path(__file__).resolve().parents[1] / 'ops/upgrade-pilot-api.py')
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)

class PilotApiUpgrade(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.root = root / 'agent'; self.root.mkdir()
        (self.root / 'gravae_agent.py').write_text('# previous agent\n')
        self.cpu = root / 'cpuinfo'; self.cpu.write_text('Serial\t: ' + upgrade.SERIAL)
        self.dropin = root / 'systemd/controlled.conf'
        for name, value in {'ROOT': self.root, 'CPUINFO': self.cpu, 'DROPIN': self.dropin, 'BACKUPS': root / 'backup', 'OBSERVATION': root / 'observation'}.items():
            p = patch.object(upgrade, name, value); p.start(); self.addCleanup(p.stop)
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for name in upgrade.FILES:
                data = b'4.0.1\n' if name == 'VERSION' else b'# new module\n'
                item = tarfile.TarInfo(name); item.size = len(data); archive.addfile(item, io.BytesIO(data))
        self.archive = root / 'payload.tar.gz'; self.archive.write_bytes(output.getvalue())
        args = ['upgrade', str(self.archive), hashlib.sha256(output.getvalue()).hexdigest()]
        p = patch.object(upgrade.sys, 'argv', args); p.start(); self.addCleanup(p.stop)

    def test_other_arena_is_rejected_before_any_service_action(self):
        self.cpu.write_text('Serial: other')
        with patch.object(upgrade.os, 'geteuid', return_value=0), patch.object(upgrade, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'PILOT_ONLY'): upgrade.main()
        run.assert_not_called()

    def test_failed_health_restores_files_and_dropin(self):
        with patch.object(upgrade.os, 'geteuid', return_value=0), patch.object(upgrade, 'snapshot', return_value={}), patch.object(upgrade, 'run') as run, patch.object(upgrade.time, 'sleep'), patch.object(upgrade.urllib.request, 'urlopen', side_effect=OSError('unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'healthy'): upgrade.main()
        self.assertEqual((self.root / 'gravae_agent.py').read_text(), '# previous agent\n')
        self.assertFalse(self.dropin.exists())
        self.assertFalse((self.root / 'VERSION').exists())
        restarts = [c.args for c in run.call_args_list if 'restart' in c.args]
        self.assertEqual(restarts, [('systemctl', 'restart', 'gravae-agent.service')] * 2)

    def test_success_only_restarts_agent_and_preserves_baseline(self):
        baseline = {'services': {'gateway': '123'}, 'media': [{'pid': 456, 'name': 'ffmpeg'}]}
        with patch.object(upgrade.os, 'geteuid', return_value=0), patch.object(upgrade, 'snapshot', return_value=baseline), patch.object(upgrade, 'run') as run, patch.object(upgrade.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps({'version': '4.0.1'}).encode())) as request, patch('builtins.print'):
            upgrade.main()
        request.assert_called_once_with('http://127.0.0.1:8888/update/version', timeout=2)
        self.assertIn('GRAVAE_STARTUP_REPAIRS=disabled', self.dropin.read_text())
        self.assertEqual([c.args for c in run.call_args_list if 'restart' in c.args], [('systemctl', 'restart', 'gravae-agent.service')])

if __name__ == '__main__': unittest.main()
