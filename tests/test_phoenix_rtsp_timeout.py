"""Phoenix rtsp-timeout: flag escolhida pelo ffmpeg que o SHINOBI usa (ffmpegDir),
não pelo do sistema — sem tocar em Raspberry nem importar o serviço."""
import ast
import json
import os
import re
import subprocess
from pathlib import Path
import unittest
from unittest.mock import MagicMock, mock_open, patch

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'
METHODS = ('_shinobi_ffmpeg_binary', '_ffmpeg_major', 'ensure_rtsp_timeout')


def load_guardian():
    tree = ast.parse(SOURCE.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ServiceGuardian')
    body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in METHODS]
    fake = ast.ClassDef(name='G', bases=[], keywords=[], body=body, decorator_list=[])
    scope = {'os': os, 're': re, 'json': json, 'subprocess': subprocess, 'log': MagicMock()}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fake], type_ignores=[])), str(SOURCE), 'exec'), scope)
    return scope


def run_out(stdout):
    return MagicMock(stdout=stdout, returncode=0)


class PhoenixRtspTimeout(unittest.TestCase):
    def setUp(self):
        self.scope = load_guardian()
        self.g = self.scope['G']()

    def test_uses_static_ffmpeg_from_conf_json(self):
        conf = json.dumps({'ffmpegDir': '/home/Shinobi/ffmpeg/ffmpeg'})
        with patch('builtins.open', mock_open(read_data=conf)), \
             patch.object(os.path, 'isdir', return_value=False), \
             patch.object(os.path, 'isfile', return_value=True), \
             patch.object(os, 'access', return_value=True):
            self.assertEqual(self.g._shinobi_ffmpeg_binary(), '/home/Shinobi/ffmpeg/ffmpeg')

    def test_falls_back_to_system_ffmpeg(self):
        with patch('builtins.open', mock_open(read_data=json.dumps({}))):
            self.assertEqual(self.g._shinobi_ffmpeg_binary(), 'ffmpeg')

    def test_parses_versions(self):
        cases = {
            'ffmpeg version 7.1.2-0+deb13u1+rpt2 Copyright': 7,
            'ffmpeg version n7.1 Copyright': 7,
            'ffmpeg version 4.2.1-static https://johnvansickle.com': 4,
            'ffmpeg version 5.1.6-0+deb12u1': 5,
            'command not found': None,
        }
        self.g._shinobi_ffmpeg_binary = lambda: 'ffmpeg'
        for out, want in cases.items():
            with patch.object(subprocess, 'run', return_value=run_out(out)):
                self.assertEqual(self.g._ffmpeg_major(), want, out)

    def test_static_4_on_new_debian_gets_stimeout(self):
        """O caso que o código antigo quebrava: sistema 7.x, Shinobi com 4.2.1 estático."""
        self.g._shinobi_db_base = lambda: ['mysql']
        self.g.restart_pm2_process = MagicMock()
        self.g._ffmpeg_major = lambda: 4
        calls = []
        def fake_run(cmd, **kw):
            calls.append(cmd)
            # saída real do mysql -N -B: última linha com cust_input vazio
            return run_out('quadra01_camera01\t\n' if 'SELECT' in cmd[-1] else '')
        with patch.object(subprocess, 'run', side_effect=fake_run):
            self.assertEqual(self.g.ensure_rtsp_timeout(), 1)
        self.assertIn('-stimeout 10000000', calls[-1][-1])

    def test_unknown_version_changes_nothing(self):
        self.g._shinobi_db_base = lambda: ['mysql']
        self.g.restart_pm2_process = MagicMock()
        self.g._ffmpeg_major = lambda: None
        with patch.object(subprocess, 'run') as run:
            self.assertEqual(self.g.ensure_rtsp_timeout(), 0)
            run.assert_not_called()
        self.g.restart_pm2_process.assert_not_called()


if __name__ == '__main__':
    unittest.main()
