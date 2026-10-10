"""Phoenix — teste de velocidade (Mali, 10/10/2026).

O alerta de internet lenta era cego pra nós: media só download
(`speedtest-cli --no-upload`) e, no Debian 13, nem rodava — o speedtest-cli não
vinha instalado e o `pip3 install` é recusado (PEP 668), então o journal só dizia
"Speed test failed" a cada 4h. Agora mede upload, instala pelo apt uma vez e cai
pro Cloudflare via curl se precisar.
"""
import ast
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'


def load(subprocess_mock, speed_file):
    tree = ast.parse(SOURCE.read_text())
    wanted_funcs = {'parse_speedtest_simple', 'classify_speed'}
    nodes = []
    for n in tree.body:
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id.startswith(('DOWNLOAD_', 'UPLOAD_', 'CF_SPEED_', 'SPEED_TEST_FILE'))
                for t in n.targets):
            nodes.append(n)
        elif isinstance(n, ast.FunctionDef) and n.name in wanted_funcs:
            nodes.append(n)
        elif isinstance(n, ast.ClassDef) and n.name == 'ResourceMonitor':
            nodes.append(n)
    alerts = MagicMock()
    scope = {'re': re, 'os': os, 'time': __import__('time'), 'subprocess': subprocess_mock,
             'log': MagicMock(), 'alerts': alerts}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(SOURCE), 'exec'), scope)
    scope['SPEED_TEST_FILE'] = speed_file
    # check_speed lê a constante do escopo do módulo
    scope['ResourceMonitor'].check_speed.__globals__['SPEED_TEST_FILE'] = speed_file
    return scope, alerts


def run_result(stdout='', rc=0):
    r = MagicMock()
    r.returncode = rc
    r.stdout = stdout
    r.stderr = ''
    return r


SIMPLE = "Ping: 12.3 ms\nDownload: 64.2 Mbit/s\nUpload: 3.1 Mbit/s\n"


class SpeedTest(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        f.close()
        self.tmp = f.name

    def tearDown(self):
        os.unlink(self.tmp)

    def test_parse_simple(self):
        sp = MagicMock()
        scope, _ = load(sp, self.tmp)
        self.assertEqual(scope['parse_speedtest_simple'](SIMPLE), (64.2, 3.1))
        self.assertEqual(scope['parse_speedtest_simple']("Download: 10 Mbit/s"), (10.0, None))

    def test_classify(self):
        scope, _ = load(MagicMock(), self.tmp)
        c = scope['classify_speed']
        self.assertEqual(c(64.0, 23.0)[:2], (False, False))  # Mali real: tudo ok
        self.assertEqual(c(64.0, 8.0)[:2], (True, False))    # upload lento
        self.assertEqual(c(64.0, 3.0)[:2], (True, True))     # upload muito lento
        self.assertEqual(c(20.0, 23.0)[:2], (True, False))   # download lento
        self.assertIn('upload 3.0', c(64.0, 3.0)[2])

    def test_upload_lento_alerta_e_salva(self):
        sp = MagicMock()
        sp.run.return_value = run_result(SIMPLE)
        scope, alerts = load(sp, self.tmp)
        rm = scope['ResourceMonitor']()
        rm.check_speed()
        cmd = sp.run.call_args_list[0].args[0]
        self.assertNotIn('--no-upload', cmd)
        alerts.add.assert_called_once()
        self.assertEqual(alerts.add.call_args.args[0], 'very_slow_internet')
        data = json.loads(Path(self.tmp).read_text())
        self.assertEqual((data['speed_mbps'], data['upload_mbps'], data['slow'], data['very_slow']),
                         (64.2, 3.1, True, True))

    def test_sem_speedtest_instala_pelo_apt_uma_vez(self):
        sp = MagicMock()
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd[0])
            if cmd[0] == 'speedtest-cli':
                raise FileNotFoundError
            if cmd[0] == 'curl':
                return run_result(b'2994474' if 'input' in kw else '8033522')
            return run_result()
        sp.run.side_effect = fake_run
        scope, alerts = load(sp, self.tmp)
        rm = scope['ResourceMonitor']()
        rm.check_speed()
        self.assertIn('apt-get', calls)
        self.assertNotIn('pip3', calls)
        data = json.loads(Path(self.tmp).read_text())
        self.assertEqual((data['speed_mbps'], data['upload_mbps']), (64.3, 24.0))  # caiu pro Cloudflare
        calls.clear()
        rm.check_speed()
        self.assertNotIn('apt-get', calls)  # não tenta instalar de novo


if __name__ == '__main__':
    unittest.main()
