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
    wanted_funcs = {'parse_speedtest_simple', 'classify_speed', 'curl_speed_mbps'}
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

    def fake(self, curl_down=('7738755', 0), curl_up=(b'3422491', 0), speedtest=SIMPLE, calls=None):
        """subprocess.run falso: curl de download/upload e speedtest-cli configuráveis."""
        def run(cmd, **kw):
            if calls is not None:
                calls.append(cmd[0])
            if cmd[0] == 'curl':
                out, rc = curl_up if 'input' in kw else curl_down
                return run_result(out, rc)
            if cmd[0] == 'speedtest-cli':
                if speedtest is FileNotFoundError:
                    raise FileNotFoundError
                return run_result(speedtest)
            return run_result()
        sp = MagicMock()
        sp.run.side_effect = run
        return sp

    def test_curl_speed(self):
        f = load(MagicMock(), self.tmp)[0]['curl_speed_mbps']
        self.assertEqual(f(0, '7738755'), 61.9)
        self.assertEqual(f(28, '250000'), 2.0)   # estourou o -m num link lento: vale
        self.assertIsNone(f(28, '0'))            # timeout sem transferir nada
        self.assertIsNone(f(7, '0'))             # não conectou
        self.assertIsNone(f(0, ''))

    def test_fitsoccer_cloudflare_primeiro_sem_alerta_falso(self):
        # speedtest-cli devolveria 1,9/2,7 (servidor a 2.400 km); o link real é 62/27
        calls = []
        sp = self.fake(speedtest="Download: 1.90 Mbit/s\nUpload: 2.70 Mbit/s\n", calls=calls)
        scope, alerts = load(sp, self.tmp)
        scope['ResourceMonitor']().check_speed()
        self.assertNotIn('speedtest-cli', calls)
        alerts.add.assert_not_called()
        data = json.loads(Path(self.tmp).read_text())
        self.assertEqual((data['speed_mbps'], data['upload_mbps'], data['slow'], data['very_slow']),
                         (61.9, 27.4, False, False))

    def test_link_lento_de_verdade_alerta_pelo_cloudflare(self):
        # 25 MB não descem em 40 s: curl sai com 28, mas a média medida vale
        calls = []
        sp = self.fake(curl_down=('250000', 28), curl_up=(b'60000', 28), calls=calls)
        scope, alerts = load(sp, self.tmp)
        scope['ResourceMonitor']().check_speed()
        self.assertNotIn('speedtest-cli', calls)
        self.assertEqual(alerts.add.call_args.args[0], 'very_slow_internet')
        data = json.loads(Path(self.tmp).read_text())
        self.assertEqual((data['speed_mbps'], data['upload_mbps']), (2.0, 0.5))

    def test_cloudflare_falha_cai_pro_speedtest(self):
        sp = self.fake(curl_down=('0', 7), curl_up=(b'0', 7))
        scope, alerts = load(sp, self.tmp)
        scope['ResourceMonitor']().check_speed()
        cmd = [c.args[0] for c in sp.run.call_args_list if c.args[0][0] == 'speedtest-cli'][0]
        self.assertNotIn('--no-upload', cmd)
        self.assertEqual(alerts.add.call_args.args[0], 'very_slow_internet')
        data = json.loads(Path(self.tmp).read_text())
        self.assertEqual((data['speed_mbps'], data['upload_mbps'], data['slow'], data['very_slow']),
                         (64.2, 3.1, True, True))

    def test_sem_speedtest_instala_pelo_apt_uma_vez(self):
        calls = []
        sp = self.fake(curl_down=('0', 7), curl_up=(b'0', 7), speedtest=FileNotFoundError, calls=calls)
        scope, alerts = load(sp, self.tmp)
        rm = scope['ResourceMonitor']()
        rm.check_speed()
        self.assertIn('apt-get', calls)
        self.assertNotIn('pip3', calls)
        calls.clear()
        rm.check_speed()
        self.assertNotIn('apt-get', calls)  # não tenta instalar de novo


if __name__ == '__main__':
    unittest.main()
