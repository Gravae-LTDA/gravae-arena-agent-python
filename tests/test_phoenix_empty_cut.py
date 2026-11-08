"""Phoenix empty-cut watchdog: corte de 0 byte -> reinicia SO' aquele monitor.
Carrega a classe do fonte via ast, sem importar o servico nem tocar em Pi."""
import ast
import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'


def load_cls(tmp):
    tree = ast.parse(SOURCE.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'EmptyCutWatchdog')
    alerts = MagicMock()
    scope = {'os': os, 're': re, 'json': json, 'time': time, 'Path': Path,
             'log': MagicMock(), 'alerts': alerts,
             'CONFIG_PATH': Path(tmp) / 'device.json'}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), str(SOURCE), 'exec'), scope)
    W = scope['EmptyCutWatchdog']
    W.VIDEOS_DIRS = [Path(tmp) / 'videos']
    return W, alerts


class EmptyCut(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        (Path(self.tmp) / 'device.json').write_text(json.dumps({'shinobiApiKey': 'K', 'shinobiGroupKey': 'ArenaX'}))
        self.W, self.alerts = load_cls(self.tmp)
        self.w = self.W()
        self.w.started_at = time.time() - 3000
        self.calls = []
        self.w._restart_monitor = lambda k, g, mid: self.calls.append(mid) or True

    def cut(self, mid, age, size, name=None):
        d = Path(self.tmp) / 'videos' / 'ArenaX' / mid
        d.mkdir(parents=True, exist_ok=True)
        f = d / (name or ('c%d.mp4' % age))
        f.write_bytes(b'x' * size)
        t = time.time() - age
        os.utime(f, (t, t))
        return f

    def test_restarts_only_monitor_with_empty_cut(self):
        self.cut('quadra04_camera01', 400, 0)
        self.cut('quadra01_camera01', 400, 1000)
        self.assertEqual(self.w.check(), 1)
        self.assertEqual(self.calls, ['quadra04_camera01'])

    def test_ignores_cut_still_settling_and_old_backlog(self):
        self.cut('quadra04_camera01', 30, 0)            # ainda gravando
        self.w.started_at = time.time() - 100
        self.cut('quadra05_camera01', 500, 0)           # antes do watcher subir
        self.assertEqual(self.w.check(), 0)
        self.assertEqual(self.calls, [])

    def test_same_file_not_handled_twice_and_cooldown(self):
        self.cut('quadra04_camera01', 400, 0, 'a.mp4')
        self.w.check()
        self.w.check()
        self.cut('quadra04_camera01', 300, 0, 'b.mp4')   # novo vazio dentro do cooldown
        self.w.check()
        self.assertEqual(self.calls, ['quadra04_camera01'])

    def test_daily_cap_only_alerts(self):
        self.w.restarts['quadra04_camera01'] = [time.time() - 7200 - i for i in range(6)]
        self.cut('quadra04_camera01', 400, 0)
        self.w.check()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.alerts.add.call_args[0][0], 'empty_cut_persistent')

    def test_post_restart_verification(self):
        self.w.pending_verify['quadra04_camera01'] = time.time() - 1000
        self.cut('quadra04_camera01', 400, 5000)
        self.w.check()
        self.assertEqual(self.alerts.add.call_args[0][0], 'empty_cut_recovered')
        self.w.pending_verify['quadra06_camera01'] = time.time() - 1000
        self.w.restarts['quadra06_camera01'] = [time.time() - 1000]
        self.cut('quadra06_camera01', 400, 0)
        self.w.check()
        kinds = [c[0][0] for c in self.alerts.add.call_args_list]
        self.assertIn('empty_cut_persistent', kinds)
        self.assertEqual(self.calls, [])   # nao insiste no restart

    def test_skips_without_config(self):
        (Path(self.tmp) / 'device.json').write_text('{}')
        self.cut('quadra04_camera01', 400, 0)
        self.assertEqual(self.w.check(), 0)


if __name__ == '__main__':
    unittest.main()
