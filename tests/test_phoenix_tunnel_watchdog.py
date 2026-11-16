"""Phoenix tunnel watchdog: internet ok + cloudflared com 0 conexões -> restart.
Carrega a classe do fonte via ast, sem importar o serviço nem tocar em Pi."""
import ast
import json
import subprocess
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'


def load_cls(direct=False):
    tree = ast.parse(SOURCE.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'TunnelReadinessWatchdog')
    alerts = MagicMock()
    scope = {'json': json, 'time': time, 'subprocess': subprocess,
             'log': MagicMock(), 'alerts': alerts, 'DIRECT_CONNECTION': direct}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), str(SOURCE), 'exec'), scope)
    return scope['TunnelReadinessWatchdog'], alerts


class TunnelWatchdog(unittest.TestCase):
    def make(self, ready, active=True, direct=False):
        W, alerts = load_cls(direct)
        w = W()
        self.state = {'ready': ready}
        w.ready_connections = lambda: self.state['ready']
        w._cloudflared_active = lambda: active
        self.restarts = []
        w._restart = lambda: self.restarts.append(1) or True
        return w, alerts

    def test_restarts_after_10_min_stuck_with_internet_ok(self):
        w, alerts = self.make(0)
        self.assertFalse(w.check(True, now=0))
        self.assertFalse(w.check(True, now=9 * 60))
        self.assertTrue(w.check(True, now=10 * 60))
        self.assertEqual(len(self.restarts), 1)
        self.assertEqual(alerts.add.call_args[0][0], 'tunnel_stuck_restarted')

    def test_cooldown_between_restarts(self):
        w, _ = self.make(0)
        w.check(True, now=0)
        w.check(True, now=600)
        self.assertFalse(w.check(True, now=600 + 14 * 60))
        self.assertTrue(w.check(True, now=600 + 15 * 60))
        self.assertEqual(len(self.restarts), 2)

    def test_daily_cap(self):
        w, _ = self.make(0)
        w.check(True, now=0)
        t = 600
        for _ in range(10):
            w.check(True, now=t)
            t += 15 * 60
        self.assertEqual(len(self.restarts), w.MAX_RESTARTS_PER_DAY)

    def test_recovery_resets_timer(self):
        w, _ = self.make(0)
        w.check(True, now=0)
        self.state['ready'] = 4
        w.check(True, now=300)
        self.state['ready'] = 0
        w.check(True, now=600)
        self.assertFalse(w.check(True, now=600 + 9 * 60))
        self.assertEqual(self.restarts, [])

    def test_no_action_without_internet_unknown_metrics_inactive_or_direct(self):
        for kwargs, online in (({'ready': 0}, False), ({'ready': None}, True),
                               ({'ready': 0, 'active': False}, True), ({'ready': 0, 'direct': True}, True)):
            w, _ = self.make(**kwargs)
            for t in range(0, 3600, 120):
                w.check(online, now=t)
            self.assertEqual(self.restarts, [], kwargs)


if __name__ == '__main__':
    unittest.main()
