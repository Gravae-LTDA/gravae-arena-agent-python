"""Phoenix press-audit: evidencia de video alem de Events, status acumulado
na janela e sem contagem dupla. Carrega a classe do fonte via ast."""
import ast
import glob
import json
import os
import re
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'


def load(tmp):
    tree = ast.parse(SOURCE.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'PressToVideoAuditor')
    alerts = MagicMock()
    scope = {'os': os, 're': re, 'json': json, 'glob': glob, 'subprocess': subprocess,
             'datetime': datetime, 'timedelta': timedelta, 'Path': Path,
             'log': MagicMock(), 'alerts': alerts, 'LOG_DIR': Path(tmp)}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), str(SOURCE), 'exec'), scope)
    A = scope['PressToVideoAuditor']
    A.VIDEOS_DIRS = (Path(tmp) / 'videos',)
    return A, alerts


def fmt(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


class PressAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.A, self.alerts = load(self.tmp)
        self.now = datetime.now().replace(microsecond=0)
        self.a = self.A()
        self.a.last_ts = fmt(self.now - timedelta(hours=1))
        self.presses = []
        self.events = {}
        self.sql = {'Videos': '', 'Logs': ''}
        self.a._recent_presses = lambda since: [p for p in self.presses if p[0] >= since]
        self.a._label_to_mids = lambda: {'Campo 1': ['campo01_camera01'], 'Campo 2': ['campo02_camera01']}
        self.a._events_since = lambda since: self.events

        def mysql(q):
            return self.sql['Videos'] if 'FROM Videos' in q else self.sql['Logs']
        self.a._mysql = mysql

    def status(self):
        return json.loads((Path(self.tmp) / 'press_audit.json').read_text())

    def test_lost_when_no_event_and_no_video(self):
        t = self.now - timedelta(minutes=10)
        self.presses = [(t, 'Campo 1')]
        self.assertTrue(self.a.check())
        self.assertEqual(self.status()['lost'], 1)

    def test_video_row_without_event_is_not_lost(self):
        t = self.now - timedelta(minutes=10)
        self.presses = [(t, 'Campo 1')]
        self.sql['Videos'] = 'campo01_camera01\t%s\n' % fmt(t - timedelta(seconds=25))
        self.assertFalse(self.a.check())
        self.assertEqual(self.status()['lost'], 0)

    def test_uploaded_video_in_logs_utc_counts(self):
        t = self.now - timedelta(minutes=10)
        self.presses = [(t, 'Campo 1')]
        utc = (t - timedelta(seconds=20)).astimezone().astimezone(tz=__import__('datetime').timezone.utc)
        info = {'type': 'Video Deleted', 'msg': {'video': {'mid': 'campo01_camera01', 'size': 15000000,
                'time': utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')}}}
        self.sql['Logs'] = json.dumps(info) + '\n'
        self.assertFalse(self.a.check())

    def test_zero_byte_video_does_not_count(self):
        t = self.now - timedelta(minutes=10)
        self.presses = [(t, 'Campo 1')]
        d = Path(self.tmp) / 'videos' / 'ArenaX' / 'campo01_camera01'
        d.mkdir(parents=True)
        (d / ((t - timedelta(seconds=25)).strftime('%Y-%m-%dT%H-%M-%S') + '.mp4')).write_bytes(b'')
        self.assertTrue(self.a.check())
        (d / ((t - timedelta(seconds=24)).strftime('%Y-%m-%dT%H-%M-%S') + '.mp4')).write_bytes(b'x')
        self.a.last_ts = fmt(self.now - timedelta(hours=1))
        self.assertFalse(self.a.check())

    def test_status_accumulates_and_no_double_count(self):
        t1 = self.now - timedelta(minutes=20)
        self.presses = [(t1, 'Campo 1')]
        self.a.check()
        # rodada seguinte: so' um aperto novo e bom no campo 2
        t2 = self.now - timedelta(minutes=10)
        self.presses = [(t1, 'Campo 1'), (t2, 'Campo 2')]
        self.events = {'campo02_camera01': [t2]}
        self.a.check()
        st = self.status()
        self.assertEqual(st['audited'], 2)   # t1 nao foi re-auditado
        self.assertEqual(st['lost'], 1)      # perda de t1 continua visivel
        self.assertEqual(st['byCourt'], {'Campo 1': 1})

    def test_future_presses_suspend_audit(self):
        # daemon em UTC numa Pi em -03: hora do aperto 3 h no futuro
        self.presses = [(self.now + timedelta(hours=3), 'Campo 1')]
        self.a._recent_presses = lambda since: self.presses
        self.assertFalse(self.a.check())
        self.assertEqual(self.alerts.add.call_args[0][0], 'press_audit_clock_skew')
        self.assertFalse((Path(self.tmp) / 'press_audit.json').exists())


if __name__ == '__main__':
    unittest.main()
