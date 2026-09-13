import ast
import json
import re
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

class MonitorControl(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'gravae_agent.py'
        tree = ast.parse(path.read_text())
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('shinobi_monitor_control', 'shinobi_monitor_restart')]
        self.url = MagicMock()
        self.url.return_value.__enter__.return_value.read.return_value = b'{"ok":true}'
        self.scope = dict(re=re, threading=threading, json=json, time=MagicMock(), urllib=MagicMock(),
            CONFIG={'shinobiGroupKey':'ArenaTeste', 'shinobiApiKey':'private'},
            _monitor_control_lock=threading.Lock(), shinobi_monitor_get=MagicMock(return_value={'success':True, 'monitor':{'mid':'cancha01_camera02','mode':'record'}}))
        self.scope['urllib'].request.urlopen = self.url
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), self.scope)
    def call(self, action='restart', mid='cancha01_camera02'):
        return self.scope['shinobi_monitor_control'](mid, action)
    def test_restart_preserves_recording_and_only_targets_one_monitor(self):
        result = self.call()
        self.assertTrue(result['success'])
        self.assertFalse(result['mediaVerified'])
        self.assertEqual([c.args[0].split('/')[-1] for c in self.url.call_args_list], ['stop','record'])
    def test_start_rejection_is_not_success_or_global_restart(self):
        self.url.return_value.__enter__.return_value.read.side_effect = [b'{"ok":true}', b'{"ok":false}']
        result=self.call()
        self.assertFalse(result['success']); self.assertEqual(result['failedStep'], 'record')
    def test_timeout_requires_reconciliation_without_retry(self):
        self.url.side_effect=TimeoutError('secret URL')
        result=self.call(); self.assertTrue(result['reconcileRequired'])
        self.assertNotIn('secret',str(result)); self.assertEqual(self.url.call_count,1)
    def test_stopped_monitor_is_not_started_by_restart(self):
        self.scope['shinobi_monitor_get'].return_value['monitor']['mode']='stop'
        self.assertFalse(self.call()['accepted']); self.url.assert_not_called()
    def test_rejects_invalid_target_and_unknown_action(self):
        self.assertFalse(self.call(mid='../other')['success'])
        self.assertFalse(self.call(action='pm2')['success']); self.url.assert_not_called()
    def test_busy_control_does_not_overlap(self):
        self.scope['_monitor_control_lock'].acquire()
        self.assertEqual(self.call()['errorCode'],'MONITOR_CONTROL_BUSY'); self.url.assert_not_called()
