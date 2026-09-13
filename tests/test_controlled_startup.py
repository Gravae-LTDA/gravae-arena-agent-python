"""Load only the startup function so test collection cannot touch host services."""
import ast
import os
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'gravae_agent.py'

class ControlledStartup(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(SOURCE.read_text())
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_startup_repairs')
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        self.scope = {name: MagicMock(name=name) for name in names}
        self.scope['os'] = os
        exec(compile(ast.Module(body=[fn], type_ignores=[]), str(SOURCE), 'exec'), self.scope)

    def test_controlled_startup_never_runs_repairs_or_spawns_threads(self):
        for policy in ('disabled', '', 'typo'):
            with patch.dict(os.environ, {'GRAVAE_STARTUP_REPAIRS': policy}):
                self.scope['run_startup_repairs']()
        self.scope['subprocess'].run.assert_not_called()
        self.scope['threading'].Thread.assert_not_called()
        self.scope['_fix_dangerous_settings'].assert_not_called()
        self.scope['_fix_button_daemon_polling'].assert_not_called()

    def test_legacy_default_still_runs_startup_repairs(self):
        with patch.dict(os.environ, {}, clear=True):
            self.scope['run_startup_repairs']()
        self.scope['_fix_dangerous_settings'].assert_called_once()
        self.scope['_fix_button_daemon_polling'].assert_called_once()
        targets = [c.kwargs['target'] for c in self.scope['threading'].Thread.call_args_list]
        self.assertIn(self.scope['_fix_shinobi_monitors_stimeout'], targets)
        self.assertIn(self.scope['ensure_shinobi_probe_disabled'], targets)

if __name__ == '__main__':
    unittest.main()
