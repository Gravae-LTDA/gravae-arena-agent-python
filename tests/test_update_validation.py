"""Exercise validation without importing the service or touching a Raspberry."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class UpdateValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse((ROOT / 'gravae_agent.py').read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_validate_update_content')
        scope = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<validator>', 'exec'), scope)
        cls.validate = staticmethod(scope['_validate_update_content'])

    def test_all_fallback_modules_also_work_with_the_installed_old_updater(self):
        for filename in ('gravae_agent.py', 'phoenix_daemon.py', 'hands_up_module.py'):
            content = (ROOT / filename).read_bytes()
            self.assertTrue(content.startswith(b'#'), filename)
            self.validate(filename, content)

    def test_valid_docstring_bom_and_import_headers(self):
        for source in (b'"""module"""\nimport os\n', b'\xef\xbb\xbfimport os\n', b'\nimport os\n'):
            self.validate('module.py', source)

    def test_rejects_error_pages_truncated_code_and_empty_downloads(self):
        for source in (b'', b'# unavailable', b'404: Not Found', b'<html>Cloudflare</html>', b'#!/usr/bin/env python3\ndef broken('):
            with self.assertRaises(ValueError):
                self.validate('module.py', source)

    def test_never_executes_downloaded_code(self):
        self.validate('module.py', b'import os\nraise RuntimeError("must not execute")\n')

if __name__ == '__main__':
    unittest.main()
