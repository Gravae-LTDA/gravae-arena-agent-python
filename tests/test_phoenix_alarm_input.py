"""Phoenix numa arena de alarm input (aperto pela câmera via FTP, sem gravae-buttons).

Sem isto o Phoenix vigiava gravae-buttons em toda Pi: na arena de alarm o serviço
não existe, e cada partida do phoenix gerava "Service gravae-buttons found down on
startup" crítico (FitSoccer, 30/10/2026).
"""
import ast
import json
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'


def load(device_json=None):
    """Executa o bloco SERVICES + detecção de alarm input com device.json simulado."""
    tree = ast.parse(SOURCE.read_text())
    wanted = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') == 'SERVICES' for t in node.targets):
            wanted.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == 'has_alarm_input':
            wanted.append(node)
        elif isinstance(node, ast.If) and 'has_alarm_input' in ast.unparse(node.test):
            wanted.append(node)
    device = Path(tempfile.mkdtemp()) / 'device.json'
    if device_json is not None:
        device.write_text(json.dumps(device_json))

    def fake_path(p):
        return device if str(p) == '/etc/gravae/device.json' else Path(p)

    ns = {'Path': fake_path, 'json': json}
    exec(compile(ast.Module(body=wanted, type_ignores=[]), str(SOURCE), 'exec'), ns)
    return ns


class AlarmInputTest(unittest.TestCase):
    def test_alarm_input_nao_vigia_gravae_buttons(self):
        ns = load({'arenaType': 'replayme', 'hasAlarmInput': True})
        self.assertNotIn('gravae-buttons', ns['SERVICES'])
        self.assertIn('shinobi', ns['SERVICES'])

    def test_gpio_continua_vigiando(self):
        self.assertIn('gravae-buttons', load({'arenaType': 'gravae'})['SERVICES'])
        self.assertIn('gravae-buttons', load({'hasAlarmInput': False})['SERVICES'])

    def test_sem_device_json_continua_vigiando(self):
        self.assertIn('gravae-buttons', load(None)['SERVICES'])


if __name__ == '__main__':
    unittest.main()
