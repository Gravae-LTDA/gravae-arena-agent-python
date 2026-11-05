"""Contador de restart do phoenix precisa decair com o tempo.

Sem isto, 3 restarts por frozen-stream (horas entre eles, porta 8080 sempre de pé)
deixavam o phoenix preso em "exceeded max restart attempts" até o próximo boot
(AAB Rasp 3, 05/11/2026)."""
import ast
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'


def load():
    tree = ast.parse(SOURCE.read_text())
    wanted = [n for n in tree.body
              if (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') in
                  ('SERVICE_RESTART_RESET_WINDOW', 'SERVICE_RESTART_MAX_ATTEMPTS') for t in n.targets))
              or (isinstance(n, ast.FunctionDef) and n.name == 'decay_restart_attempts')]
    ns = {}
    exec(compile(ast.Module(body=wanted, type_ignores=[]), str(SOURCE), 'exec'), ns)
    return ns


class RestartDecayTest(unittest.TestCase):
    def setUp(self):
        self.ns = load()
        self.decay = self.ns['decay_restart_attempts']
        self.window = self.ns['SERVICE_RESTART_RESET_WINDOW']

    def test_esgotado_ha_mais_de_1h_volta_a_zero(self):
        # congelamentos a cada ~13h: o 4º precisa poder reiniciar
        now = 1_000_000
        self.assertEqual(self.decay(3, now - 13 * 3600, now)[0], 0)

    def test_falha_persistente_continua_limitada(self):
        now = 1_000_000
        self.assertEqual(self.decay(3, now - 600, now)[0], 3)
        self.assertEqual(self.decay(2, now - self.window + 1, now)[0], 2)

    def test_sem_tentativas_nao_muda(self):
        self.assertEqual(self.decay(0, 0, 1_000_000), (0, 0))

    def test_os_dois_caminhos_de_restart_usam_o_decay(self):
        src = SOURCE.read_text()
        for fn in ('def restart_pm2_process', 'def restart_service'):
            body = src.split(fn, 1)[1].split('\n    def ', 1)[0]
            self.assertIn('decay_restart_attempts(', body, fn)


if __name__ == '__main__':
    unittest.main()
