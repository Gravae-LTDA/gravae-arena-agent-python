"""Phoenix — escalonamento de conectividade (Glory Soccer, 30/09–06/10/2026).

Dois bugs: (1) o tempo offline era medido com o relógio de parede, que pula dias
numa Pi sem bateria no RTC quando o NTP acerta a hora → o escalonamento ia direto
pro reboot; (2) o reboot bloqueado (uptime < 5 min) marcava o nível 4 mesmo
assim → nunca mais tentava. E a rede gerenciada por NetworkManager não era
reiniciada (só networking/dhcpcd).
"""
import ast
import json
from datetime import datetime, timedelta
from pathlib import Path
import unittest
from unittest.mock import MagicMock

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'


class FakeTime:
    def __init__(self):
        self.mono = 1000.0

    def monotonic(self):
        return self.mono


def load_sentinel(fake_time):
    tree = ast.parse(SOURCE.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ConnectivitySentinel')
    consts = [n for n in tree.body if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id.startswith(('ESCALATION_', 'MAX_REBOOTS', 'MIN_UPTIME')) for t in n.targets)]
    scope = {
        'time': fake_time, 'datetime': datetime, 'timedelta': timedelta, 'json': json,
        'subprocess': MagicMock(), 'log': MagicMock(), 'alerts': MagicMock(),
        'os': __import__('os'), 'Path': Path, 'socket': MagicMock(), 'LOG_DIR': Path('/tmp'),
    }
    mod = ast.Module(body=consts + [cls], type_ignores=[])
    exec(compile(ast.fix_missing_locations(mod), str(SOURCE), 'exec'), scope)
    return scope['ConnectivitySentinel']


class Escalation(unittest.TestCase):
    def setUp(self):
        self.t = FakeTime()
        Cls = load_sentinel(self.t)
        self.s = Cls.__new__(Cls)  # sem __init__ real (lê estado do disco)
        self.s.is_online = True
        self.s.offline_since = None
        self.s._offline_since_mono = None
        self.s.escalation_level = 0
        self.s.actions_taken = []
        self.s.dhcp_fallback_attempted = False
        self.s.check_connectivity = lambda: False
        self.calls = []
        self.s.restart_cloudflared = lambda: self.calls.append('cloudflared')
        self.s.restart_networking = lambda: self.calls.append('networking')
        self.s.try_dhcp_fallback = lambda: self.calls.append('dhcp')
        self.reboot_ok = False
        self.s.reboot_system = lambda: (self.calls.append('reboot'), self.reboot_ok)[1]

    def tick(self, minutes):
        self.t.mono += minutes * 60
        self.s.update()

    def test_salto_do_relogio_de_parede_nao_conta_como_tempo_offline(self):
        self.s.update()  # perde a conexão agora
        self.s.offline_since = datetime.now() - timedelta(days=4)  # NTP "acertou" a hora
        self.tick(1)
        self.assertEqual(self.calls, [])
        self.assertLess(self.s.get_offline_minutes(), 5)

    def test_um_degrau_por_vez_mesmo_muito_tempo_offline(self):
        self.s.update()
        self.tick(300)  # já passou de 4h
        self.tick(1)
        self.tick(1)
        self.assertEqual(self.calls, ['cloudflared', 'networking', 'dhcp'])

    def test_reboot_bloqueado_tenta_de_novo(self):
        self.s.update()
        for _ in range(3):
            self.tick(100)
        self.assertEqual(self.calls[-1], 'dhcp')
        self.tick(10)  # 310 min: tenta reboot, bloqueado
        self.assertEqual(self.calls[-1], 'reboot')
        self.assertLess(self.s.escalation_level, 4)
        self.reboot_ok = True
        self.tick(5)
        self.assertEqual(self.calls.count('reboot'), 2)
        self.assertEqual(self.s.escalation_level, 4)

    def test_voltou_online_zera(self):
        self.s.update()
        self.tick(40)
        self.s.check_connectivity = lambda: True
        self.tick(1)
        self.assertEqual(self.s.escalation_level, 0)
        self.assertIsNone(self.s._offline_since_mono)
        self.assertEqual(self.s.get_offline_minutes(), 0)


class NetworkManagerRestart(unittest.TestCase):
    def test_reativa_conexao_nm(self):
        tree = ast.parse(SOURCE.read_text())
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ConnectivitySentinel')
        body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in ('_reactivate_networkmanager',)]
        sp = MagicMock()
        sp.run.side_effect = [MagicMock(returncode=0), MagicMock(stdout='Wired connection 1\n'), MagicMock()]
        scope = {'subprocess': sp, 'log': MagicMock()}
        fake = ast.ClassDef(name='G', bases=[], keywords=[], body=body, decorator_list=[])
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fake], type_ignores=[])), str(SOURCE), 'exec'), scope)
        g = scope['G'](); g._get_primary_interface = lambda: 'eth0'
        self.assertTrue(g._reactivate_networkmanager())
        self.assertEqual(sp.run.call_args_list[-1].args[0], ['nmcli', 'connection', 'up', 'Wired connection 1'])


if __name__ == '__main__':
    unittest.main()
