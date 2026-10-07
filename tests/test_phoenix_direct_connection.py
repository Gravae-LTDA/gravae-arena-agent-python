"""Phoenix numa Pi instalada em conexão DIRECT (VPN, sem cloudflared).

Sem isto o Phoenix vigiava cloudflared — serviço que não existe na Pi DIRECT:
alerta "cloudflared down" eterno (vira anomalia no OPS), restart inútil e setup
"incompleto" (watchdog desligado).
"""
import ast
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

SOURCE = Path(__file__).resolve().parents[1] / 'phoenix_daemon.py'


def load(device_json=None, wg_conf=False, cloudflared_installed=False):
    """Executa o bloco SERVICES + detecção DIRECT com arquivos/units simulados."""
    tree = ast.parse(SOURCE.read_text())
    wanted = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') in ('SERVICES', 'WG_UNIT', 'WG_CONF', 'DIRECT_CONNECTION') for t in node.targets):
            wanted.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == 'is_direct_connection':
            wanted.append(node)
        elif isinstance(node, ast.If) and 'DIRECT_CONNECTION' in ast.unparse(node.test):
            wanted.append(node)
    tmp = Path(tempfile.mkdtemp())
    device = tmp / 'device.json'
    if device_json is not None:
        device.write_text(json.dumps(device_json))
    wg = tmp / 'wg0.conf'
    if wg_conf:
        wg.write_text('[Interface]\n')

    def fake_path(p):
        return {'/etc/gravae/device.json': device, '/etc/wireguard/wg0.conf': wg}.get(str(p), Path(p))

    subprocess = MagicMock()
    subprocess.run.return_value = MagicMock(stdout='cloudflared.service enabled\n' if cloudflared_installed else '0 unit files listed.\n')
    ns = {'Path': fake_path, 'json': json, 'subprocess': subprocess}
    exec(compile(ast.Module(body=wanted, type_ignores=[]), str(SOURCE), 'exec'), ns)
    return ns


class DirectConnectionTest(unittest.TestCase):
    def test_legacy_keeps_watching_cloudflared(self):
        ns = load(device_json={'arenaType': 'gravae'}, cloudflared_installed=True)
        self.assertFalse(ns['DIRECT_CONNECTION'])
        self.assertIn('cloudflared', ns['SERVICES'])
        self.assertNotIn('wg-quick@wg0', ns['SERVICES'])

    def test_direct_flag_swaps_cloudflared_for_wireguard(self):
        ns = load(device_json={'connectionMode': 'DIRECT'}, wg_conf=True)
        self.assertTrue(ns['DIRECT_CONNECTION'])
        self.assertNotIn('cloudflared', ns['SERVICES'])
        self.assertTrue(ns['SERVICES']['wg-quick@wg0']['critical'])

    def test_wg0_without_cloudflared_is_direct_even_without_flag(self):
        self.assertTrue(load(device_json={}, wg_conf=True)['DIRECT_CONNECTION'])

    def test_migrated_legacy_with_wg0_and_cloudflared_stays_legacy(self):
        # Arena LEGACY migrada para mídia DIRECT mantém o túnel: nada muda.
        self.assertFalse(load(device_json={}, wg_conf=True, cloudflared_installed=True)['DIRECT_CONNECTION'])


if __name__ == '__main__':
    unittest.main()
