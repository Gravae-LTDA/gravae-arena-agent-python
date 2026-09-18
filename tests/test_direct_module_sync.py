import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

for _name in ('RPi', 'RPi.GPIO'):
    sys.modules.setdefault(_name, types.ModuleType(_name))

import gravae_agent


def _fake_run(copies, restarts):
    def run(cmd, *args, **kwargs):
        if cmd[:2] == ['sudo', 'cp']:
            Path(cmd[3]).write_bytes(Path(cmd[2]).read_bytes())
            copies.append(cmd[3])
        elif cmd[:3] == ['sudo', 'systemctl', 'restart']:
            restarts.append(cmd[3])
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')
    return run


class DirectModuleSyncTest(unittest.TestCase):
    def _setup(self, root):
        source = Path(root) / 'agent'
        client = Path(root) / 'client'
        queue = Path(root) / 'queue'
        for d in (source, client, queue):
            d.mkdir()
        # fonte do agent: config_sync mudou, VERSION mudou, media_mode igual
        (source / 'arena_config_sync.py').write_text("UA novo")
        (source / 'VERSION').write_text("4.0.12")
        (source / 'media_mode.py').write_text("igual")
        (source / 'direct_upload_queue.py').write_text("upload novo")
        # deployado (velho)
        (client / 'arena_config_sync.py').write_text("UA velho")
        (client / 'VERSION').write_text("4.0.6")
        (client / 'media_mode.py').write_text("igual")
        (queue / 'direct_upload_queue.py').write_text("upload velho")
        (queue / 'media_mode.py').write_text("igual")
        targets = (
            (str(client), ('arena_config_sync.py', 'media_mode.py', 'VERSION')),
            (str(queue), ('direct_upload_queue.py', 'media_mode.py')),
        )
        return str(source), str(client), str(queue), targets

    def test_syncs_changed_files_and_restarts(self):
        with tempfile.TemporaryDirectory() as root:
            source, client, queue, targets = self._setup(root)
            copies, restarts = [], []
            with patch.object(gravae_agent, 'AGENT_PATH', source), \
                 patch.object(gravae_agent, 'DIRECT_MODULE_TARGETS', targets), \
                 patch.object(gravae_agent.subprocess, 'run', _fake_run(copies, restarts)):
                gravae_agent._sync_direct_modules()
            # so os arquivos que mudaram foram copiados (media_mode.py identico fica de fora)
            self.assertEqual(
                sorted(Path(p).name for p in copies),
                ['VERSION', 'arena_config_sync.py', 'direct_upload_queue.py'],
            )
            # servicos reiniciados uma vez cada
            self.assertEqual(sorted(restarts), ['gravae-device-client', 'gravae-direct-queue'])
            # conteudo realmente atualizado
            self.assertEqual(Path(client, 'VERSION').read_text(), '4.0.12')
            self.assertEqual(Path(client, 'arena_config_sync.py').read_text(), 'UA novo')

    def test_noop_when_nothing_changed(self):
        with tempfile.TemporaryDirectory() as root:
            source, client, queue, targets = self._setup(root)
            # deixa tudo identico a fonte
            for folder, names in targets:
                for name in names:
                    Path(folder, name).write_bytes(Path(source, name).read_bytes())
            copies, restarts = [], []
            with patch.object(gravae_agent, 'AGENT_PATH', source), \
                 patch.object(gravae_agent, 'DIRECT_MODULE_TARGETS', targets), \
                 patch.object(gravae_agent.subprocess, 'run', _fake_run(copies, restarts)):
                gravae_agent._sync_direct_modules()
            self.assertEqual(copies, [])
            self.assertEqual(restarts, [])  # nada mudou -> nao reinicia

    def test_noop_when_not_direct_arena(self):
        with tempfile.TemporaryDirectory() as root:
            source, client, queue, targets = self._setup(root)
            missing = ((str(Path(root) / 'inexistente'), ('VERSION',)),)
            copies, restarts = [], []
            with patch.object(gravae_agent, 'AGENT_PATH', source), \
                 patch.object(gravae_agent, 'DIRECT_MODULE_TARGETS', missing), \
                 patch.object(gravae_agent.subprocess, 'run', _fake_run(copies, restarts)):
                gravae_agent._sync_direct_modules()
            self.assertEqual(copies, [])
            self.assertEqual(restarts, [])


if __name__ == '__main__':
    unittest.main()
