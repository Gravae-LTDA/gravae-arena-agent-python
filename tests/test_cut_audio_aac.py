"""Patch do audio do corte SIP (AC3 no mp4 nao toca no app) -- carrega so o helper."""
import ast
import re
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'gravae_agent.py'

# Linha real do Shinobi recente (libs/events/utils.js, runRecord)
NEW_SHINOBI = (
    "const ffmpegCommand = `-threads 1 -loglevel warning -i \"x\" ${outputMap}-movflags faststart "
    "-c:v copy ${noAudio ? '-an' : autoAudio ? '' : `-c:a ${audioCodec}`} -strict -2 -y \"out\"`"
)
OLD_SHINOBI = NEW_SHINOBI.replace('`-c:a ${audioCodec}`', '`-c:a aac`')


class CutAudioAac(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(SOURCE.read_text())
        keep = [n for n in tree.body
                if (isinstance(n, ast.Assign) and any(getattr(t, 'id', '') == '_CUT_AUDIO_CODEC_RE' for t in n.targets))
                or (isinstance(n, ast.FunctionDef) and n.name == '_patch_cut_audio_aac')]
        self.scope = {'re': re}
        exec(compile(ast.Module(body=keep, type_ignores=[]), str(SOURCE), 'exec'), self.scope)

    def test_patches_buffer_codec_to_aac(self):
        out = self.scope['_patch_cut_audio_aac'](NEW_SHINOBI)
        self.assertEqual(out, OLD_SHINOBI)
        self.assertNotIn('${audioCodec}`', out)
        self.assertIn("noAudio ? '-an'", out)  # -an pra camera sem audio continua

    def test_noop_when_already_aac(self):
        self.assertIsNone(self.scope['_patch_cut_audio_aac'](OLD_SHINOBI))

    def test_idempotent(self):
        once = self.scope['_patch_cut_audio_aac'](NEW_SHINOBI)
        self.assertIsNone(self.scope['_patch_cut_audio_aac'](once))


if __name__ == '__main__':
    unittest.main()
