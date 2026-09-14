import unittest
from types import SimpleNamespace
from unittest.mock import patch
import hands_up_module as module

SHA = 'd395928b322329d4e859f9227618a2e1593f58b0'


class PinnedInstallTests(unittest.TestCase):
    def run_install(self, *, revision=SHA, fail=None, dirty=False, mismatch=False):
        calls = []
        def run(cmd, **kwargs):
            calls.append(cmd)
            out = ''
            if 'status' in cmd:
                out = ' M rasp/instalar.sh' if dirty else ''
            if 'rev-parse' in cmd:
                out = ('0' * 40 if mismatch else SHA) + '\n'
            return SimpleNamespace(returncode=int(bool(fail and fail in cmd)), stdout=out, stderr='git failed')
        with patch.object(module.os.path, 'isdir', return_value=True), patch.object(module.subprocess, 'run', side_effect=run), patch.object(module.os, 'chmod'), patch.object(module, 'status', return_value={}):
            result = module._instala_bloqueante(nuvem_url='https://worker.example', revision=revision)
        return result, calls

    def test_exact_revision_verified_before_installer(self):
        result, calls = self.run_install()
        self.assertTrue(result['ok'])
        self.assertIn(['git', '-C', module.DIR_PADRAO, 'fetch', '--depth', '1', module.REPO, SHA], calls)
        self.assertIn(['git', '-C', module.DIR_PADRAO, 'checkout', '--detach', SHA], calls)
        self.assertEqual(calls[-1], ['bash', 'instalar.sh', '--nuvem', 'https://worker.example'])

    def test_git_failures_and_dirty_checkout_never_execute(self):
        for kwargs in ({'fail': 'fetch'}, {'fail': 'checkout'}, {'fail': 'rev-parse'}, {'dirty': True}, {'mismatch': True}, {'revision': None, 'fail': 'pull'}):
            with self.subTest(kwargs=kwargs):
                result, calls = self.run_install(**kwargs)
                self.assertFalse(result['ok'])
                self.assertFalse(any(c[0] == 'bash' for c in calls))

    def test_invalid_revision_does_not_start_thread_or_git(self):
        for revision in ('main', '--upload-pack=evil', '', 'a'*39, 123):
            with self.subTest(revision=revision), patch.object(module.threading, 'Thread') as thread, patch.object(module.subprocess, 'run') as run:
                self.assertFalse(module.instala(revision=revision)['ok'])
                self.assertFalse(module._instala_bloqueante(revision=revision)['ok'])
                thread.assert_not_called()
                run.assert_not_called()

    def test_legacy_install_still_updates_branch(self):
        result, calls = self.run_install(revision=None)
        self.assertTrue(result['ok'])
        self.assertIn(['git', '-C', module.DIR_PADRAO, 'pull', '--ff-only'], calls)

    def test_async_worker_receives_revision(self):
        with patch.object(module, '_instalacao', {'estado': 'ocioso'}), patch.object(module.threading, 'Thread') as thread:
            result = module.instala(revision=SHA)
            self.assertTrue(result['iniciado'])
            self.assertEqual(result['instalacao']['revision'], SHA)
            self.assertEqual(thread.call_args.kwargs['args'][-1], SHA)


if __name__ == '__main__':
    unittest.main()
