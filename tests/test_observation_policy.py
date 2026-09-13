import unittest
from unittest.mock import Mock, patch
import observation_mode as obs


class ObservationPolicy(unittest.TestCase):
    def setUp(self):
        for name, value in [('_state', {}), ('_thread', Mock()), ('_consecutive', {})]:
            p = patch.object(obs, name, value); p.start(); self.addCleanup(p.stop)
        for name in ['save_state', '_log']:
            p = patch.object(obs, name); p.start(); self.addCleanup(p.stop)

    def test_legacy_default_stays_compatible_and_explicit_false_persists(self):
        obs.enable('secret', 'https://ops.test')
        self.assertTrue(obs.status()['autohealEnabled'])
        obs.enable('secret', 'https://ops.test', autoheal=False)
        self.assertFalse(obs.status()['autohealEnabled'])
        self.assertFalse(obs._state['autoheal'])
        self.assertTrue(obs.status()['supportsAutohealPolicy'])
        self.assertNotIn('secret', obs.status())

    def test_resume_preserves_the_disabled_recovery_policy(self):
        obs._state.update(enabled=True, secret='secret', opsUrl='https://ops.test', autoheal=False)
        with patch.object(obs, 'load_state'), patch.object(obs, 'enable') as enable:
            self.assertTrue(obs.resume_if_enabled())
            self.assertIs(enable.call_args.args[-1], False)

    def test_observation_checks_continue_without_invoking_restarts(self):
        obs._state.update(enabled=True, secret='secret', opsUrl='https://ops.test', autoheal=False)
        names = ['check_service_down', 'check_shinobi_8080', 'check_press_without_video',
                 'check_monitor_died', 'check_camera_frozen', 'check_gpio_stuck',
                 'check_gpio_idle_24h', 'check_memory_pressure']
        for name in names:
            p = patch.object(obs, name, return_value=[]); p.start(); self.addCleanup(p.stop)
        with patch.object(obs, 'get_serial', return_value='pilot'), patch.object(obs, '_recent_presses', return_value={}), patch.object(obs, '_post') as post, patch.object(obs, '_maybe_autoheal') as heal:
            obs._cycle()
            post.assert_called_once()
            heal.assert_not_called()
            obs._state['autoheal'] = True
            obs._cycle()
            heal.assert_called_once()

    def test_string_false_is_not_treated_as_permission_to_restart(self):
        with self.assertRaises(ValueError):
            obs.enable('secret', 'https://ops.test', autoheal='false')
        self.assertFalse(obs._state)
