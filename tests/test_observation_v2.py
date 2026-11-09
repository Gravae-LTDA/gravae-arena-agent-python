import json
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import observation_mode as obs


class Base(unittest.TestCase):
    def setUp(self):
        for name, value in [('_state', {}), ('_thread', Mock()), ('_consecutive', {}),
                            ('_local_seen', {}), ('_prev_throttled', None), ('_hb_401', 0),
                            ('_kernel_lines', [])]:
            p = patch.object(obs, name, value); p.start(); self.addCleanup(p.stop)
        for name in ['save_state', '_log']:
            p = patch.object(obs, name); p.start(); self.addCleanup(p.stop)
        self.spool = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.spool, True)
        p = patch.object(obs, 'SPOOL_DIR', self.spool); p.start(); self.addCleanup(p.stop)


class Snapshot(Base):
    def test_parse_throttled(self):
        self.assertEqual(obs.parse_throttled('throttled=0x50005\n'), 0x50005)
        self.assertEqual(obs.parse_throttled('throttled=0x0'), 0)
        self.assertIsNone(obs.parse_throttled(''))
        self.assertIsNone(obs.parse_throttled('VCHI initialization failed'))

    def test_rootfs_readonly_uses_last_root_entry(self):
        rw = "/dev/root / ext4 rw,noatime 0 0\n"
        self.assertFalse(obs._rootfs_readonly(rw))
        self.assertTrue(obs._rootfs_readonly(rw + "/dev/root / ext4 ro,noatime 0 0\n"))
        self.assertIsNone(obs._rootfs_readonly("tmpfs /run tmpfs rw 0 0\n"))

    def test_snapshot_has_contract_fields(self):
        with patch.object(obs, '_run', return_value=(0, 'throttled=0x50005')), \
             patch.object(obs, '_unit_active', return_value=None), \
             patch.object(obs, '_dns_ok', return_value=True), \
             patch.object(obs, '_ntp_synced', return_value=True):
            snap = obs.build_snapshot()
        for k in ['tempC', 'throttled', 'undervoltageNow', 'memAvailMb', 'memTotalMb', 'diskFreeMb',
                  'diskFreePct', 'rootfsReadOnly', 'load1', 'uptimeSec', 'ntpSynced', 'dnsOk',
                  'cloudflaredActive', 'mariadbActive', 'buttonsActive', 'spoolChunks']:
            self.assertIn(k, snap)
        self.assertEqual(snap['throttled'], '0x50005')
        self.assertTrue(snap['undervoltageNow'])
        self.assertEqual(snap['spoolChunks'], 0)


class Checks(Base):
    def test_undervoltage_now_and_since_boot_transition(self):
        self.assertEqual(obs.check_undervoltage({'throttled': '0x50005'})[0]['dedupKey'], 'undervoltage')
        obs._prev_throttled = None
        # bootou já com o bit 16: não sabe quando foi -> não reporta
        self.assertEqual(obs.check_undervoltage({'throttled': '0x50000'}), [])
        obs._prev_throttled = 0
        out = obs.check_undervoltage({'throttled': '0x50000'})
        self.assertEqual(out[0]['type'], 'undervoltage')
        self.assertTrue(out[0]['dedupKey'].startswith('undervoltage_event:'))
        self.assertEqual(obs.check_undervoltage({'throttled': '0x50000'}), [])
        self.assertEqual(obs.check_undervoltage({'throttled': None}), [])

    def test_temperature_needs_two_cycles(self):
        self.assertEqual(obs.check_high_temperature({'tempC': 82}), [])
        self.assertEqual(obs.check_high_temperature({'tempC': 82})[0]['severity'], 'high')
        obs._local_seen.clear()
        obs.check_high_temperature({'tempC': 76})
        self.assertEqual(obs.check_high_temperature({'tempC': 76})[0]['severity'], 'medium')
        self.assertEqual(obs.check_high_temperature({'tempC': 60}), [])

    def test_disk_full_thresholds(self):
        self.assertEqual(obs.check_disk_full({'diskFreePct': 30, 'diskFreeMb': 8000}), [])
        self.assertEqual(obs.check_disk_full({'diskFreePct': 8, 'diskFreeMb': 2000})[0]['severity'], 'medium')
        self.assertEqual(obs.check_disk_full({'diskFreePct': 4, 'diskFreeMb': 2000})[0]['severity'], 'high')
        self.assertEqual(obs.check_disk_full({'diskFreePct': 20, 'diskFreeMb': 400})[0]['severity'], 'high')
        self.assertEqual(obs.check_disk_full({}), [])

    def test_sd_readonly(self):
        self.assertEqual(obs.check_sd_readonly({'rootfsReadOnly': True})[0]['severity'], 'critical')
        self.assertEqual(obs.check_sd_readonly({'rootfsReadOnly': None}), [])

    def test_kernel_one_shots(self):
        obs._kernel_lines = [
            {'m': 'mmc0: card stuck in programming state! mmc_do_erase'},
            {'m': 'Out of memory: Killed process 1234 (ffmpeg)'},
            {'m': 'usb 1-1.3: new high-speed USB device'},
        ]
        sd = obs.check_sd_errors()
        self.assertEqual(sd[0]['type'], 'sd_errors')
        self.assertEqual(sd[0]['evidence']['lines'], ['mmc0: card stuck in programming state! mmc_do_erase'])
        self.assertTrue(sd[0]['dedupKey'].startswith('sd_errors:'))
        self.assertEqual(obs.check_oom_kill()[0]['type'], 'oom_kill')
        obs._kernel_lines = [{'m': 'usb 1-1.3: new high-speed USB device'}]
        self.assertEqual(obs.check_sd_errors() + obs.check_oom_kill(), [])

    def test_clock_unsynced_has_boot_grace_and_confirmation(self):
        snap = {'ntpSynced': False, 'uptimeSec': 60}
        for _ in range(5):
            self.assertEqual(obs.check_clock_unsynced(snap), [])
        snap['uptimeSec'] = 3600
        results = [obs.check_clock_unsynced(snap) for _ in range(4)]
        self.assertEqual(results[:3], [[], [], []])
        self.assertEqual(results[3][0]['type'], 'clock_unsynced')

    def test_service_units_only_when_installed_and_confirmed(self):
        for fn, field, t in [(obs.check_tunnel_down, 'cloudflaredActive', 'tunnel_down'),
                             (obs.check_database_down, 'mariadbActive', 'database_down'),
                             (obs.check_buttons_service_down, 'buttonsActive', 'buttons_service_down'),
                             (obs.check_dns_failure, 'dnsOk', 'dns_failure')]:
            self.assertEqual(fn({field: None}), [])
            self.assertEqual(fn({field: False}), [])
            self.assertEqual(fn({field: False})[0]['type'], t)
            self.assertEqual(fn({field: True}), [])

    def test_monitor_died_ignores_single_restart_blip(self):
        died = {'monitors': [{'mid': 'm1', 'name': 'quadra01_camera01', 'mode': 'start', 'status': 'died'}]}
        ok = {'monitors': [{'mid': 'm1', 'name': 'quadra01_camera01', 'mode': 'start', 'status': 'watching'}]}
        with patch.object(obs, '_local_get', side_effect=[died, ok, died, died]):
            self.assertEqual(obs.check_monitor_died(), [])
            self.assertEqual(obs.check_monitor_died(), [])
            self.assertEqual(obs.check_monitor_died(), [])
            self.assertEqual(obs.check_monitor_died()[0]['dedupKey'], 'monitor_died:m1')

    def test_service_down_reprobes(self):
        down = {'services': {'camera': False, 'buttons': True}}
        up = {'services': {'camera': True, 'buttons': True}}
        with patch.object(obs.time, 'sleep'), patch.object(obs, '_local_get', side_effect=[down, up]):
            self.assertEqual(obs.check_service_down(), [])
        with patch.object(obs.time, 'sleep'), patch.object(obs, '_local_get', side_effect=[down, down]):
            self.assertEqual(obs.check_service_down()[0]['dedupKey'], 'service_down:camera')

    def test_shinobi_port_reprobes(self):
        with patch.object(obs.time, 'sleep'), patch.object(obs, '_shinobi_port_ok', side_effect=[False, True]):
            self.assertEqual(obs.check_shinobi_8080(), [])
        with patch.object(obs.time, 'sleep'), patch.object(obs, '_shinobi_port_ok', side_effect=[False, False]):
            self.assertEqual(obs.check_shinobi_8080()[0]['type'], 'shinobi_port_dead')

    def test_memory_needs_two_cycles(self):
        with patch.object(obs, '_meminfo_mb', return_value=(200, 900)), \
             patch.object(obs, '_ffmpeg_rss_mb', return_value=[{'pid': 1, 'rssMb': 950, 'monitor': 'q1_camera01'}]):
            self.assertEqual(obs.check_memory_pressure(), [])
            types = sorted(a['type'] for a in obs.check_memory_pressure())
        self.assertEqual(types, ['ffmpeg_memory_leak', 'high_memory'])


class Journal(Base):
    def _entry(self, unit, prio, msg, ts=1_700_000_000.0, cursor='c', transport='journal'):
        e = {'__CURSOR': cursor, '__REALTIME_TIMESTAMP': str(int(ts * 1e6)), 'PRIORITY': str(prio),
             'MESSAGE': msg, '_TRANSPORT': transport}
        if unit:
            e['_SYSTEMD_UNIT'] = unit + '.service'
        return json.dumps(e)

    def test_parse_filters_units_kernel_and_errors(self):
        out = '\n'.join([
            self._entry('gravae-buttons', 6, '[PRESS] x', cursor='c1'),
            self._entry('random', 6, 'noise', cursor='c2'),
            self._entry('random', 3, 'boom', cursor='c3'),
            self._entry(None, 6, 'kernel info', cursor='c4', transport='kernel'),
            self._entry(None, 4, 'mmc0: error', cursor='c5', transport='kernel'),
            self._entry('gravae-agent', 6, 'x' * 900, cursor='c6'),
        ])
        keep, kernel, cursor = obs.parse_journal(out)
        self.assertEqual([l['m'][:9] for l in keep], ['[PRESS] x', 'boom', 'mmc0: err', 'x' * 9])
        self.assertEqual(len(kernel), 2)
        self.assertEqual(cursor, 'c6')
        self.assertEqual(len(keep[-1]['m']), obs.MSG_MAX_CHARS)
        self.assertEqual(keep[0]['u'], 'gravae-buttons')

    def test_chunks_are_split_and_seq_is_monotonic(self):
        obs._state['journalSeq'] = 41
        lines = [{'t': 1_700_000_000.0 + i, 'u': 'kernel', 'p': 3, 'm': str(i)} for i in range(650)]
        chunks = obs.make_chunks(lines)
        self.assertEqual([c['seq'] for c in chunks], [42, 43, 44])
        self.assertEqual([len(c['lines']) for c in chunks], [300, 300, 50])
        self.assertEqual(obs._state['journalSeq'], 44)
        self.assertTrue(chunks[0]['from'].startswith('2023-11-14T22:13:20'))

    def test_offline_spools_then_flushes_and_prunes_by_accepted_seq(self):
        chunks = obs.make_chunks([{'t': 1.0, 'u': 'kernel', 'p': 3, 'm': 'a'}] * 3)
        obs.ship_journal(chunks, 's', 'k', 'https://ops', time.time() + 30, online=False)
        self.assertEqual(len(obs._spool_files()), 1)
        more = obs.make_chunks([{'t': 2.0, 'u': 'kernel', 'p': 3, 'm': 'b'}])
        sent = []

        def fake_post(path, body, *a, **k):
            sent.append([c['seq'] for c in body['chunks']])
            return 200, {'ok': True, 'acceptedSeq': body['chunks'][-1]['seq']}

        with patch.object(obs, '_post_status', side_effect=fake_post):
            self.assertTrue(obs.ship_journal(more, 's', 'k', 'https://ops', time.time() + 30))
        self.assertEqual(sent, [[1, 2]])   # spool mais antigo primeiro
        self.assertEqual(obs._spool_files(), [])

    def test_failed_post_keeps_new_chunks_in_spool(self):
        chunks = obs.make_chunks([{'t': 1.0, 'u': 'kernel', 'p': 3, 'm': 'a'}])
        with patch.object(obs, '_post_status', return_value=(None, None)):
            self.assertFalse(obs.ship_journal(chunks, 's', 'k', 'https://ops', time.time() + 30))
        self.assertEqual(obs._spool_files(), ['%012d.json' % 1])

    def test_spool_ring_drops_oldest(self):
        with patch.object(obs, 'SPOOL_MAX_BYTES', 3000):
            for i in range(10):
                obs.spool_write([{'seq': i + 1, 'lines': [{'m': 'x' * 900}]}])
        files = obs._spool_files()
        self.assertLess(len(files), 10)
        self.assertEqual(files[-1], '%012d.json' % 10)
        total = sum(os.path.getsize(os.path.join(self.spool, f)) for f in files)
        self.assertLessEqual(total, 3000)

    def test_batch_respects_count_and_size(self):
        chunks = [{'seq': i, 'lines': []} for i in range(25)]
        self.assertEqual(len(obs._batch(chunks)), obs.POST_MAX_CHUNKS)
        big = [{'seq': i, 'lines': [{'m': 'x' * 200_000}]} for i in range(3)]
        self.assertEqual(len(obs._batch(big)), 1)


class Lifecycle(Base):
    def _cycle_with(self, hb_code):
        obs._state.update(enabled=True, secret='k', opsUrl='https://ops.test', autoheal=False)
        with patch.object(obs, 'build_snapshot', return_value={}), \
             patch.object(obs, 'collect_journal', return_value=([], [])), \
             patch.object(obs, '_recent_presses', return_value={}), \
             patch.object(obs, 'ship_journal'), \
             patch.object(obs, 'get_serial', return_value='pi'), \
             patch.object(obs, '_post_status', return_value=(hb_code, None)) as hb, \
             patch.object(obs, '_post'):
            for name in ['check_service_down', 'check_shinobi_8080', 'check_monitor_died',
                         'check_camera_frozen', 'check_memory_pressure']:
                p = patch.object(obs, name, return_value=[]); p.start(); self.addCleanup(p.stop)
            obs._cycle()
        return hb

    def test_heartbeat_carries_snapshot_and_short_timeout(self):
        hb = self._cycle_with(200)
        path, body = hb.call_args.args[:2]
        self.assertEqual(path, '/api/observation/heartbeat')
        self.assertEqual(body['obsVersion'], '2.0.0')
        self.assertIn('snapshot', body)
        self.assertEqual(hb.call_args.kwargs, {'timeout': obs.HB_TIMEOUT, 'attempts': 2})

    def test_ten_consecutive_401_disable_locally(self):
        with patch.object(obs, 'disable') as dis:
            for _ in range(9):
                self._cycle_with(401)
            dis.assert_not_called()
            self._cycle_with(401)
            dis.assert_called_once()

    def test_401_counter_resets_on_success(self):
        with patch.object(obs, 'disable') as dis:
            for _ in range(9):
                self._cycle_with(401)
            self._cycle_with(200)
            for _ in range(9):
                self._cycle_with(401)
            dis.assert_not_called()

    def test_fixed_mode_runs_without_until(self):
        with patch.object(obs.threading, 'Thread') as T:
            T.return_value.is_alive.return_value = False
            obs._thread = None
            obs.enable('k', 'https://ops.test', until=None, mode='fixo')
        st = obs.status()
        self.assertEqual(st['mode'], 'fixo')
        self.assertIsNone(st['until'])
        self.assertTrue(st['supportsJournal'])
        self.assertEqual(st['obsVersion'], '2.0.0')
        self.assertNotIn('secret', st)
        calls = []

        def cycle():
            calls.append(1)
            if len(calls) == 3:
                obs._stop.set()

        obs._stop.clear()
        with patch.object(obs, '_cycle', side_effect=cycle), patch.object(obs._stop, 'wait'):
            obs._loop()
        self.assertEqual(len(calls), 3)
        self.assertTrue(obs._state['enabled'])

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            obs.enable('k', 'https://ops.test', mode='sempre')

    def test_resume_preserves_mode_and_seq_survives_disable(self):
        obs._state.update(enabled=True, secret='k', opsUrl='https://ops.test', mode='fixo', journalSeq=7)
        with patch.object(obs, 'load_state'), patch.object(obs, 'enable') as en:
            obs.resume_if_enabled()
        self.assertEqual(en.call_args.kwargs['mode'], 'fixo')
        obs.disable()
        self.assertEqual(obs._state['journalSeq'], 7)
        obs._stop.clear()


if __name__ == '__main__':
    unittest.main()
