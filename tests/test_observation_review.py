"""Correções da revisão do PR #70 (um teste por item)."""
import json
import os
import threading
import time
import unittest
from unittest.mock import Mock, patch

import observation_mode as obs
import os.path as _p
import sys as _sys
_sys.path.insert(0, _p.dirname(_p.abspath(__file__)))
from test_observation_round3 import Base as _Base, L  # noqa: E402

_REAL_SAVE = obs.save_state   # capturado antes dos patches dos testes


class Base(_Base):
    def setUp(self):
        super().setUp()
        for name, value in [('_pending_reports', []), ('_journal_backoff_until', 0.0), ('_svc_cache', {'out': []}),
                            ('_deadline', 0.0), ('_secret_cache', {'ts': 0.0, 'values': []})]:
            p = patch.object(obs, name, value); p.start(); self.addCleanup(p.stop)


class Item01Reboot(Base):
    def test_enable_resume_disable_carry_boot_offsets_cursor(self):
        obs._state.update(bootId='b1', _savedBootId='b1', pm2Offsets={'/x': 10}, journalCursor='c9',
                          journalSeq=50, lastPress={'q1': 1.0})
        with patch.object(obs.threading, 'Thread') as T:
            T.return_value.is_alive.return_value = False
            obs._thread = None
            obs.enable('k', 'https://ops', mode='semana')
        for k, v in [('bootId', 'b1'), ('pm2Offsets', {'/x': 10}), ('journalCursor', 'c9'), ('journalSeq', 50),
                     ('lastPress', {'q1': 1.0}), ('guard', True)]:
            self.assertEqual(obs._state[k], v, k)
        obs.disable()
        obs._stop.clear()
        self.assertEqual(obs._state['journalCursor'], 'c9')     # item 15
        self.assertEqual(obs._state['bootId'], 'b1')
        self.assertFalse(obs._state['enabled'])

    def test_volatile_journal_is_medium_unknown(self):
        obs._state['bootId'] = 'old'
        with patch.object(obs, '_run', return_value=(1, 'Specifying boot ID or boot offset has no effect, no persistent journal was found.')), \
             patch.object(obs, '_agent_initiated_reboot', return_value=False):
            out = obs.check_unexpected_reboot({'bootId': 'new', 'uptimeSec': 60})
        self.assertEqual(out[0]['severity'], 'medium')
        self.assertIn('motivo desconhecido', out[0]['detail'])
        self.assertIsNone(out[0]['evidence']['cleanShutdown'])
        self.assertFalse(out[0]['evidence']['journalPersistent'])

    def test_phoenix_initiated_reboot_not_reported(self):
        now = time.time()
        path = os.path.join(self.tmp, 'reboot_state.json')
        from datetime import datetime
        json.dump({'timestamps': [datetime.fromtimestamp(now - 300).isoformat()]}, open(path, 'w'))
        with patch.object(obs, 'PHOENIX_REBOOT_STATE', path), \
             patch.object(obs, 'EXPECTED_REBOOT_MARKER', os.path.join(self.tmp, 'none')):
            self.assertTrue(obs._agent_initiated_reboot(uptime_sec=200, now=now))
            self.assertFalse(obs._agent_initiated_reboot(uptime_sec=86400, now=now))
            obs._state['bootId'] = 'old'
            with patch.object(obs, '_run') as run:
                self.assertEqual(obs.check_unexpected_reboot({'bootId': 'new', 'uptimeSec': 200}), [])
            run.assert_not_called()

    def test_expected_reboot_marker_consumed(self):
        marker = os.path.join(self.tmp, 'expected-reboot')
        open(marker, 'w').close()
        t = time.time() - 400
        os.utime(marker, (t, t))
        with patch.object(obs, 'EXPECTED_REBOOT_MARKER', marker), \
             patch.object(obs, 'PHOENIX_REBOOT_STATE', os.path.join(self.tmp, 'none')):
            self.assertTrue(obs._agent_initiated_reboot(uptime_sec=300))
        self.assertFalse(os.path.exists(marker))


class Item02Targeting(Base):
    def test_stream_mid_only_for_live_stream(self):
        live = ['ffmpeg', '-i', 'rtsp://cam/x', '/dev/shm/streams/GK1/quadra01_camera01/s.m3u8']
        rec = ['ffmpeg', '-i', 'rtsp://cam', '/home/Shinobi/videos/GK1/quadra01_camera01/2026.mp4']
        self.assertEqual(obs.stream_mid(live, 'GK1'), 'quadra01_camera01')
        self.assertIsNone(obs.stream_mid(live, 'OTHER'))
        self.assertIsNone(obs.stream_mid(rec, 'GK1'))
        self.assertIsNone(obs.stream_mid(['ffmpeg', '-f', 'flv', 'rtmp://x'], None))

    def test_pid_info_requires_shinobi_parent(self):
        files = {'/proc/7/comm': 'ffmpeg\n', '/proc/7/status': 'VmRSS:\t512000 kB\n'}

        def fake_open(path, mode='r', *a, **k):
            import io
            if path in files:
                return io.StringIO(files[path])
            raise OSError(path)

        argv = ['ffmpeg', '/dev/shm/streams/GK1/m1/s.m3u8']
        with patch('builtins.open', side_effect=fake_open), patch.object(obs, '_cmdline', return_value=argv), \
             patch.object(obs, '_under_shinobi', return_value=True):
            self.assertEqual(obs._pid_info(7, 'GK1'), {'pid': 7, 'rssMb': 500, 'monitor': 'm1'})
        with patch('builtins.open', side_effect=fake_open), patch.object(obs, '_cmdline', return_value=argv), \
             patch.object(obs, '_under_shinobi', return_value=False):
            self.assertIsNone(obs._pid_info(7, 'GK1'))       # ffmpeg do agent/device-client

    def test_under_shinobi_walks_parents(self):
        parents = {50: 40, 40: 30, 30: 1}
        cmds = {40: ['/bin/sh', '-c', 'ffmpeg'], 30: ['node', '/home/Shinobi/libs/singleCamera.js']}
        with patch.object(obs, '_read_ppid', side_effect=lambda p: parents.get(p)), \
             patch.object(obs, '_cmdline', side_effect=lambda p: cmds.get(p, [])):
            self.assertTrue(obs._under_shinobi(50))
        cmds[30] = ['python3', '/opt/gravae-device-client/direct_publisher.py']
        with patch.object(obs, '_read_ppid', side_effect=lambda p: parents.get(p)), \
             patch.object(obs, '_cmdline', side_effect=lambda p: cmds.get(p, [])):
            self.assertFalse(obs._under_shinobi(50))

    def test_device_wide_cooldown_no_chain(self):
        obs._state['autoheal'] = True
        a = {'pid': 1, 'rssMb': 600, 'monitor': 'mA'}
        b = {'pid': 2, 'rssMb': 600, 'monitor': 'mB'}
        with patch.object(obs, '_kill_pid', return_value=True) as kill, patch.object(obs.time, 'sleep'), \
             patch.object(obs, '_meminfo_mb', return_value=(300, 900)):
            self.assertEqual(obs.guard_act(a, 90, 900, now=1000.0), 'killed')
            self.assertEqual(obs.guard_act(b, 90, 900, now=1010.0), 'verifying')
        kill.assert_called_once_with(1)

    def test_no_monitor_no_target_and_dicts_pruned(self):
        self.assertEqual(obs.guard_act({'pid': 3, 'rssMb': 900, 'monitor': None}, 50, 900), 'no_target')
        obs._guard['lastKill'] = {'old': 0.0, 'new': 9000.0}
        obs._guard['recurReported'] = {'old': 0.0}
        obs._guard['kills'] = {'old': [0.0], 'new': [9000.0]}
        obs._prune_guard(10000.0)
        self.assertEqual(obs._guard['lastKill'], {'new': 9000.0})
        self.assertEqual(obs._guard['recurReported'], {})
        self.assertEqual(obs._guard['kills'], {'new': [9000.0]})


class Item03SingleActor(Base):
    def test_cycle_never_kills_only_flags(self):
        with patch.object(obs, '_meminfo_mb', return_value=(60, 900)), \
             patch.object(obs, '_ffmpeg_rss_mb', return_value=[{'pid': 5, 'rssMb': 700, 'monitor': 'm1'}]), \
             patch.object(obs, 'guard_act') as act, patch.object(obs, '_kill_pid') as kill:
            obs.check_memory_pressure()
        act.assert_not_called(); kill.assert_not_called()
        self.assertTrue(obs._guard['watch'])


class Item04GuardUnderPressure(Base):
    def test_guard_rescans_proc_itself(self):
        obs._guard['pids'] = [999]    # lista velha do ciclo
        with patch.object(obs, '_meminfo_mb', return_value=(100, 900)), \
             patch.object(obs, '_scan_ffmpeg_pids', return_value=[11]) as scan, \
             patch.object(obs, '_shinobi_creds', return_value=('k', 'GK1')), \
             patch.object(obs, '_pid_info', side_effect=lambda pid, gk=None: {'pid': pid, 'rssMb': 120, 'monitor': 'm1'}) as info, \
             patch.object(obs, '_top_rss_is_ffmpeg', return_value=False):
            self.assertEqual(obs.guard_tick(), 'warn')
        scan.assert_called_once()
        self.assertEqual([c.args[0] for c in info.call_args_list], [11])

    def test_watch_flag_makes_guard_look_with_free_ram(self):
        obs._guard['watch'] = True
        with patch.object(obs, '_meminfo_mb', return_value=(3000, 3800)), \
             patch.object(obs, '_current_ffmpeg', return_value=[{'pid': 4, 'rssMb': 1400, 'monitor': 'm1'}]), \
             patch.object(obs, 'guard_act', return_value='killed') as act:
            self.assertEqual(obs.guard_tick(), 'killed')
        act.assert_called_once()

    def test_recurring_kills_before_querying_config(self):
        obs._state['autoheal'] = True
        order = []
        obs._guard['kills'] = {'m1': [100.0, 800.0, 1500.0]}
        with patch.object(obs, '_kill_pid', side_effect=lambda pid: order.append('kill')), \
             patch.object(obs, '_leak_config', side_effect=lambda m: order.append('config')), \
             patch.object(obs.time, 'sleep'), patch.object(obs, '_meminfo_mb', return_value=(400, 900)):
            res = obs.guard_act({'pid': 9, 'rssMb': 600, 'monitor': 'm1'}, 80, 900, now=2300.0)
        self.assertEqual(res, 'killed_recurring')
        self.assertEqual(order, ['kill', 'config'])


class Item05Backoff(Base):
    def test_relative_backoff(self):
        with patch.object(obs.os, 'cpu_count', return_value=4):
            _, skipped = obs._tiers({'load1': 0.5, 'memAvailMb': 150, 'memTotalMb': 900})
            self.assertEqual(skipped, 0)                    # 150 > 12% de 900
            tiers, skipped = obs._tiers({'load1': 0.5, 'memAvailMb': 100, 'memTotalMb': 900})
            self.assertGreater(skipped, 0)
            self.assertFalse(any(tiers.values()))
            _, skipped = obs._tiers({'load1': 0.5, 'memAvailMb': 400, 'memTotalMb': 3800})
            self.assertGreater(skipped, 0)                  # 400 < 456 num Pi de 4 GB


class Item06Duplicate(Base):
    def test_camera_js_by_cmdline_not_comm(self):
        procs = [{'pid': 1, 'comm': 'camera', 'argv': ['node', '/home/Shinobi/camera.js'], 'uid': 0, 'cwd': '/home/Shinobi'},
                 {'pid': 2, 'comm': 'PM2 v5.3', 'argv': ['/usr/bin/node', 'camera.js'], 'uid': 1000, 'cwd': '/opt/x'},
                 {'pid': 3, 'comm': 'node', 'argv': ['node', '/home/Shinobi/libs/singleCamera.js'], 'uid': 0},
                 {'pid': 4, 'comm': 'node', 'argv': ['node', '/home/Shinobi/cron.js'], 'uid': 0}]
        with patch.object(obs, '_proc_list', return_value=procs):
            self.assertEqual([p['pid'] for p in obs._camera_js_procs()], [1, 2])


class Item07Network(Base):
    def test_icmp_blocked_internet_but_heartbeat_ok(self):
        for _ in range(3):
            obs._net.update(result=('gw', {'gw': (0.0, 1.0), 'net': (100.0, None)}), fresh=True)
            out = obs.check_network_degraded(hb_ok=True)
        self.assertEqual(out, [])

    def test_gateway_that_never_answers_is_ignored(self):
        for _ in range(3):
            obs._net.update(result=('gw', {'gw': (100.0, None), 'net': (0.0, 30.0)}), fresh=True)
            out = obs.check_network_degraded(hb_ok=True)
        self.assertEqual(out, [])
        obs._local_seen.clear()
        obs._net['gwEverAnswered'] = True
        for _ in range(3):
            obs._net.update(result=('gw', {'gw': (100.0, None), 'net': (0.0, 30.0)}), fresh=True)
            out = obs.check_network_degraded(hb_ok=True)
        self.assertEqual(out[0]['type'], 'network_degraded')

    def test_tcp_probe(self):
        ok = Mock(); ok.__enter__ = Mock(return_value=ok); ok.__exit__ = Mock(return_value=False)
        with patch.object(obs.socket, 'create_connection', side_effect=[ok, OSError(), ok]):
            loss, ms = obs.tcp_probe()
        self.assertAlmostEqual(loss, 33.33, places=1)
        self.assertIsNotNone(ms)


class Item08Secrets(Base):
    def test_redaction_patterns_and_device_values(self):
        obs._secret_cache.update(ts=1e18, values=['GKSECRET99', 'APIKEY1234567'])
        line = ('[HTTP] 2026-11-09 10:00:00 q1 -> 200 mas RECUSADO http://localhost:8080/APIKEY1234567/motion/GKSECRET99/m1 '
                '?key=abc auth_token=xyz Bearer eyJhb.c password=hunter2 MYSQL_PWD=x {"password": "p"}')
        r = obs.redact(line)
        for leaked in ['APIKEY1234567', 'GKSECRET99', 'abc', 'xyz', 'eyJhb', 'hunter2', 'MYSQL_PWD=x', '"p"']:
            self.assertNotIn(leaked, r)
        self.assertIn('/***/motion/***/m1', r)

    def test_journal_and_evidence_are_redacted(self):
        obs._secret_cache.update(ts=1e18, values=['GKSECRET99'])
        e = {'__CURSOR': 'c', '__REALTIME_TIMESTAMP': '1', 'PRIORITY': '3', 'MESSAGE': 'fail GKSECRET99 token=abc',
             '_SYSTEMD_UNIT': 'gravae-buttons.service'}
        keep, _, _ = obs.parse_journal(json.dumps(e))
        self.assertNotIn('GKSECRET99', keep[0]['m']); self.assertNotIn('abc', keep[0]['m'])
        os.makedirs(obs.PM2_LOG_DIR)
        path = os.path.join(obs.PM2_LOG_DIR, 'camera-out.log')
        open(path, 'w').write('x\n')
        obs.check_shinobi_log_errors()
        with open(path, 'a') as fh:
            fh.write('Not Authorized http://localhost:8080/ABCDEFGHIJKLMNOP/monitor/GKSECRET99\n')
        out = obs.check_shinobi_log_errors()
        self.assertNotIn('ABCDEFGHIJKLMNOP', json.dumps(out)); self.assertNotIn('GKSECRET99', json.dumps(out))


class Item09GuardSurvivesDisable(Base):
    def test_disable_does_not_stop_guard_and_resume_starts_it(self):
        obs._state.update(enabled=True, guard=True, autoheal=False)
        obs.disable()
        obs._stop.clear()
        self.assertFalse(obs._guard_stop.is_set())
        self.assertFalse(obs._state['autoheal'])          # política do piloto preservada
        with patch.object(obs, 'load_state'), patch.object(obs, '_start_guard') as sg, patch.object(obs, 'enable') as en:
            obs.resume_if_enabled()
        sg.assert_called_once()
        en.assert_not_called()


class Item10LastPress(Base):
    def test_cleanup(self):
        now = time.time()
        obs._state['lastPress'] = {'q1_camera01': now - 100, 'gone_camera09': now - 100, 'q2_camera01': now - 8 * 86400}
        with patch.object(obs, '_local_get', return_value={'monitors': [{'mid': 'm1', 'name': 'q1_camera01'},
                                                                         {'mid': 'm2', 'name': 'q2_camera01'}]}):
            self.assertTrue(obs._cleanup_last_press(now))
        self.assertEqual(list(obs._state['lastPress']), ['q1_camera01'])
        with patch.object(obs, '_local_get', return_value=None):   # sem lista de monitores: só idade
            obs._state['lastPress'] = {'x': now}
            self.assertFalse(obs._cleanup_last_press(now))


class Item11SaveState(Base):
    def test_concurrent_saves_keep_valid_file(self):
        path = os.path.join(self.tmp, 'obs.json')
        with patch.object(obs, 'STATE_PATH', path):
            obs._state.update(a=1)
            ts = [threading.Thread(target=_REAL_SAVE) for _ in range(8)]
            [t.start() for t in ts]
            [t.join() for t in ts]
            self.assertEqual(json.load(open(path))['a'], 1)
            self.assertEqual([f for f in os.listdir(self.tmp) if '.tmp.' in f], [])


class Item12Upload(Base):
    def test_direct_mode_ignores_db_status_and_record_excluded(self):
        mm = os.path.join(self.tmp, 'media-mode.json')
        json.dump({'mode': 'DIRECT'}, open(mm, 'w'))
        with patch.object(obs, 'MEDIA_MODE_FILES', (mm,)), patch.object(obs, '_shinobi_creds', return_value=('k', 'GK1')), \
             patch.object(obs, '_local_get', return_value={'monitors': []}), patch.object(obs, '_mysql') as sql:
            obs.check_upload_stuck(run=True)
        sql.assert_not_called()
        d = os.path.join(obs.VIDEO_DIRS[0], 'GK1', 'rec_camera01')
        os.makedirs(d)
        for i in range(3):
            f = os.path.join(d, '%d.mp4' % i); open(f, 'wb').write(b'x'); os.utime(f, (time.time() - 7200,) * 2)
        mons = {'monitors': [{'mid': 'rec_camera01', 'name': 'rec_camera01', 'mode': 'record'}]}
        with patch.object(obs, 'MEDIA_MODE_FILES', ()), patch.object(obs, '_shinobi_creds', return_value=('k', 'GK1')), \
             patch.object(obs, '_local_get', return_value=mons), \
             patch.object(obs, '_mysql', return_value=[['rec_camera01', 't', '50'], ['rec_camera01', 't', '40']]):
            self.assertEqual(obs.check_upload_stuck(run=True), [])


class Item13Deadline(Base):
    def test_reports_spill_to_next_cycle(self):
        found = [{'dedupKey': 'a:1'}, {'dedupKey': 'b:1'}, {'dedupKey': 'c:1'}]
        sent = []
        with patch.object(obs, '_post', side_effect=lambda path, a, *x, **k: sent.append(a['dedupKey'])):
            obs._deadline = time.time() + 1.5      # sem tempo
            self.assertEqual(obs._send_reports(found, 's', 'k', 'o', True), 0)
            self.assertEqual(len(obs._pending_reports), 3)
            obs._deadline = time.time() + 30
            self.assertEqual(obs._send_reports([{'dedupKey': 'a:1'}], 's', 'k', 'o', True), 3)
        obs._deadline = 0.0
        self.assertEqual(sent, ['a:1', 'b:1', 'c:1'])
        self.assertEqual(obs._pending_reports, [])

    def test_local_timeouts_bounded_by_deadline(self):
        obs._deadline = time.time() + 3
        self.assertLessEqual(obs._remaining(8), 3)
        obs._deadline = 0.0
        self.assertEqual(obs._remaining(8), 8)


class Item14JournalBackoff(Base):
    def test_404_backs_off(self):
        obs.spool_write([{'seq': 1, 'lines': []}])
        with patch.object(obs, '_post_status', return_value=(404, None)) as post:
            obs.ship_journal([{'seq': 2, 'lines': []}], 's', 'k', 'o', time.time() + 30)
            self.assertEqual(post.call_count, 1)
            with patch.object(obs, 'spool_read') as rd:
                obs.ship_journal([{'seq': 3, 'lines': []}], 's', 'k', 'o', time.time() + 30)
                rd.assert_not_called()
            self.assertEqual(post.call_count, 1)
        self.assertEqual(len(obs._spool_files()), 3)
        obs._journal_backoff_until = 0.0


if __name__ == '__main__':
    unittest.main()
