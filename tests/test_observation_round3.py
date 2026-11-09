import json
import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import observation_mode as obs


def L(unit, msg, t=None, p=6):
    return {'t': t or time.time(), 'u': unit, 'p': p, 'm': msg}


class Base(unittest.TestCase):
    def setUp(self):
        fresh = {
            '_state': {}, '_thread': Mock(), '_consecutive': {}, '_local_seen': {}, '_prev_throttled': None,
            '_hb_401': 0, '_kernel_lines': [], '_cycle_lines': [], '_rejects': {}, '_link_downs': [],
            '_mon_status': {}, '_mon_recoveries': {}, '_disk_samples': [], '_upload_cache': {'out': []},
            '_drift_cache': {'ts': 0.0, 'out': []}, '_net': {'thread': None, 'result': None, 'fresh': False},
            '_top_cache': {'cyc': None, 'top': []}, '_cycle_cache': {}, '_press_log': [],
            '_video_seen': {}, '_video_floor': None, '_ffprobe_missing': False, '_cyc': 0,
            '_cost': {'cpuMs': None, 'skipped': 0}, '_last_autoheal': 0.0,
            '_guard': {'pids': [], 'kills': {}, 'lastKill': {}, 'pending': None, 'events': [], 'rss': {},
                       'recurReported': {}},
        }
        for name, value in fresh.items():
            p = patch.object(obs, name, value); p.start(); self.addCleanup(p.stop)
        for name in ['save_state', '_log']:
            p = patch.object(obs, name); p.start(); self.addCleanup(p.stop)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for name, value in [('SPOOL_DIR', os.path.join(self.tmp, 'spool')), ('VIDEO_DIRS', (os.path.join(self.tmp, 'videos'),)),
                            ('PM2_LOG_DIR', os.path.join(self.tmp, 'pm2'))]:
            p = patch.object(obs, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(obs, '_local_get_cached', side_effect=lambda path: obs._local_get(path))
        p.start(); self.addCleanup(p.stop)


class Buttons(Base):
    def test_gpio_held_low_reports_unless_pin_reads_high(self):
        obs._state['lastPress'] = {'quadra01_camera01': 1700000000.0}
        obs._cycle_lines = [L('gravae-buttons', '[ALERT] 2026-11-09 10:00:00 quadra01_camera01 (GPIO6) stuck LOW ~20s'),
                            L('gravae-buttons', '[ALERT] 2026-11-09 10:00:20 quadra01_camera01 (GPIO6) stuck LOW ~20s')]
        with patch.object(obs, '_gpio_level', return_value=0) as lvl:
            out = obs.check_gpio_held_low()
        lvl.assert_called_once_with('6')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['severity'], 'critical')
        self.assertEqual(out[0]['dedupKey'], 'gpio_held_low:GPIO6')
        self.assertEqual(out[0]['evidence']['lastPressTs'], 1700000000.0)
        with patch.object(obs, '_gpio_level', return_value=None):
            self.assertEqual(len(obs.check_gpio_held_low()), 1)   # sem ferramenta: confia no daemon
        with patch.object(obs, '_gpio_level', return_value=1):
            self.assertEqual(obs.check_gpio_held_low(), [])        # já soltou

    def test_gpio_level_parsers(self):
        with patch.object(obs, '_run', return_value=(0, 'GPIO 6: level=0 fsel=0 func=INPUT pull=UP')):
            self.assertEqual(obs._gpio_level(6), 0)
        with patch.object(obs, '_run', side_effect=[(1, ''), (0, ' 6: ip    pu | hi // GPIO6 = input')]):
            self.assertEqual(obs._gpio_level(6), 1)

    def test_ghost_presses_threshold(self):
        now = time.time()
        obs._cycle_lines = [L('gravae-buttons', '[REJECT] glitch 0.4ms GPIO13', now - i) for i in range(19)]
        self.assertEqual(obs.check_gpio_ghost_presses(now), [])
        obs._cycle_lines = [L('gravae-buttons', '[REJECT] glitch GPIO13', now)]
        out = obs.check_gpio_ghost_presses(now)
        self.assertEqual(out[0]['evidence']['rejectsIn10min'], 20)
        self.assertEqual(out[0]['severity'], 'medium')
        obs._cycle_lines = []
        self.assertEqual(obs.check_gpio_ghost_presses(now + 700), [])

    def test_trigger_rejected(self):
        obs._cycle_lines = [
            L('gravae-buttons', '[HTTP] 2026-11-09 10:00:00 quadra01_camera01 -> 200'),
            L('gravae-buttons', '[HTTP] 2026-11-09 10:00:01 quadra02_camera01 -> 200 mas RECUSADO pelo Shinobi: Not Authorized'),
            L('gravae-buttons', '[HTTP] 2026-11-09 10:00:02 quadra03_camera01 -> 401'),
            L('gravae-buttons', '[HTTP] 2026-11-09 10:00:03 quadra03_camera01 -> ERRO: Connection refused'),
        ]
        out = {a['evidence']['monitor']: a for a in obs.check_trigger_rejected()}
        self.assertEqual(sorted(out), ['quadra02_camera01', 'quadra03_camera01'])
        self.assertEqual(out['quadra03_camera01']['evidence']['count'], 2)
        self.assertTrue(out['quadra02_camera01']['dedupKey'].startswith('trigger_rejected:quadra02_camera01:'))
        self.assertEqual(out['quadra02_camera01']['severity'], 'critical')

    def test_presses_come_from_cycle_journal_in_all_formats(self):
        self.assertEqual(obs.parse_press('[PRESS] 2026-08-07 18:16:18 - GPIO6 - quadra01_camera01 [1 monitors]'),
                         ('6', 'quadra01_camera01'))
        self.assertEqual(obs.parse_press('[PRESS] 2026-08-07 18:16:18 - quadra01_camera01 (GPIO6)'),
                         ('6', 'quadra01_camera01'))
        self.assertEqual(obs.parse_press('[PRESS] GPIO13 -> quadra02_camera01 (Quadra 1) HTTP 200'),
                         ('13', 'quadra02_camera01'))
        now = time.time()
        obs._feed_presses([L('gravae-buttons', '[PRESS] 2026-08-07 18:16:18 - quadra01_camera01 (GPIO6)', now - 10),
                           L('gravae-agent', '[PRESS] GPIO1 -> x', now)], now)
        self.assertEqual(obs._recent_presses(3, now), {'quadra01_camera01': {'last': now - 10, 'count': 1}})


class Upload(Base):
    def test_upload_stuck_db_and_folder(self):
        d = os.path.join(obs.VIDEO_DIRS[0], 'GK1', 'q1_camera01')
        os.makedirs(d)
        for i in range(2):
            f = os.path.join(d, 'v%d.mp4' % i)
            open(f, 'wb').write(b'x' * 10)
            os.utime(f, (time.time() - 3600, time.time() - 3600))
        with patch.object(obs, '_shinobi_creds', return_value=('k', 'GK1')), \
             patch.object(obs, '_mysql', return_value=[['q1_camera01', '2026-11-09 10:00:00', '45']]) as sql:
            out = obs.check_upload_stuck(run=True)
        sql.assert_called_once()
        ev = out[0]['evidence']
        self.assertEqual((ev['dbUnread'], ev['dbOldestMin'], ev['localFiles']), (1, 45, 2))
        with patch.object(obs, '_mysql') as sql:
            self.assertEqual(obs.check_upload_stuck(run=False), out)   # repete sem consultar
            sql.assert_not_called()

    def test_upload_stuck_ignores_single_and_fresh(self):
        with patch.object(obs, '_shinobi_creds', return_value=('k', 'GK1')), \
             patch.object(obs, '_mysql', return_value=[['m', 't', '25']]):
            self.assertEqual(obs.check_upload_stuck(run=True), [])

    def test_upload_sync_failed(self):
        obs._cycle_lines = [L('gravae-device-client', 'ARENA_CONFIG_SYNC_FAILED status=403 error code: 1010')]
        out = obs.check_upload_sync_failed()
        self.assertEqual(out[0]['type'], 'upload_sync_failed')
        obs._cycle_lines = [L('gravae-device-client', 'sync ok 200')]
        self.assertEqual(obs.check_upload_sync_failed(), [])


class ShinobiChecks(Base):
    def test_log_errors_tail_from_offset(self):
        os.makedirs(obs.PM2_LOG_DIR)
        path = os.path.join(obs.PM2_LOG_DIR, 'camera-error.log')
        open(path, 'w').write('old EACCES line\n')
        self.assertEqual(obs.check_shinobi_log_errors(), [])        # 1ª vez: não relê histórico
        with open(path, 'a') as fh:
            fh.write("Error: EACCES: permission denied, open '/home/Shinobi/videos/GK/x.mp4'\nok\nlisten EADDRINUSE :::8080\n")
        out = obs.check_shinobi_log_errors()
        self.assertEqual(len(out[0]['evidence']['lines']), 2)
        self.assertIn('EADDRINUSE', out[0]['evidence']['kinds'])
        self.assertEqual(obs.check_shinobi_log_errors(), [])        # nada novo
        open(path, 'w').write('ENOSPC: no space left\n')            # rotação (arquivo menor)
        self.assertEqual(obs.check_shinobi_log_errors()[0]['evidence']['kinds'], ['ENOSPC'])

    def test_duplicate_camera_js_needs_two_cycles(self):
        procs = [{'pid': 10, 'comm': 'node', 'argv': ['/usr/bin/node', '/home/Shinobi/camera.js'], 'uid': 0, 'cwd': '/opt/gravae-agent'},
                 {'pid': 11, 'comm': 'node', 'argv': ['node', 'camera.js'], 'uid': 1000, 'cwd': '/home/Shinobi'},
                 {'pid': 12, 'comm': 'node', 'argv': ['node', '/home/Shinobi/libs/singleCamera.js'], 'uid': 0}]
        with patch.object(obs, '_proc_list', return_value=procs):
            self.assertEqual(obs.check_shinobi_duplicate(), [])
            out = obs.check_shinobi_duplicate()
        self.assertEqual(len(out[0]['evidence']['processes']), 2)
        with patch.object(obs, '_proc_list', return_value=procs[1:]):
            self.assertEqual(obs.check_shinobi_duplicate(), [])

    def test_phoenix_down(self):
        self.assertEqual(obs.check_phoenix_down({'phoenixActive': False}), [])
        self.assertEqual(obs.check_phoenix_down({'phoenixActive': False})[0]['type'], 'phoenix_down')
        self.assertEqual(obs.check_phoenix_down({'phoenixActive': None}), [])


class SystemChecks(Base):
    def test_unexpected_reboot(self):
        obs._state['bootId'] = 'old'
        prev = '-- Journal begins --\nNov 09 kernel: x\nNov 09 systemd[1]: Reached target System Reboot.\n'
        with patch.object(obs, '_run', return_value=(0, prev)) as run:
            out = obs.check_unexpected_reboot({'bootId': 'new', 'throttled': '0x50000', 'uptimeSec': 30})
        self.assertEqual(run.call_args.args[0][:4], ['journalctl', '-b', '-1', '-n'])
        ev = out[0]['evidence']
        self.assertTrue(ev['cleanShutdown'])
        self.assertTrue(ev['undervoltageSinceBoot'])
        self.assertEqual(out[0]['severity'], 'medium')
        self.assertEqual(obs._state['bootId'], 'new')
        self.assertEqual(obs.check_unexpected_reboot({'bootId': 'new'}), [])
        obs._state['bootId'] = 'new'
        with patch.object(obs, '_run', return_value=(0, 'Nov 09 kernel: mmc0: timeout\n')):
            out = obs.check_unexpected_reboot({'bootId': 'b3'})
        self.assertEqual(out[0]['severity'], 'high')
        self.assertFalse(out[0]['evidence']['cleanShutdown'])

    def test_first_boot_seen_is_not_a_reboot(self):
        self.assertEqual(obs.check_unexpected_reboot({'bootId': 'x'}), [])
        self.assertEqual(obs._state['bootId'], 'x')

    def test_ping_parse_and_network_confirmation(self):
        txt = '3 packets transmitted, 1 received, 66.6667% packet loss, time 2003ms\nrtt min/avg/max/mdev = 10.1/20.5/30.2/4.1 ms'
        self.assertEqual(obs.parse_ping(txt), (66.6667, 20.5))
        self.assertEqual(obs.parse_ping('100% packet loss'), (100.0, None))
        for i in range(3):
            obs._net.update(result=('192.168.0.1', {'gw': (66.0, 3.0), 'net': (0.0, 30.0)}), fresh=True)
            out = obs.check_network_degraded()
        self.assertEqual(out[0]['type'], 'network_degraded')
        self.assertEqual(obs.check_network_degraded(), out)   # sem medição nova: repete
        obs._net.update(result=('gw', {'gw': (0.0, 1.0), 'net': (0.0, 30.0)}), fresh=True)
        self.assertEqual(obs.check_network_degraded(), [])

    def test_ping_round_never_blocks(self):
        import threading
        gate = threading.Event()
        with patch.object(obs, '_ping_worker', side_effect=lambda: gate.wait(2)):
            t0 = time.time()
            self.assertTrue(obs.start_ping_round())
            self.assertFalse(obs.start_ping_round())   # rodada pendurada não abre outra
            self.assertLess(time.time() - t0, 0.5)
            gate.set()

    def test_ethernet_flapping(self):
        now = time.time()
        obs._kernel_lines = [L('kernel', 'bcmgenet fd580000.ethernet eth0: Link is Down', now - 100)]
        self.assertEqual(obs.check_ethernet_flapping(now), [])
        obs._kernel_lines = [L('kernel', 'bcmgenet fd580000.ethernet eth0: Link is Down', now)]
        self.assertEqual(obs.check_ethernet_flapping(now)[0]['evidence']['linkDownsIn30min'], 2)
        obs._kernel_lines = []
        self.assertEqual(obs.check_ethernet_flapping(now + 2000), [])

    def test_camera_unstable(self):
        seq = ['watching', 'died', 'watching', 'died', 'watching', 'died', 'watching']
        out = []
        now = time.time()
        for i, st in enumerate(seq):
            with patch.object(obs, '_local_get', return_value={'monitors': [{'mid': 'm1', 'name': 'q1_camera01', 'status': st}]}):
                out = obs.check_camera_unstable(now + i * 45)
        self.assertEqual(out[0]['evidence']['recoveriesIn1h'], 3)
        self.assertEqual(out[0]['dedupKey'], 'camera_unstable:m1')

    def test_high_cpu_needs_four_cycles_and_names_libx264(self):
        top = [{'pid': 5, 'comm': 'ffmpeg', 'cpuPct': 180.0, 'monitor': 'q1_camera01', 'libx264': True}]
        with patch.object(obs.os, 'cpu_count', return_value=4), patch.object(obs, '_top_cpu', return_value=top) as tc:
            for _ in range(3):
                self.assertEqual(obs.check_high_cpu({'load1': 7.0}), [])
            out = obs.check_high_cpu({'load1': 7.0})
            obs.check_high_cpu({'load1': 7.0})
        self.assertIn('libx264', out[0]['detail'])
        tc.assert_called_once()   # top é caro: cacheado

    def test_disk_filling_prediction(self):
        now = 1_000_000.0
        total = 30000
        self.assertIsNone(obs.predict_disk_eta_hours([(0, 5000, total), (1800, 5000, total), (3600, 5000, total)]))
        out = []
        for i in range(0, 61, 5):   # perde 300 MB/h, 3000 MB livres, alvo 1500 MB ⇒ ~5h
            out = obs.check_disk_filling({'diskFreeMb': 3000 - 5 * i, 'diskTotalMb': total}, now + i * 60)
        self.assertEqual(out[0]['type'], 'disk_filling')
        self.assertAlmostEqual(out[0]['evidence']['etaHours'], 4.0, delta=0.6)

    def test_parse_units_single_call(self):
        text = ('Id=cloudflared.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\n'
                'Id=mariadb.service\nLoadState=loaded\nActiveState=failed\nUnitFileState=enabled\n\n'
                'Id=mysql.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n\n'
                'Id=gravae-buttons.service\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n')
        self.assertEqual(obs.parse_units(text), {'cloudflared': True, 'mariadb': False, 'mysql': None, 'gravae-buttons': None})

    def test_snapshot_new_fields(self):
        with patch.object(obs, '_run', return_value=(0, '')), patch.object(obs, '_dns_ok', return_value=True):
            snap = obs.build_snapshot()
        for k in ['tz', 'bootId', 'obsCpuMs', 'obsRssMb', 'obsSkipped', 'phoenixActive', 'diskTotalMb']:
            self.assertIn(k, snap)


class ConfigDrift(Base):
    def test_problems(self):
        d = {'detector': 1, 'detector_trigger': '1', 'det_trigger_tags': 'x', 'tagLegend': '',
             'vcodec': 'libx264', 'detector_buffer': '1', 'detector_use_motion': '1'}
        probs = obs.monitor_config_problems('mon_123', 'stop', d, {'mon_123'}, 'q1', hevc=True)
        joined = ' | '.join(probs)
        self.assertNotIn('detector_buffer', joined)   # '1' é a correção do caso SIP: não é drift
        for needle in ['details.detector salvo como número', 'tagLegend', 'libx264',
                       'detector_use_motion=1', 'mode=stop', "mid 'mon_", 'H.265']:
            self.assertIn(needle, joined)
        self.assertEqual(obs.monitor_config_problems('quadra01_camera01', 'start',
                                                     {'detector': '1', 'vcodec': 'copy'}), [])

    def test_hourly_single_query(self):
        rows = [['m1', 'start', 'q1', json.dumps({'detector': 1})], ['m2', 'start', 'q2', json.dumps({'vcodec': 'copy'})]]
        with patch.object(obs, '_shinobi_creds', return_value=('k', 'GK1')), \
             patch.object(obs, '_mysql', return_value=rows) as sql, patch.object(obs, '_hls_codec', return_value='h264'):
            out = obs.check_config_drift(run=True)
            again = obs.check_config_drift(run=False)
        sql.assert_called_once()
        self.assertEqual([a['dedupKey'] for a in out], ['config_drift:m1'])
        self.assertEqual(again, out)

    def test_mysql_unescape(self):
        self.assertEqual(obs._mysql_unescape(r'{"a":"x\ty","b":"c\\d"}'), '{"a":"x\ty","b":"c\\d"}')


class MemoryGuard(Base):
    def test_thresholds_scale_with_ram(self):
        pi3 = obs.mem_thresholds(900)
        self.assertEqual((pi3['warnRss'], pi3['actRss']), (300.0, 450.0))
        self.assertAlmostEqual(pi3['actAvail'], 108.0)
        pi4 = obs.mem_thresholds(3800)
        self.assertEqual((pi4['warnRss'], pi4['actRss']), (760.0, 1330.0))
        self.assertAlmostEqual(pi4['warnAvail'], 760.0)
        p = [{'pid': 9, 'rssMb': 500, 'monitor': 'q1_camera01'}]
        self.assertEqual(obs.guard_target(400, 900, p)['pid'], 9)           # Pi 3: 500 MB já é ação
        self.assertIsNone(obs.guard_target(2000, 3800, p))                   # Pi 4: ainda não
        self.assertEqual(obs.guard_target(100, 900, [{'pid': 9, 'rssMb': 200, 'monitor': 'm1'}], top_is_ffmpeg=True)['pid'], 9)
        self.assertIsNone(obs.guard_target(100, 900, [{'pid': 9, 'rssMb': 200, 'monitor': 'm1'}], top_is_ffmpeg=False))
        # sem mid de stream do Shinobi nunca é alvo
        self.assertIsNone(obs.guard_target(100, 900, [{'pid': 9, 'rssMb': 900, 'monitor': None}], top_is_ffmpeg=True))

    def test_trend_projection(self):
        t0 = 0
        self.assertIsNone(obs.leak_trend([(t0, 80), (60, 82)], 450))
        steady = [(t0 + i * 45, 80 + i * 6) for i in range(30)]          # 6 MB/45s ≈ 8 MB/min, +174 MB
        tr = obs.leak_trend(steady, 450)
        self.assertEqual(tr['growthMb'], 174)
        early = [(i * 60, 300 + i * 10) for i in range(7)]                # 360 MB, 10 MB/min ⇒ 9 min
        self.assertAlmostEqual(obs.leak_trend(early, 450)['projectedActInMin'], 9.0, delta=0.1)
        self.assertIsNone(obs.leak_trend([(0, 100), (60, 300), (120, 120), (180, 400)], 450))  # caiu
        self.assertIsNone(obs.leak_trend([(i * 60, 100 + i) for i in range(10)], 450))          # lento

    def test_trend_reports_before_threshold(self):
        obs._state['autoheal'] = True
        out = []
        for i in range(8):
            with patch.object(obs, '_meminfo_mb', return_value=(500, 900)), \
                 patch.object(obs, '_ffmpeg_rss_mb', return_value=[{'pid': 7, 'rssMb': 100 + i * 25, 'monitor': 'q1_camera01'}]):
                out = obs.check_memory_pressure(now=1000 + i * 45)
        self.assertEqual(out[0]['type'], 'ffmpeg_memory_leak')
        self.assertIn('trend', out[0]['evidence'])
        self.assertEqual(out[0]['severity'], 'medium')

    def _act(self, avail_after=600, now=10_000.0):
        target = {'pid': 4242, 'rssMb': 520, 'monitor': 'q1_camera01'}
        with patch.object(obs, '_kill_pid', return_value=True) as kill, patch.object(obs.time, 'sleep'), \
             patch.object(obs, '_meminfo_mb', return_value=(avail_after, 900)):
            res = obs.guard_act(target, 90, 900, now)
        return res, kill

    def test_kill_then_verify_then_fallback_restart(self):
        obs._state['autoheal'] = True
        res, kill = self._act()
        self.assertEqual(res, 'killed')
        kill.assert_called_once_with(4242)
        ev = obs.drain_guard_events()[0]
        self.assertEqual(ev['type'], 'memory_guard_action')
        self.assertEqual(ev['evidence']['action'], 'kill_ffmpeg')
        self.assertEqual(ev['evidence']['freedMb'], 510)
        # 60s depois ainda no limite ⇒ pm2 restart camera
        still = [{'pid': 5000, 'rssMb': 600, 'monitor': 'q1_camera01'}]
        with patch.object(obs, '_meminfo_mb', return_value=(80, 900)), patch.object(obs, '_scan_ffmpeg_pids', return_value=[5000]), \
             patch.object(obs, '_pid_info', side_effect=lambda pid, gk=None: still[0]), patch.object(obs, '_restart_camera', return_value=True) as rc, \
             patch.object(obs.time, 'sleep'):
            r = obs.guard_tick(now=10_061.0)
        self.assertEqual(r, 'restarted')
        rc.assert_called_once()
        self.assertEqual(obs.drain_guard_events()[0]['evidence']['action'], 'restart_camera')

    def test_verify_recovered_does_not_restart(self):
        obs._state['autoheal'] = True
        self._act()
        obs.drain_guard_events()
        with patch.object(obs, '_meminfo_mb', return_value=(600, 900)), patch.object(obs, '_scan_ffmpeg_pids', return_value=[]), \
             patch.object(obs, '_restart_camera') as rc:
            self.assertEqual(obs.guard_tick(now=10_061.0), 'recovered')
        rc.assert_not_called()

    def test_cooldown_and_recurring_keeps_protecting(self):
        obs._state['autoheal'] = True
        self.assertEqual(self._act(now=1.0)[0], 'killed')
        self.assertEqual(self._act(now=30.0)[0], 'verifying')     # cooldown do aparelho
        obs._guard['pending'] = None                               # verificação de 60s passou
        self.assertEqual(self._act(now=300.0)[0], 'cooldown')
        self.assertEqual(self._act(now=700.0)[0], 'killed')
        obs._guard['pending'] = None
        self.assertEqual(self._act(now=1400.0)[0], 'killed')
        obs._guard['pending'] = None
        obs.drain_guard_events()
        with patch.object(obs, '_leak_config', return_value={'mid': 'q1_camera01', 'wall_clock_timestamp_ignore': '1'}):
            res, kill = self._act(now=2100.0)
        self.assertEqual(res, 'killed_recurring')
        kill.assert_called_once_with(4242)             # continua derrubando
        evs = obs.drain_guard_events()
        types = [e['type'] for e in evs]
        self.assertEqual(sorted(types), ['ffmpeg_leak_recurring', 'memory_guard_action'])
        rec = [e for e in evs if e['type'] == 'ffmpeg_leak_recurring'][0]
        self.assertEqual(rec['evidence']['config']['wall_clock_timestamp_ignore'], '1')
        obs._guard['pending'] = None
        self.assertEqual(self._act(now=2400.0)[0], 'cooldown')   # cooldown de 10 min vale também
        with patch.object(obs, '_leak_config', return_value=None):
            self.assertEqual(self._act(now=2800.0)[0], 'killed_recurring')
        self.assertNotIn('ffmpeg_leak_recurring', [e['type'] for e in obs.drain_guard_events()])  # 1× a cada 2 h

    def test_policy_off_only_reports(self):
        obs._state['autoheal'] = False
        res, kill = self._act()
        self.assertEqual(res, 'reported')
        kill.assert_not_called()
        ev = obs.drain_guard_events()[0]
        self.assertEqual((ev['type'], ev['severity']), ('ffmpeg_memory_leak', 'high'))

    def test_kill_pid_refuses_non_ffmpeg(self):
        with patch('builtins.open', side_effect=lambda *a, **k: __import__('io').StringIO('python3\n')), \
             patch.object(obs.os, 'kill') as k:
            self.assertFalse(obs._kill_pid(1))
        k.assert_not_called()

    def test_fast_lane_is_cheap(self):
        with patch.object(obs.subprocess, 'run') as run, patch.object(obs.subprocess, 'Popen') as po, \
             patch.object(obs, '_meminfo_mb', return_value=(600, 900)), patch.object(obs, '_current_ffmpeg') as cur:
            for _ in range(20):
                self.assertEqual(obs.guard_tick(), 'ok')
        cur.assert_not_called()       # RAM folgada: nem olha os ffmpeg
        run.assert_not_called(); po.assert_not_called()
        with patch.object(obs.subprocess, 'run') as run, \
             patch.object(obs, '_meminfo_mb', return_value=(150, 900)), \
             patch.object(obs, '_current_ffmpeg', return_value=[{'pid': 3, 'rssMb': 120, 'monitor': None}]), \
             patch.object(obs, '_top_rss_is_ffmpeg', return_value=False):
            self.assertEqual(obs.guard_tick(), 'warn')
        run.assert_not_called()


class Budget(Base):
    """Conta processos abertos por ciclo e por camada (meta: ciclo barato ≤3)."""

    def _run_cycles(self, n, tight=False):
        obs._state.update(enabled=True, secret='k', opsUrl='https://ops.test', autoheal=False)
        spawns = []

        def fake_run(cmd, *a, **k):
            spawns.append((obs._cyc, os.path.basename(cmd[0]) if cmd[0] not in ('ionice', 'nice') else 'ffprobe'))
            r = Mock(); r.returncode, r.stdout, r.stderr = 0, '', ''
            return r

        mem = (80, 900) if tight else (600, 900)
        load = (9.0, 1, 1) if tight else (0.3, 0.3, 0.3)
        with patch.object(obs.subprocess, 'run', side_effect=fake_run), \
             patch.object(obs, '_post_status', return_value=(200, {})), patch.object(obs, '_post'), \
             patch.object(obs, '_local_get', return_value={'monitors': [], 'services': {}}), \
             patch.object(obs, '_shinobi_port_ok', return_value=True), \
             patch.object(obs, '_shinobi_creds', return_value=('k', 'GK1')), \
             patch.object(obs, '_shinobi_db', return_value={}), \
             patch.object(obs, '_meminfo_mb', return_value=mem), patch.object(obs.os, 'getloadavg', return_value=load), \
             patch.object(obs, '_read_throttled', return_value=0), patch.object(obs, '_dns_ok', return_value=True), \
             patch.object(obs, 'get_serial', return_value='pi'), \
             patch.object(obs, '_default_gateway', return_value='192.168.0.1'):
            saves0 = obs.save_state.call_count
            for _ in range(n):
                obs._cycle()
                t = obs._net.get('thread')
                if t is not None:
                    t.join(2)
            saves = obs.save_state.call_count - saves0
        per = {}
        for cyc, name in spawns:
            per.setdefault(cyc, []).append(name)
        return per, saves

    def test_spawns_per_tier(self):
        per, saves = self._run_cycles(26)
        cheap = [c for c in range(1, 27) if c % 3 != 1 and c % 13 != 1]
        for c in cheap:
            self.assertLessEqual(len(per.get(c, [])), 3, (c, per.get(c)))
            self.assertEqual(sorted(per.get(c, [])), ['journalctl', 'systemctl'])
        # ciclo de rede: +1 ping no gateway (em thread); internet por TCP, sem processo
        self.assertEqual(sorted(per[4]), ['journalctl', 'ping', 'systemctl'])   # gateway ICMP; internet é TCP
        # ciclo 1: rede + 1 SQL de upload + 1 SQL do config_drift (sem streams ⇒ 0 ffprobe)
        self.assertEqual(sorted(per[1]), ['journalctl', 'mysql', 'mysql', 'ping', 'systemctl'])
        # ciclo 14: só upload (drift só 1×/hora; rede nos ciclos 1, 4, 7…)
        self.assertEqual(sorted(per[14]), ['journalctl', 'mysql', 'systemctl'])
        # SD: ≤1 escrita a cada 2 ciclos (~90s)
        self.assertLessEqual(saves, 26 // 2 + 1)

    def test_backoff_skips_expensive_tiers(self):
        per, _ = self._run_cycles(1, tight=True)
        self.assertEqual(sorted(per[1]), ['journalctl', 'systemctl'])
        self.assertEqual(obs._cost['skipped'], 4)   # rede, upload, drift, vídeo
        self.assertIsNotNone(obs._cost['cpuMs'])


if __name__ == '__main__':
    unittest.main()
