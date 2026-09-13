from contextlib import ExitStack
from datetime import datetime,timedelta,timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock,patch
import time
from device_gateway_client import DeviceRuntime

class MonitorPublishersTests(TestCase):
    def setUp(self):
        temp=TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name)
        source=root/'s.m3u8';source.write_text('#EXTM3U\n')
        self.r=DeviceRuntime({'stateDir':temp.name,'mediaDeviceId':'device','arenaId':'arena',
            'liveActiveFile':str(root/'live'),'monitors':{m:{'hlsManifest':str(source),'rtspUrl':'rtsp://camera.local/feed'} for m in ['cam2','cam14']}})
        self.addCleanup(self.r.lock_file.close)
        self.context=ExitStack();self.addCleanup(self.context.close)
        self.context.enter_context(patch('device_gateway_client.time.sleep'))
        self.context.enter_context(patch('device_gateway_client.hls_check',return_value={'ready':True}))
        self.context.enter_context(patch('device_gateway_client.resource_checks',return_value={'shmReady':True,'shinobiDescriptorsReady':True}))
        self.spawn=self.context.enter_context(patch('device_gateway_client.RetryingPublisher'))
        def process(*a,**kw):
            p=Mock();p.poll.return_value=None;p.pid=123;return p
        self.spawn.side_effect=process
    def command(self,s,m,kind='STREAM_START'):
        return {'commandId':kind+s,'mediaDeviceId':'device','arenaId':'arena','streamId':s,'type':kind,
                'expiresAt':(datetime.now(timezone.utc)+timedelta(minutes=2)).isoformat(),
                'payload':{'monitorId':m,'rtmpUrl':'rtmp://dynamic-vm/live','streamKey':s}}
    def test_two_monitors_and_stop_are_isolated(self):
        self.assertEqual(self.r.execute(self.command('a','cam2'))['event'],'command.ack')
        self.assertEqual(self.r.execute(self.command('b','cam14'))['event'],'command.ack')
        other=self.r.streams['b']['process']
        self.r.execute(self.command('a','cam2','STREAM_STOP'))
        self.assertEqual(list(self.r.streams),['b']);other.terminate.assert_not_called()
        self.assertTrue(self.r.marker.exists())
        self.r.execute(self.command('b','cam14','STREAM_STOP'))
        self.assertFalse(self.r.marker.exists())
    def test_same_monitor_cannot_start_second_live_and_duplicate_is_idempotent(self):
        command=self.command('a','cam2');first=self.r.execute(command)
        self.assertEqual(self.r.execute(command),first)
        self.assertEqual(self.r.execute(self.command('b','cam2'))['errorCode'],'MONITOR_PUBLISHER_BUSY')
        self.assertEqual(self.spawn.call_count,1)
    def test_one_failure_keeps_other_live_and_replays_failure(self):
        a=self.command('a','cam2');self.r.execute(a);self.r.execute(self.command('b','cam14'))
        failed=self.r.streams['a']['process'];failed.poll.return_value=146;failed.returncode=146
        self.r.reap_publishers()
        self.assertEqual(list(self.r.streams),['b'])
        self.assertTrue(self.r.marker.exists())
        self.assertEqual(self.r.execute(a)['event'],'command.failed')
    def test_one_timeout_keeps_other_live(self):
        self.r.execute(self.command('a','cam2'));self.r.execute(self.command('b','cam14'))
        self.r.streams['a']['deadline']=time.monotonic()-1;self.r.reap_publishers()
        self.assertEqual(list(self.r.streams),['b']);self.assertTrue(self.r.marker.exists())
