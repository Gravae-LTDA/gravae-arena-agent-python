import sys
import time
import tempfile
import unittest
from pathlib import Path
from direct_publisher import RetryingPublisher, safe_stderr, failure_code

class PublisherTests(unittest.TestCase):
    def test_redaction_and_classification(self):
        line = safe_stderr('rtmp://10.0.0.1/live/secret tcp://10.0.0.1:1935 Connection refused /private/hls/file', ['secret','/private/hls/file'])
        self.assertNotIn('secret', line)
        self.assertNotIn('10.0.0.1', line)
        self.assertNotIn('/private', line)
        self.assertEqual(failure_code(line), 'RTMP_CONNECTION_REFUSED')

    def test_retry_then_media_without_duplicate_publisher(self):
        with tempfile.TemporaryDirectory() as temp:
            counter = Path(temp)/'count'
            script = """import pathlib,sys,time
p=pathlib.Path(sys.argv[1]);n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n))
if n<3:
 print('Connection refused rtmp://host/live/secret',file=sys.stderr);sys.exit(146)
print('out_time_us=1000',flush=True);time.sleep(.2)
"""
            logs=[]
            publisher=RetryingPublisher([sys.executable,'-c',script,str(counter)], ['secret'],
                lambda event,**kw:logs.append((event,kw)), {}, 5, retry_seconds=3,retry_interval=.02)
            publisher.wait(5)
            self.assertTrue(publisher.media_started.is_set())
            self.assertEqual(counter.read_text(),'3')
            self.assertEqual(len([x for x in logs if x[0]=='publisher.retry']),2)
            self.assertTrue(any(x[1].get('exitCode')==146 for x in logs))
            self.assertNotIn('secret',str(logs))

    def test_stop_cancels_retry(self):
        logs=[]
        publisher=RetryingPublisher([sys.executable,'-c','import sys;sys.exit(1)'], [],
            lambda event,**kw:logs.append(event),{},10,retry_interval=2)
        time.sleep(.1)
        publisher.terminate();publisher.wait(3)
        attempts=logs.count('publisher.attempt')
        time.sleep(.1)
        self.assertEqual(logs.count('publisher.attempt'),attempts)
        self.assertIsNotNone(publisher.poll())

    def test_hung_startup_is_bounded(self):
        publisher=RetryingPublisher([sys.executable,'-c','import time;time.sleep(30)'],[],
            lambda *a,**kw:None,{},30,retry_seconds=.2,retry_interval=.01)
        publisher.wait(4)
        self.assertIsNotNone(publisher.poll())
        self.assertFalse(publisher.media_started.is_set())
