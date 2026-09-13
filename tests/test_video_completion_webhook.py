import json
import unittest
import urllib.request
import urllib.error
from video_completion_webhook import start_completion_server

class CompletionWebhookTests(unittest.TestCase):
    def setup_server(self, accept):
        state={};server,thread=start_completion_server({'completionWebhook':{'port':0,'token':'x'*40}},accept,state)
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        return 'http://127.0.0.1:'+str(server.server_port)+'/video-complete',state
    def post(self,url,token='x'*40):
        request=urllib.request.Request(url,b'{"monitorId":"camera02","filename":"clip.mp4"}',
            {'Authorization':'Bearer '+token,'Content-Type':'application/json'},method='POST')
        try:
            with urllib.request.urlopen(request,timeout=3) as response:return response.status,json.loads(response.read())
        except urllib.error.HTTPError as response:
            with response:return response.code,json.loads(response.read())
    def test_requires_auth_before_calling_queue(self):
        calls=[];url,_=self.setup_server(lambda data:calls.append(data))
        self.assertEqual(self.post(url,'wrong')[0],401);self.assertEqual(calls,[])
    def test_accepts_only_after_enqueue_returns_job(self):
        persisted=[]
        def enqueue(data):persisted.append(data);return 'durable-job'
        url,state=self.setup_server(enqueue)
        code,body=self.post(url)
        self.assertEqual(code,202);self.assertEqual(body['jobId'],'durable-job');self.assertEqual(len(persisted),1)
        self.assertEqual(state['notificationsAccepted'],1)
    def test_queue_failure_requests_retry(self):
        def failed(data):raise OSError('queue unavailable')
        url,_=self.setup_server(failed)
        code,body=self.post(url)
        self.assertEqual(code,503);self.assertFalse(body['accepted'])
