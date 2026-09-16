import json
import os
from pathlib import Path
import tempfile
import unittest
from device_readiness import public_direct_status

class DirectStatusTests(unittest.TestCase):
    def test_diagnostic_projection_omits_secrets_and_marks_stale_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'status.json'
            path.write_text(json.dumps({'status':'READY','directModeValid':True,'configSyncOk':True,
                'deviceToken':'secret','activeStreams':[{'streamId':'live-1','rtmpUrl':'secret'}],
                'lastConfigSyncError':{'httpStatus':403,'message':'secret'}}))
            result = public_direct_status(path)
            self.assertNotIn('secret', json.dumps(result))
            self.assertEqual(result['activeStreams'], [{'streamId':'live-1'}])
            self.assertEqual(result['lastConfigSyncError']['httpStatus'],403)
            os.utime(path,(1,1))
            result = public_direct_status(path)
            self.assertTrue(result['stale'])
            self.assertFalse(result['directModeValid'])
            self.assertEqual(result['status'],'UNKNOWN')

    def test_missing_status_never_implies_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(public_direct_status(Path(tmp)/'absent')['configSyncOk'])
