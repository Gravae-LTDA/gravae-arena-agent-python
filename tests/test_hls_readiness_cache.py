import unittest
from unittest.mock import patch
from device_readiness import HlsReadinessCache

class CachedReadinessTests(unittest.TestCase):
    def setUp(self):
        self.now=0
        self.clock=patch('device_readiness.time.monotonic',side_effect=lambda:self.now)
        self.clock.start();self.addCleanup(self.clock.stop)
        self.probe=patch('device_readiness.hls_check',return_value={'ready':True,'errorCode':None})
        self.check=self.probe.start();self.addCleanup(self.probe.stop)
        self.cache=HlsReadinessCache()
    def decodes(self):return sum(c.kwargs['probe'] for c in self.check.call_args_list)
    def test_light_checks_every_cycle_and_decode_only_every_five_minutes(self):
        for i in range(20):
            self.now=i*15;self.assertTrue(self.cache.check('camera2')['ready'])
        self.assertEqual(self.decodes(),1)
        self.assertEqual(len(self.check.call_args_list),21)
        self.now=300;self.cache.check('camera2');self.assertEqual(self.decodes(),2)
    def test_corruption_invalidates_cached_success_and_recovery_requires_decode(self):
        self.cache.check('camera2')
        self.check.return_value={'ready':False,'errorCode':'HLS_TRUNCATED_SEGMENT'}
        self.now=15;self.assertFalse(self.cache.check('camera2')['ready'])
        self.assertEqual(self.decodes(),1)
        self.check.return_value={'ready':True,'errorCode':None}
        self.now=30;self.assertTrue(self.cache.check('camera2')['ready']);self.assertEqual(self.decodes(),2)
    def test_decode_failure_remains_failed_until_retry(self):
        self.check.side_effect=lambda manifest,probe: {'ready':not probe,'errorCode':'HLS_DECODE_FAILED' if probe else None}
        self.assertFalse(self.cache.check('camera2')['ready'])
        self.now=15;self.assertFalse(self.cache.check('camera2')['ready']);self.assertEqual(self.decodes(),1)
        self.now=60;self.cache.check('camera2');self.assertEqual(self.decodes(),2)
    def test_each_monitor_has_independent_validation(self):
        self.cache.check('camera2');self.cache.check('camera14');self.assertEqual(self.decodes(),2)
        self.now=15;r=self.cache.check('camera2');self.assertEqual(r['decodeAgeSeconds'],15)
    def test_missing_hls_does_not_spawn_decoder(self):
        self.check.return_value={'ready':False,'errorCode':'HLS_UNAVAILABLE'}
        self.assertFalse(self.cache.check('camera1')['ready']);self.assertEqual(self.decodes(),0)
