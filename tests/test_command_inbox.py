import threading
import unittest
from unittest.mock import Mock
from device_gateway_client import CommandInbox

class CommandInboxTests(unittest.TestCase):
    def test_receipt_does_not_wait_for_operational_completion(self):
        entered, release, done, stopping = [threading.Event() for _ in range(4)]
        def execute(command):
            entered.set()
            release.wait(2)
            done.set()
            return {'event': 'command.failed', 'errorCode': 'DIRECT_MODE_REQUIRED'}
        runtime = Mock(execute=execute)
        inbox = CommandInbox(runtime, stopping)
        worker = threading.Thread(target=inbox.run)
        worker.start()
        try:
            receipt = inbox.receive({'commandId': 'one'})
            self.assertEqual(receipt, {'accepted': True, 'received': True, 'commandId': 'one'})
            self.assertTrue(entered.wait(1))
            self.assertFalse(done.is_set())
        finally:
            stopping.set(); release.set(); worker.join(3)
        self.assertTrue(done.is_set())

    def test_overload_is_rejected_without_unbounded_workers(self):
        inbox = CommandInbox(Mock(), threading.Event())
        for i in range(64):
            self.assertTrue(inbox.receive({'commandId': str(i)})['accepted'])
        self.assertEqual(inbox.receive({'commandId': 'overflow'})['errorCode'], 'COMMAND_QUEUE_FULL')
