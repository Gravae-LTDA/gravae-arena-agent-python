from contextlib import closing
from pathlib import Path
import tempfile
import unittest

from device_event_outbox import EventOutbox


class EventOutboxTests(unittest.TestCase):
    def test_restart_retry_keeps_id_and_requires_matching_application_ack(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.sqlite3"
            outbox = EventOutbox(path)
            outbox.put("command.ack", {"eventId": "stable", "occurredAt": "fixed"})
            outbox.put("command.ack", {"eventId": "stable", "occurredAt": "fixed"})
            self.assertEqual(outbox.count(), 1)
            outbox.step(lambda *_: {"accepted": True, "eventId": "wrong"})
            self.assertEqual(outbox.count(), 1)
            restarted = EventOutbox(path)
            with closing(restarted.db()) as db:
                db.execute("UPDATE events SET due=0")
            seen = []
            def ack(event, payload):
                seen.append(payload)
                return {"accepted": True, "eventId": payload["eventId"]}
            restarted.step(ack)
            self.assertEqual(seen, [{"eventId": "stable", "occurredAt": "fixed"}])
            self.assertEqual(restarted.count(), 0)


if __name__ == "__main__":
    unittest.main()
