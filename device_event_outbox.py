"""Durable events are removed only after an application ACK for the same ID."""

from contextlib import closing
import json
import random
import sqlite3
import time


class EventOutbox:
    def __init__(self, path):
        self.path = path
        with closing(self.db()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, event TEXT NOT NULL, "
                       "payload TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, due REAL NOT NULL DEFAULT 0)")

    def db(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def put(self, event, payload, db=None):
        if db is None:
            with closing(self.db()) as connection:
                return self.put(event, payload, connection)
        db.execute("INSERT OR IGNORE INTO events(id,event,payload) VALUES(?,?,?)",
                   (payload["eventId"], event, json.dumps(payload)))

    def step(self, send):
        with closing(self.db()) as db:
            row = db.execute("SELECT id,event,payload,attempts FROM events WHERE due<=? "
                             "ORDER BY due,rowid LIMIT 1", (time.time(),)).fetchone()
        if not row:
            return False
        event_id, event, payload, attempts = row
        try:
            ack = send(event, json.loads(payload))
            confirmed = isinstance(ack, dict) and ack.get("accepted") is True and ack.get("eventId") == event_id
        except Exception:
            confirmed = False
        with closing(self.db()) as db:
            if confirmed:
                db.execute("DELETE FROM events WHERE id=?", (event_id,))
            else:
                delay = min(300, 5 * 2**min(attempts, 6)) * random.uniform(0.8, 1.2)
                db.execute("UPDATE events SET attempts=attempts+1,due=? WHERE id=?",
                           (time.time() + delay, event_id))
        return True

    def count(self):
        with closing(self.db()) as db:
            return db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
