"""Short-lived mode confirmation written by the authenticated OPS worker."""
import json
import time
from pathlib import Path

def direct_enabled(config):
    try:
        value = json.loads(Path(config.get('mediaModeFile', '/etc/gravae/media-mode.json')).read_text())
        identity = config.get('mediaDeviceId') or config.get('shinobiId') or config.get('deviceId')
        return (value.get('mode') == 'DIRECT' and value.get('mediaDeviceId') == identity
                and value.get('arenaId') == config.get('arenaId')
                and value.get('confirmedAt', 0) <= time.time() < value.get('expiresAt', 0)
                and 0 < value['expiresAt'] - value['confirmedAt'] <= 120)
    except (OSError, ValueError, TypeError, KeyError):
        return False
