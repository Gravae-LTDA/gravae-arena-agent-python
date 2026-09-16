"""Fetch only the device's official config. No redirect or shared backend secret."""
import json
import os
from pathlib import Path
import time
import urllib.request
from urllib.parse import urlsplit, quote

class ConfigSyncError(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ConfigSyncError('ARENA_CONFIG_SYNC_FAILED')

def fetch_snapshot(config, config_path=None):
    identity = config.get('mediaDeviceId') or config.get('shinobiId') or config.get('deviceId')
    expected = '/internal/media-devices/' + quote(identity, safe='') + '/config'
    if config_path is not None and config_path != expected:
        raise ConfigSyncError('ARENA_CONFIG_SYNC_FAILED')
    base = config.get('backendUrl', '').rstrip('/')
    if not base:
        upload = json.loads(Path('/etc/gravae/direct-upload.json').read_text())
        if upload.get('arenaId') != config['arenaId'] or (upload.get('mediaDeviceId') or upload.get('deviceId')) != identity:
            raise ConfigSyncError('ARENA_CONFIG_SYNC_FAILED')
        base = upload['backendUrl'].rstrip('/')
    parsed = urlsplit(base)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ConfigSyncError('ARENA_CONFIG_SYNC_FAILED')
    # Cloudflare blocks the default Python-urllib User-Agent with error 1010, which
    # makes ARENA_CONFIG_SYNC fail fleet-wide. A non-library User-Agent passes the
    # bot check (same fix already applied in phoenix_daemon/gravae_agent).
    request = urllib.request.Request(base + expected, headers={'Authorization': 'Bearer ' + config['deviceToken'], 'User-Agent': 'gravae-device-client'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ConfigSyncError('ARENA_CONFIG_SYNC_FAILED')
        snapshot = json.loads(raw)
    if snapshot.get('arenaId') != config['arenaId'] or snapshot.get('mediaDeviceId') != identity or snapshot.get('mediaMode') not in ('DIRECT', 'LEGACY'):
        raise ConfigSyncError('ARENA_CONFIG_SYNC_FAILED')
    if config.get('groupKey') and snapshot.get('groupKey') != config['groupKey']:
        raise ConfigSyncError('ARENA_CONFIG_SYNC_FAILED')
    if not isinstance(snapshot.get('bindings'), list):
        raise ConfigSyncError('ARENA_CONFIG_SYNC_FAILED')
    return snapshot

def save_mode(config, mode):
    now = time.time()
    path = Path(config.get('mediaModeFile', '/var/lib/gravae-device-client/media-mode.json'))
    temp = path.with_name(path.name + '.' + str(os.getpid()) + '.tmp')
    value = {'mode': mode, 'arenaId': config['arenaId'], 'mediaDeviceId': config.get('mediaDeviceId') or config.get('shinobiId') or config.get('deviceId'), 'confirmedAt': now, 'expiresAt': now + 120}
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    temp.replace(path)
