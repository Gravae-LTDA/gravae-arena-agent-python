"""Fixed, root-only provisioning entrypoint. Input arrives via SSH stdin, never argv.
Only this program owns local installation; OPS owns enrollment and mode changes.
Existing device identity, queue, recordings and WireGuard peers are preserved.
"""
import base64
import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import secrets
import subprocess
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

class InstallError(Exception):
    pass

def media_identity(config):
    ids = [config[k] for k in ('mediaDeviceId', 'shinobiId') if config.get(k)]
    if len(set(ids)) > 1:
        raise InstallError('IDENTITY_MISMATCH')
    return ids[0] if ids else config.get('deviceId')

def http_agent_version():
    with urllib.request.urlopen('http://127.0.0.1:8888/update/version', timeout=5) as response:
        version = json.load(response).get('version', '')
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise InstallError('AGENT_UPDATE_FAILED')
    return version

def controlled_startup():
    dropin = Path('/etc/systemd/system/gravae-agent.service.d/90-controlled-startup.conf')
    baseline = Path('/etc/gravae/http-startup-baseline.json')
    if not baseline.exists():
        atomic(baseline, json.dumps({'dropin': dropin.read_text() if dropin.exists() else None}))
    atomic(dropin, '[Service]\nEnvironment=GRAVAE_STARTUP_REPAIRS=disabled\n')
    run(['systemctl', 'daemon-reload'])

def update_agent(data):
    identity(data['serial'])
    if Path('/run/gravae-live.active').exists():
        raise InstallError('LIVE_IN_PROGRESS')
    try:
        target = Path(__file__).with_name('VERSION').read_text().strip()
        if not re.fullmatch(r'\d+\.\d+\.\d+', target):
            raise InstallError('AGENT_UPDATE_FAILED')
        required_version = tuple(map(int, target.split('.')))
        version = http_agent_version()
        if tuple(map(int, version.split('.'))) >= required_version:
            return {'agentVersion': version, 'updated': False}
        controlled_startup()
        request = urllib.request.Request('http://127.0.0.1:8888/update/perform', b'{}', {'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(request, timeout=10) as response:
            if json.load(response).get('success') is not True:
                raise InstallError('AGENT_UPDATE_FAILED')
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            time.sleep(2)
            try:
                version = http_agent_version()
                if tuple(map(int, version.split('.'))) >= required_version:
                    return {'agentVersion': version, 'updated': True}
            except (OSError, ValueError, InstallError):
                pass  # The HTTP service restarts during its own update.
    except Exception:
        raise InstallError('AGENT_UPDATE_FAILED')
    raise InstallError('AGENT_UPDATE_FAILED')

def camera_sources(data):
    # Credentials stay on the Raspberry. Read the authenticated local monitor API.
    url = 'http://127.0.0.1:8080/' + '/'.join(urllib.parse.quote(p, safe='') for p in (data['shinobiKey'], 'monitor', data['groupKey']))
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            rows = json.load(response)
        if not isinstance(rows, list):
            raise ValueError()
        sources = {}
        for row in rows:
            if row.get('mid') not in {m['monitorId'] for m in data['monitors']}:
                continue
            details = row.get('details') or {}
            if isinstance(details, str):
                details = json.loads(details)
            protocol = row.get('protocol')
            host = row.get('host', '')
            if protocol not in ('rtsp', 'rtsps') or not host or any(x in host for x in '/\r\n'):
                raise ValueError()
            auth = ''
            if details.get('muser'):
                auth = urllib.parse.quote(str(details['muser']), safe='') + ':' + urllib.parse.quote(str(details.get('mpass') or ''), safe='') + '@'
            source = protocol + '://' + auth + host + ':' + str(row.get('port') or 554) + '/' + str(row.get('path') or '').lstrip('/')
            if not urllib.parse.urlsplit(source).hostname or any(ord(c) < 32 for c in source):
                raise ValueError()
            # Runtime validates again before every publication.
            sources[row['mid']] = {'rtspUrl': source, 'rtspTransport': details.get('rtsp_transport') or 'tcp', 'probeSize': int(details.get('probesize') or 1000000), 'analyzeDuration': int(details.get('aduration') or 1000000)}
        if len(sources) != len(data['monitors']):
            raise ValueError()
        return sources
    except Exception:
        raise InstallError('CAMERA_MAPPING_REQUIRED')

def monitor_inventory(data):
    observed_sources = camera_sources(data)
    return [{key: m[key] for key in ('monitorId', 'blockSlug', 'cameraSlug')}
            for m in data['monitors'] if m['monitorId'] in observed_sources]


def configure_http_agent(data):
    """Install only the local Shinobi identity; never backend EXTERNAL_KEY."""
    if not isinstance(data.get('shinobiKey'), str) or not data['shinobiKey']:
        raise InstallError('SHINOBI_AUTH_REQUIRED')
    path = Path('/etc/gravae/device.json')
    config = read(path) if path.exists() else {}
    if config.get('shinobiGroupKey') not in (None, '', data['groupKey']):
        raise InstallError('IDENTITY_MISMATCH')
    if config.get('shinobiGroupKey') == data['groupKey'] and config.get('shinobiApiKey') == data['shinobiKey']:
        return False
    config.update(shinobiGroupKey=data['groupKey'], shinobiApiKey=data['shinobiKey'])
    atomic(path, json.dumps(config))
    return True

def reload_http_agent():
    # Loading the new local key must not trigger the old startup media repairs.
    if tuple(map(int, http_agent_version().split('.'))) < (4, 0, 1):
        raise InstallError('AGENT_UPDATE_REQUIRED')
    controlled_startup()
    run(['systemctl', 'restart', 'gravae-agent'])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if tuple(map(int, http_agent_version().split('.'))) >= (4, 0, 1):
                return
        except (OSError, ValueError, InstallError):
            pass
        time.sleep(1)
    raise InstallError('AGENT_RELOAD_FAILED')

def configure_v4(data, current, cfg, source):
    sources = camera_sources(data)
    http_config_changed = configure_http_agent(data)
    if data.get('backendUrl'):
        current['backendUrl'] = data['backendUrl']
    current['groupKey'] = data['groupKey']
    current['mediaModeFile'] = '/var/lib/gravae-device-client/media-mode.json'
    current.update(mediaDeviceId=data['deviceId'], shinobiId=data['deviceId'],
                   hlsDecodeIntervalSeconds=300, hlsDecodeRetrySeconds=60)
    for m in data['monitors']:
        monitor = m['monitorId']
        current.setdefault('monitors', {}).setdefault(monitor, {}).update(sources[monitor])
        current['monitors'][monitor]['hlsManifest'] = f'/dev/shm/streams/{data["groupKey"]}/{monitor}/s.m3u8'
    cfg['mediaModeFile'] = '/var/lib/gravae-device-client/media-mode.json'
    cfg.setdefault('queueIdentity', cfg['deviceId'])
    cfg.update(mediaDeviceId=data['deviceId'], shinobiId=data['deviceId'],
               adaptiveUploadEnabled=True, requireClosedFile=True, settleSeconds=3,
               scanIntervalSeconds=300, uploadBytesPerSecond=10*1024**2,
               uploadInitialBytesPerSecond=2*1024**2, uploadMinimumBytesPerSecond=65536,
               liveUploadBytesPerSecond=2*1024**2, liveUploadFraction=0.2)
    # Preserve the queue, collection watermark and confirmed recordings.
    hookfile = Path('/etc/gravae/shinobi-upload-hook.json')
    hook = read(hookfile) if hookfile.exists() else {'token': secrets.token_urlsafe(32), 'port': 8766}
    if not isinstance(hook.get('token'), str) or len(hook['token']) < 32:
        raise InstallError('WEBHOOK_ACTIVATION_REQUIRED')
    hook['groupKey'] = data['groupKey']
    cfg['deleteLocalAfterUpload'] = True
    cfg['localVideoDeleteBases'] = {m['monitorId']: 'http://127.0.0.1:8080/' + '/'.join(urllib.parse.quote(p, safe='') for p in (data['shinobiKey'], 'videos', data['groupKey'], m['monitorId'])) for m in data['monitors']}
    cfg['completionWebhook'] = {'token': hook['token'], 'port': hook['port']}
    atomic(hookfile, json.dumps(hook))
    atomic('/home/Shinobi/libs/customAutoLoad/gravae-upload-hook.js', (source/'shinobi_upload_hook.js').read_text())
    atomic('/etc/gravae/device-client.json', json.dumps(current))
    atomic('/etc/gravae/direct-upload.json', json.dumps(cfg))
    atomic('/etc/systemd/system/gravae-confirmed-video-cleanup.service', '[Unit]\nDescription=Cleanup confirmed R2 uploads\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /opt/gravae-direct-queue/confirmed_video_cleanup.py --config /etc/gravae/direct-upload.json\nNice=15\nUMask=0077\n')
    atomic('/etc/systemd/system/gravae-confirmed-video-cleanup.timer', '[Unit]\nDescription=Cleanup confirmed R2 uploads\n[Timer]\nOnBootSec=30\nOnUnitInactiveSec=10\n[Install]\nWantedBy=timers.target\n')
    return http_config_changed

def activate_hook():
    # Native extension hot reload preserves Shinobi recording processes.
    try:
        users = read('/home/Shinobi/super.json')
        conf = read('/home/Shinobi/conf.json')
        tokens = next(u['tokens'] for u in users if u.get('tokens'))
        token = next(iter(tokens))
        paths = conf.get('webPaths') or {}
        prefix = paths.get('superApiPrefix') or paths.get('super') or '/super/'
        url = 'http://127.0.0.1:' + str(conf.get('port') or 8080) + '/' + prefix.strip('/') + '/' + urllib.parse.quote(token, safe='') + '/package/reloadAll'
        request = urllib.request.Request(url, b'{}', {'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200 or json.load(response).get('ok') is not True:
                raise ValueError()
    except Exception:
        raise InstallError('WEBHOOK_ACTIVATION_REQUIRED')

def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=kwargs.pop('timeout', 60), **kwargs)
    if result.returncode:
        raise InstallError('INSTALL_FAILED')
    return result.stdout.strip()

def read(path):
    return json.loads(Path(path).read_text())

def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(value)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)

def identity(expected):
    serial = next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('Serial')), '')
    if not serial or serial != expected:
        raise InstallError('IDENTITY_MISMATCH')
    return serial

def bindings(monitors):
    if not monitors:
        raise InstallError('CAMERA_MAPPING_REQUIRED')
    for monitor in monitors:
        for key in ('blockSlug', 'cameraSlug', 'monitorId'):
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', monitor.get(key, '')):
                raise InstallError('CAMERA_MAPPING_REQUIRED')
    if len({m['monitorId'] for m in monitors}) != len(monitors):
        raise InstallError('CAMERA_MAPPING_REQUIRED')
    return monitors

def check_shinobi(data):
    key = data.get('shinobiKey')
    if not key or not isinstance(key, str):
        raise InstallError('SHINOBI_AUTH_REQUIRED')
    for monitor in data['monitors']:
        parts = (key, 'hls', data['groupKey'], monitor['monitorId'], 's.m3u8')
        url = 'http://127.0.0.1:8080/' + '/'.join(urllib.parse.quote(p, safe='') for p in parts)
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status != 200 or not response.read(1024).startswith(b'#EXTM3U'):
                    raise InstallError('SHINOBI_AUTH_REQUIRED')
        except Exception:
            raise InstallError('SHINOBI_AUTH_REQUIRED')


class NoBackendRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def gateway_token_ready(data, config):
    token = config.get('deviceToken')
    if not token:
        return False
    base = data.get('backendUrl', '').rstrip('/')
    if urllib.parse.urlparse(base).scheme != 'https':
        raise InstallError('IDENTITY_MISMATCH')
    request = urllib.request.Request(
        base + '/internal/media-devices/' + urllib.parse.quote(media_identity(config), safe='') + '/config',
        headers={'Authorization': 'Bearer ' + token})
    try:
        with urllib.request.build_opener(NoBackendRedirect()).open(request, timeout=15) as response:
            snapshot = json.load(response)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code in (401, 403):
            return False
        raise InstallError('BACKEND_UNAVAILABLE') from None
    except Exception:
        raise InstallError('BACKEND_UNAVAILABLE') from None
    if snapshot.get('arenaId') != data['arenaId'] or snapshot.get('mediaDeviceId') != media_identity(config):
        raise InstallError('IDENTITY_MISMATCH')
    return True


def install_gateway_token(config_file, current, enrollment):
    if not enrollment:
        return
    token = enrollment.get('deviceGatewayToken')
    if not isinstance(token, str) or not token:
        raise InstallError('INSTALL_FAILED')
    current['deviceToken'] = token
    atomic(config_file, json.dumps(current))


def prepare(data):
    serial = identity(data['serial'])
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', data.get('groupKey', '')):
        raise InstallError('CAMERA_MAPPING_REQUIRED')
    bindings(data['monitors'])
    check_shinobi(data)
    camera_sources(data)
    existing = read('/etc/gravae/device-client.json') if Path('/etc/gravae/device-client.json').exists() else {}
    if existing and (existing.get('arenaId') != data['arenaId'] or existing.get('environment') != data['environment']):
        raise InstallError('IDENTITY_MISMATCH')
    if existing:
        return {'serial': serial, 'deviceId': media_identity(existing), 'existing': True, 'gatewayTokenReady': gateway_token_ready(data, existing), 'sshHostPublicKey': Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip()}
    if not shutil.which('wg'):
        run(['apt-get', 'update'], timeout=300)
        run(['apt-get', 'install', '-y', 'wireguard-tools'], timeout=600)
    # Existing unowned configuration must be explicitly reconciled by OPS first.
    if Path('/etc/wireguard/wg0.conf').exists() and not Path('/etc/gravae/direct-wireguard.key').exists():
        raise InstallError('VPN_CONFIG_CONFLICT')
    keyfile = Path('/etc/gravae/direct-wireguard.key')
    if not keyfile.exists():
        atomic(keyfile, run(['wg', 'genkey']) + '\n')
    public = run(['wg', 'pubkey'], input=keyfile.read_text())
    return {'serial': serial, 'publicKey': public, 'existing': False, 'sshHostPublicKey': Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip()}

def wg_config(enrollment, environment, private_key):
    cidr = {'staging': '10.89.0.0/16', 'prod': '10.88.0.0/16', 'replayme': '10.90.0.0/16'}[environment]
    net = ipaddress.ip_network(cidr)
    ip = ipaddress.ip_address(enrollment['vpnIp'])
    routes = enrollment['allowedIps']
    if not isinstance(routes, list) or not routes or ip not in net or any(not ipaddress.ip_network(r).subnet_of(net) for r in routes):
        raise InstallError('VPN_CONFIG_CONFLICT')
    endpoint = enrollment['hubEndpoint']
    if not re.fullmatch(r'[A-Za-z0-9.-]+:[0-9]{1,5}', endpoint):
        raise InstallError('VPN_CONFIG_CONFLICT')
    pubkey = enrollment['hubPublicKey']
    if len(base64.b64decode(pubkey, validate=True)) != 32:
        raise InstallError('VPN_CONFIG_CONFLICT')
    return f'[Interface]\nPrivateKey = {private_key.strip()}\nAddress = {ip}/32\n\n[Peer]\nPublicKey = {pubkey}\nEndpoint = {endpoint}\nAllowedIPs = {", ".join(routes)}\nPersistentKeepalive = 25\n'

def install_ops_key(data):
    """Reuse the authenticated LEGACY account; add the OPS key without replacing keys."""
    key, user = data.get('opsPublicKey'), data.get('opsSshUser')
    if key is None and user is None:
        return
    if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]*', user):
        raise InstallError('SSH_NOT_CONFIGURED')
    if not isinstance(key, str) or not re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/]+={0,3}', key):
        raise InstallError('SSH_NOT_CONFIGURED')
    import pwd
    account = pwd.getpwnam(user)
    folder = Path(account.pw_dir) / '.ssh'
    if folder.is_symlink() or (folder / 'authorized_keys').is_symlink():
        raise InstallError('SSH_NOT_CONFIGURED')
    folder.mkdir(mode=0o700, exist_ok=True)
    target = folder / 'authorized_keys'
    previous = target.read_text() if target.exists() else ''
    if not any(' '.join(line.split()[:2]) == key for line in previous.splitlines()):
        atomic(target, previous.rstrip('\n') + ('\n' if previous else '') + key + '\n')
    os.chown(folder, account.pw_uid, account.pw_gid)
    os.chown(target, account.pw_uid, account.pw_gid)
    folder.chmod(0o700)
    target.chmod(0o600)


def install(data):
    identity(data['serial'])
    monitors = bindings(data['monitors'])
    config_file = Path('/etc/gravae/device-client.json')
    current = read(config_file) if config_file.exists() else {}
    if current and (media_identity(current) != data['deviceId'] or current.get('arenaId') != data['arenaId'] or current.get('environment') != data['environment']):
        raise InstallError('IDENTITY_MISMATCH')
    if Path('/etc/gravae/direct-upload.json').exists():
        previous_upload = read('/etc/gravae/direct-upload.json')
        if media_identity(previous_upload) != data['deviceId'] or previous_upload.get('arenaId') != data['arenaId'] or previous_upload.get('backendUrl', '').rstrip('/') != data['backendUrl'].rstrip('/'):
            raise InstallError('IDENTITY_MISMATCH')
    if Path('/run/gravae-live.active').exists():
        raise InstallError('LIVE_IN_PROGRESS')
    install_ops_key(data)
    backup = Path('/var/lib/gravae-device-client') / ('before-4.0.0-' + str(time.time_ns()))
    backup.mkdir(parents=True, mode=0o700)
    for old in (Path('/etc/gravae/device.json'), Path('/etc/gravae/device-client.json'), Path('/etc/gravae/direct-upload.json'), Path('/etc/gravae/shinobi-upload-hook.json')):
        if old.exists():
            shutil.copy2(old, backup / old.name)
    for folder in ('/opt/gravae-device-client', '/opt/gravae-direct-queue'):
        if Path(folder).exists():
            target = backup / Path(folder).name
            target.mkdir(mode=0o700)
            for old in Path(folder).glob('*.py'):
                shutil.copy2(old, target / old.name)
    if current:
        install_gateway_token(config_file, current, data.get('enrollment'))
    if not current:
        enrollment = data['enrollment']
        if not enrollment.get('deviceGatewayToken'):
            raise InstallError('INSTALL_FAILED')
        text = wg_config(enrollment, data['environment'], Path('/etc/gravae/direct-wireguard.key').read_text())
        wg = Path('/etc/wireguard/wg0.conf')
        # Resume after a crash may reuse only the exact configuration we wrote.
        if wg.exists() and wg.read_text() != text:
            raise InstallError('VPN_CONFIG_CONFLICT')
        atomic(wg, text)
        run(['systemctl', 'enable', '--now', 'wg-quick@wg0'])
    for binary in ('ffmpeg', 'python3', 'wg'):
        if not shutil.which(binary):
            run(['apt-get', 'update'], timeout=300)
            run(['apt-get', 'install', '-y', 'ffmpeg', 'python3-venv', 'wireguard-tools'], timeout=600)
            break
    source = Path(__file__).parent
    client = Path('/opt/gravae-device-client')
    queue = Path('/opt/gravae-direct-queue')
    client.mkdir(parents=True, exist_ok=True)
    queue.mkdir(parents=True, exist_ok=True)
    for name in ('device_gateway_client.py', 'device_readiness.py', 'device_event_outbox.py', 'direct_publisher.py', 'arena_config_sync.py', 'media_mode.py', 'VERSION', 'direct_installer.py'):
        atomic(client / name, (source / name).read_text())
    for name in ('direct_upload_queue.py', 'adaptive_upload.py', 'video_completion_webhook.py', 'confirmed_video_cleanup.py', 'media_mode.py'):
        atomic(queue / name, (source / name).read_text())
    python = client / 'venv/bin/python'
    if not python.exists():
        run(['apt-get', 'install', '-y', 'python3-venv'], timeout=600)
        run(['python3', '-m', 'venv', str(client / 'venv')])
    try:
        run([str(python), '-c', 'import socketio, websocket'])
    except InstallError:
        run([str(python), '-m', 'pip', 'install', 'python-socketio[client]==5.13.0'], timeout=600)
    group = data['groupKey']
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', group):
        raise InstallError('CAMERA_MAPPING_REQUIRED')
    if not current:
        queue_dir = '/var/lib/gravae-direct-managed'
        current = {'deviceId': data['deviceId'], 'arenaId': data['arenaId'], 'environment': data['environment'], 'deviceToken': data['enrollment']['deviceGatewayToken'], 'gatewayUrl': data['gatewayUrl'], 'stateDir': '/var/lib/gravae-device-client', 'queueStatusFile': queue_dir + '/status.json', 'liveActiveFile': '/run/gravae-live.active', 'publisherHosts': data.get('publisherHosts', []), 'monitors': {m['monitorId']: {'hlsManifest': f'/dev/shm/streams/{group}/{m["monitorId"]}/s.m3u8'} for m in monitors}}
        atomic(config_file, json.dumps(current))
    upload = Path('/etc/gravae/direct-upload.json')
    if not upload.exists():
        queue_dir = str(Path(current['queueStatusFile']).parent)
        cfg = {'arenaId': data['arenaId'], 'deviceId': data['deviceId'], 'backendUrl': data['backendUrl'], 'deviceClientConfig': str(config_file), 'uploadsEnabled': True, 'queueDir': queue_dir, 'collectSince': time.time(), 'groupKey': group, 'cameraBindings': {m['monitorId']: {'blockSlug': m['blockSlug'], 'cameraSlug': m['cameraSlug']} for m in monitors}, 'watchDirectories': {m['monitorId']: f'/home/Shinobi/videos/{group}/{m["monitorId"]}' for m in monitors}, 'settleSeconds': 30, 'uploadBytesPerSecond': 262144, 'liveActiveFile': '/run/gravae-live.active', 'maxBytes': 1073741824, 'minFreeBytes': 2147483648}
        atomic(upload, json.dumps(cfg))
    else:
        cfg = read(upload)
        if media_identity(cfg) != data['deviceId'] or cfg.get('arenaId') != data['arenaId'] or cfg.get('backendUrl', '').rstrip('/') != data['backendUrl'].rstrip('/'):
            raise InstallError('IDENTITY_MISMATCH')
    if configure_v4(data, current, cfg, source):
        reload_http_agent()
    for path in (current['stateDir'], str(Path(current['queueStatusFile']).parent)):
        Path(path).mkdir(parents=True, exist_ok=True)
    for service in ('gravae-device-client.service', 'gravae-direct-queue.service'):
        atomic('/etc/systemd/system/' + service, (source / service).read_text().replace('staging ', ''))
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'gravae-device-client', 'gravae-direct-queue'])
    if Path('/run/gravae-live.active').exists():
        raise InstallError('LIVE_IN_PROGRESS')
    run(['systemctl', 'restart', 'gravae-device-client', 'gravae-direct-queue'])
    activate_hook()
    run(['systemctl', 'enable', '--now', 'gravae-confirmed-video-cleanup.timer'])
    harden(data)
    return {'installed': True}

def harden(data):
    """Limit SSH/HLS to VPN with a timed, local recovery of our own changes."""
    ip = ipaddress.ip_address(data['vpnIp'])
    base = {'staging': '10.89', 'prod': '10.88', 'replayme': '10.90'}[data['environment']]
    if ip not in ipaddress.ip_network(base + '.0.0/16'):
        raise InstallError('VPN_CONFIG_CONFLICT')
    if subprocess.run(['systemctl', 'is-active', 'gravae-private-services'], capture_output=True).returncode == 0:
        return  # Preserve the established pilot policy; verify independently below.
    if not shutil.which('nft'):
        run(['apt-get', 'install', '-y', 'nftables'], timeout=600)
    dropin = Path('/etc/ssh/sshd_config.d/90-gravae-direct.conf')
    root = Path('/etc/gravae/direct-hardening')
    root.mkdir(parents=True, exist_ok=True)
    # Do not refresh the rollback baseline on a retry.
    ssh_unit = Path('/etc/systemd/system/ssh.service.d/90-gravae-direct.conf')
    snapshot = root / 'baseline.json'
    if not snapshot.exists():
        atomic(snapshot, json.dumps({'ssh': dropin.read_text() if dropin.exists() else None, 'unit': ssh_unit.read_text() if ssh_unit.exists() else None}))
    rollback = """import json, pathlib, subprocess
root = pathlib.Path('/etc/gravae/direct-hardening')
old = json.loads((root / 'baseline.json').read_text())['ssh']
p = pathlib.Path('/etc/ssh/sshd_config.d/90-gravae-direct.conf')
if old is None: p.unlink(missing_ok=True)
else: p.write_text(old)
subprocess.run(['systemctl', 'disable', '--now', 'gravae-direct-private'], capture_output=True)
subprocess.run(['nft', 'delete', 'table', 'inet', 'gravae_direct_managed'], capture_output=True)
unit = json.loads((root / 'baseline.json').read_text()).get('unit')
p = pathlib.Path('/etc/systemd/system/ssh.service.d/90-gravae-direct.conf')
if unit is None: p.unlink(missing_ok=True)
else: p.write_text(unit)
subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
subprocess.run(['systemctl', 'restart', 'ssh'], capture_output=True)
"""
    atomic(root / 'rollback.py', rollback)
    subprocess.run(['systemctl', 'stop', 'gravae-direct-rollback.timer'], capture_output=True)
    run(['systemd-run', '--unit=gravae-direct-rollback', '--on-active=5m', '/usr/bin/python3', str(root / 'rollback.py')])
    rules = f"""table inet gravae_direct_managed {{
 chain input {{
  type filter hook input priority -10; policy accept;
  iifname "lo" accept
  iifname "wg0" ip saddr {{ {base}.0.1, {base}.20.0/24 }} tcp dport 22 accept
  iifname "wg0" ip saddr {{ {base}.0.1, {base}.10.0/24 }} tcp dport 8080 accept
  tcp dport {{ 22, 8080 }} drop
 }}
}}
"""
    atomic(root / 'firewall.nft', rules)
    run(['nft', '-c', '-f', str(root / 'firewall.nft')])
    # An isolated table avoids flushing any existing firewall rules.
    subprocess.run(['nft', 'delete', 'table', 'inet', 'gravae_direct_managed'], capture_output=True)
    unit = f"""[Unit]
Description=Gravae private SSH and Shinobi
After=wg-quick@wg0.service
Wants=wg-quick@wg0.service
Before=ssh.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f {root}/firewall.nft
ExecStop=-/usr/sbin/nft delete table inet gravae_direct_managed
[Install]
WantedBy=multi-user.target
"""
    atomic('/etc/systemd/system/gravae-direct-private.service', unit)
    atomic(dropin, f'ListenAddress {ip}:22\nListenAddress 127.0.0.1:22\n')
    run(['sshd', '-t'])
    # Explicit ListenAddress elsewhere would keep a public listener: rollback and block.
    listeners = [line.split(' ', 1)[1] for line in run(['sshd', '-T']).splitlines() if line.startswith('listenaddress ')]
    if set(listeners) != {str(ip) + ':22', '127.0.0.1:22'}:
        run(['python3', str(root / 'rollback.py')])
        raise InstallError('PRIVATE_ACCESS_REQUIRED')
    atomic('/etc/systemd/system/ssh.service.d/90-gravae-direct.conf', '[Unit]\nAfter=wg-quick@wg0.service gravae-direct-private.service\nWants=wg-quick@wg0.service gravae-direct-private.service\nStartLimitIntervalSec=0\n[Service]\nRestart=on-failure\nRestartSec=5\n')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'gravae-direct-private'])
    run(['systemctl', 'restart', 'ssh'])


def verify(data):
    identity(data['serial'])
    config = read('/etc/gravae/device-client.json')
    if media_identity(config) != data['deviceId'] or config.get('arenaId') != data['arenaId']:
        raise InstallError('IDENTITY_MISMATCH')
    check_shinobi(data)
    inventory = monitor_inventory(data)
    status = read(Path(config['stateDir']) / 'status.json')
    at = datetime.datetime.fromisoformat(status['checkedAt'].replace('Z', '+00:00')).timestamp()
    ready = status.get('eventsPending') == 0 and status.get('status') == 'READY' and 0 <= time.time() - at < 45
    checks = {key: value for key, value in status.items() if key.endswith('Ready') or key.startswith('hlsReady:')}
    for m in data['monitors']:
        ready = ready and checks.get('hlsReady:' + m['monitorId']) is True
    services = all(run(['systemctl', 'is-active', s]) == 'active' for s in ('gravae-device-client', 'gravae-direct-queue'))
    # No automatic claim of full migration until private exposure is hardened.
    ssh = run(['ss', '-H', '-ltn', 'sport = :22'])
    ssh_private = bool(ssh) and any(data['vpnIp'] + ':22' in line for line in ssh.splitlines()) and all(any(address in line for address in (data['vpnIp'] + ':22', '127.0.0.1:22', '[::1]:22')) for line in ssh.splitlines())
    firewall = any(subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True).returncode == 0 for unit in ('gravae-private-services', 'gravae-direct-private'))
    if ready and services and ssh_private and firewall:
        subprocess.run(['systemctl', 'stop', 'gravae-direct-rollback.timer'], capture_output=True)
    return {'ready': bool(ready and services and ssh_private and firewall and bool(re.fullmatch(r'4\.\d+\.\d+', str(status.get('agentVersion', ''))))), 'monitors': inventory, 'agentVersion': status.get('agentVersion'), 'checks': checks, 'privateAccessReady': bool(ssh_private and firewall), 'publisherConfigured': all(m.get('rtspUrl') for m in config.get('monitors', {}).values()), 'eventsReady': status.get('eventsPending') == 0}


def set_mode(data):
    identity(data['serial'])
    config = read('/etc/gravae/device-client.json')
    if media_identity(config) != data['deviceId'] or config.get('arenaId') != data['arenaId']:
        raise InstallError('IDENTITY_MISMATCH')
    if data.get('mode') not in ('DIRECT', 'LEGACY'):
        raise InstallError('MODE_NOT_CONFIRMED')
    now = time.time()
    atomic('/var/lib/gravae-device-client/media-mode.json', json.dumps({'mode': data['mode'], 'mediaDeviceId': data['deviceId'], 'arenaId': data['arenaId'], 'confirmedAt': now, 'expiresAt': now + 120}))
    return {'mode': data['mode']}

def network(data):
    from pilot_network import transact, public_result
    operation = data.pop('operation', None)
    try:
        return public_result(transact(operation, data))
    except ValueError as exc:
        raise InstallError(str(exc) if re.fullmatch(r'[A-Z_]{1,80}', str(exc)) else 'INVALID_NETWORK_REQUEST')

def buttons(data):
    from pilot_buttons import execute
    try:
        return execute(data)
    except ValueError as exc:
        raise InstallError(str(exc) if re.fullmatch(r'[A-Z_]{1,80}', str(exc)) else 'INVALID_BUTTON_REQUEST')

if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            raise InstallError('INSTALL_FAILED')
        with open('/run/gravae-direct-installer.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            data = json.load(sys.stdin)
            result = {'prepare': prepare, 'install': install, 'verify': verify, 'set-mode': set_mode, 'update-agent': update_agent, 'network': network, 'buttons': buttons}[sys.argv[1]](data)
            print(json.dumps(result))
    except Exception as exc:
        print(json.dumps({'errorCode': str(exc) if isinstance(exc, InstallError) else 'INSTALL_FAILED'}))
        sys.exit(1)
