#!/usr/bin/env python3
"""Controlled API-only upgrade. Run on the authorized pilot as root.

Usage: upgrade-pilot-api.py ARCHIVE SHA256
Does not install the DIRECT stack, change credentials, or run install.sh.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

SERIAL = '10000000a8917a01'
FILES = {'gravae_agent.py', 'observation_mode.py', 'hands_up_module.py', 'VERSION'}
ROOT = Path('/opt/gravae-agent')
CPUINFO = Path('/proc/cpuinfo')
BACKUPS = Path('/var/backups/gravae-api')
OBSERVATION = Path('/etc/gravae/observation.json')
DROPIN = Path('/etc/systemd/system/gravae-agent.service.d/90-controlled-startup.conf')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30).stdout.strip()


def snapshot():
    services = {s: run('systemctl', 'show', s, '-p', 'MainPID', '--value') for s in (
        'gravae-device-client.service', 'gravae-direct-queue.service')}
    media = []
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            name = (proc / 'comm').read_text().strip()
            if name in ('node', 'ffmpeg'):
                group = (proc / 'cgroup').read_text()
                if '/gravae-agent.service' in group:
                    raise RuntimeError('Media shares the agent cgroup; cannot restart safely')
                media.append({'pid': int(proc.name), 'name': name})
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return {'services': services, 'media': sorted(media, key=lambda p: p['pid'])}


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Root required')
    serial = next((line.split(':', 1)[1].strip() for line in CPUINFO.read_text().splitlines() if line.startswith('Serial')), '')
    if serial != SERIAL:
        raise RuntimeError('PILOT_ONLY')
    payload = Path(sys.argv[1]).read_bytes()
    if hashlib.sha256(payload).hexdigest() != sys.argv[2]:
        raise RuntimeError('Archive hash mismatch')
    before = snapshot()
    # Avoid implicitly enabling an existing observation/coaching worker on this pilot.
    observation = OBSERVATION
    if observation.exists() and json.loads(observation.read_text()).get('enabled'):
        raise RuntimeError('Active observation requires a separate migration')
    with tempfile.TemporaryDirectory(prefix='gravae-api-stage-') as tmp:
        stage = Path(tmp)
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
            if {m.name for m in archive.getmembers()} != FILES or len(archive.getmembers()) != len(FILES):
                raise RuntimeError('Unexpected archive files')
            for member in archive:
                if not member.isfile():
                    raise RuntimeError('Only regular files are permitted')
                (stage / member.name).write_bytes(archive.extractfile(member).read())
        if (stage / 'VERSION').read_text().strip() != '4.0.4':
            raise RuntimeError('Unexpected version')
        for file in stage.glob('*.py'):
            py_compile.compile(str(file), doraise=True)
        backup = BACKUPS / str(int(time.time()))
        backup.mkdir(parents=True, mode=0o700)
        manifest = []
        for target in [*(ROOT / f for f in sorted(FILES)), DROPIN]:
            saved = backup / str(len(manifest))
            if target.exists():
                shutil.copy2(target, saved)
            manifest.append({'path': str(target), 'backup': str(saved) if target.exists() else None})
        (backup / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        (backup / 'before.json').write_text(json.dumps(before, indent=2))
        try:
            for file in FILES:
                target = ROOT / file
                temp = target.with_suffix(target.suffix + '.upgrade')
                shutil.copy2(stage / file, temp)
                temp.chmod(0o644)
                os.replace(temp, target)
            DROPIN.parent.mkdir(parents=True, exist_ok=True)
            DROPIN.write_text('[Service]\nEnvironment=GRAVAE_STARTUP_REPAIRS=disabled\n')
            run('systemctl', 'daemon-reload')
            run('systemctl', 'restart', 'gravae-agent.service')
            version = None
            for _ in range(20):
                try:
                    with urllib.request.urlopen('http://127.0.0.1:8888/update/version', timeout=2) as response:
                        version = json.load(response).get('version')
                    if version == '4.0.4':
                        break
                except Exception:
                    pass
                time.sleep(1)
            if version != '4.0.4':
                raise RuntimeError('New API did not become healthy')
        except Exception:
            for item in manifest:
                target = Path(item['path'])
                if item['backup']:
                    shutil.copy2(item['backup'], target)
                elif target.exists():
                    target.unlink()
            run('systemctl', 'daemon-reload')
            run('systemctl', 'restart', 'gravae-agent.service')
            raise
        after = snapshot()
        print(json.dumps({'version': version, 'backup': str(backup), 'before': before, 'after': after,
                          'directServicesUnchanged': before['services'] == after['services'],
                          'mediaProcessesUnchanged': before['media'] == after['media']}))

if __name__ == '__main__':
    main()
