"""
Ultra Watch (Modo Observação) — módulo orquestrado pelo gravae_agent.

Loop de alta frequência (default 45s) que, quando ATIVO, manda heartbeat pro OPS
e roda checks; cada anomalia vira um POST /report (autenticado por HMAC com o
segredo por-device). Estado persiste em /etc/gravae/observation.json (sobrevive a
restart). NUNCA mexe em rede/reboot.

Fase 1: heartbeat + service_down + press_without_video.
"""
import os
import re
import json
import time
import hmac
import hashlib
import threading
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

STATE_PATH = "/etc/gravae/observation.json"
DEFAULT_INTERVAL = 45
OBS_VERSION = "1.0.0"

_state = {}
_thread = None
_stop = threading.Event()
_lock = threading.Lock()
_consecutive = {}  # dedupKey -> ciclos consecutivos


def _log(msg):
    print(f"[ultra-watch] {msg}", flush=True)


def load_state():
    global _state
    try:
        with open(STATE_PATH) as f:
            _state = json.load(f)
    except Exception:
        _state = {}
    return _state


def save_state():
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_state, f)
        os.replace(tmp, STATE_PATH)
    except Exception as e:
        _log(f"save_state falhou: {e}")


def _sign(secret, raw):
    return hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()


def _post(path, obj, serial, secret, ops):
    raw = json.dumps(obj)
    sig = _sign(secret, raw)
    req = urllib.request.Request(
        ops.rstrip("/") + path,
        data=raw.encode(),
        headers={
            "content-type": "application/json",
            "x-obs-serial": serial,
            "x-obs-signature": sig,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        _log(f"POST {path} HTTP {e.code}")
    except Exception as e:
        _log(f"POST {path} erro: {e}")
    return None


def _local_get(path):
    try:
        with urllib.request.urlopen("http://localhost:8888" + path, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def get_serial():
    try:
        with open("/etc/gravae/device.json") as f:
            d = json.load(f)
            if d.get("deviceSerial"):
                return d["deviceSerial"]
    except Exception:
        pass
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("Serial"):
                return line.split(":")[1].strip()
    except Exception:
        pass
    return "unknown"


# ---------------------------------------------------------------- checks
def check_service_down():
    out = []
    st = _local_get("/phoenix/status")
    if not st:
        return out
    services = st.get("services", {}) or {}
    for name, ok in services.items():
        if ok is False:
            out.append({
                "type": "service_down",
                "severity": "critical",
                "detail": f"serviço {name} caído",
                "evidence": {"service": name},
                "dedupKey": f"service_down:{name}",
            })
    return out


_PRESS_RE = re.compile(r"\[PRESS\]\s+\S+\s+-\s+GPIO(\d+)\s+-\s+(\S+)")


def _recent_presses(minutes=3):
    """{monitor_name: last_press_epoch} pelos logs [PRESS] do journald."""
    out = {}
    try:
        res = subprocess.run(
            ["journalctl", "-u", "gravae-buttons", "--since", f"-{minutes} min", "-o", "short-unix", "--no-pager"],
            capture_output=True, text=True, timeout=15,
        )
        for line in res.stdout.splitlines():
            m = _PRESS_RE.search(line)
            if not m:
                continue
            try:
                ts = float(line.split()[0])
            except Exception:
                continue
            mon = m.group(2)
            out[mon] = max(out.get(mon, 0), ts)
    except Exception:
        pass
    return out


def check_press_without_video(tolerance=20):
    """Aperto ([PRESS] no journald) sem vídeo/evento correspondente no Shinobi
    (detector travado). Reconcilia com os eventos de /phoenix/monitors."""
    out = []
    presses = _recent_presses(3)
    if not presses:
        return out
    mons = _local_get("/phoenix/monitors")
    if not mons:
        return out
    last_event = {}
    for mo in (mons.get("monitors", []) or []):
        name = mo.get("name")
        evs = mo.get("events", []) or []
        if name and evs and evs[0].get("time"):
            try:
                t = datetime.fromisoformat(str(evs[0]["time"]).replace("Z", "+00:00")).timestamp()
                last_event[name] = t
            except Exception:
                pass
    for mon, ptime in presses.items():
        ev = last_event.get(mon, 0)
        if ptime - ev > tolerance:
            out.append({
                "type": "press_without_video",
                "severity": "high",
                "detail": f"aperto em {mon} sem vídeo/evento correspondente",
                "evidence": {"monitor": mon, "pressTs": ptime, "lastEventTs": ev, "matchedEvent": False},
                "dedupKey": f"press_without_video:{mon}",
            })
    return out


# ---------------------------------------------------------------- loop
def _cycle():
    serial = get_serial()
    secret = _state.get("secret")
    ops = _state.get("opsUrl")
    if not secret or not ops:
        return
    _post("/api/observation/heartbeat", {"ts": time.time(), "obsVersion": OBS_VERSION}, serial, secret, ops)
    found = []
    for fn in (check_service_down, check_press_without_video):
        try:
            found.extend(fn())
        except Exception as e:
            _log(f"check {fn.__name__} erro: {e}")
    seen = set()
    for a in found:
        dk = a["dedupKey"]
        seen.add(dk)
        _consecutive[dk] = _consecutive.get(dk, 0) + 1
        a["consecutiveCount"] = _consecutive[dk]
        a["firstSeenAt"] = datetime.now(timezone.utc).isoformat()
        _post("/api/observation/report", a, serial, secret, ops)
    for dk in list(_consecutive):
        if dk not in seen:
            del _consecutive[dk]


def _loop():
    while not _stop.is_set():
        interval = int(_state.get("interval") or DEFAULT_INTERVAL)
        until = _state.get("until")
        if until:
            try:
                if datetime.fromisoformat(str(until).replace("Z", "+00:00")) < datetime.now(timezone.utc):
                    _log("observationUntil expirou — desligando")
                    disable()
                    return
            except Exception:
                pass
        try:
            _cycle()
        except Exception as e:
            _log(f"cycle erro: {e}")
        _stop.wait(interval)


def enable(secret, ops_url, interval=DEFAULT_INTERVAL, until=None):
    global _thread, _state
    with _lock:
        _state = {"enabled": True, "secret": secret, "opsUrl": ops_url, "interval": int(interval or DEFAULT_INTERVAL), "until": until}
        save_state()
        _stop.clear()
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_loop, daemon=True)
            _thread.start()
    _log(f"ativado (interval={interval}s, until={until})")
    return True


def disable():
    global _state
    with _lock:
        _state = {"enabled": False}
        save_state()
        _stop.set()
    _log("desativado")
    return True


def resume_if_enabled():
    load_state()
    if _state.get("enabled") and _state.get("secret") and _state.get("opsUrl"):
        enable(_state["secret"], _state["opsUrl"], int(_state.get("interval") or DEFAULT_INTERVAL), _state.get("until"))
        return True
    return False


def status():
    return {
        "enabled": bool(_state.get("enabled")),
        "interval": _state.get("interval"),
        "until": _state.get("until"),
        "running": _thread is not None and _thread.is_alive(),
        "obsVersion": OBS_VERSION,
    }
