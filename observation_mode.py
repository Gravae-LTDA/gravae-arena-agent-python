"""
Ultra Watch (Modo Observação) — módulo orquestrado pelo gravae_agent.

Loop de alta frequência (default 45s) que, quando ATIVO, manda heartbeat pro OPS
e roda checks locais baratos (Pi 3B friendly); cada anomalia vira um POST /report
(autenticado por HMAC com o segredo por-device). Estado persiste em
/etc/gravae/observation.json (sobrevive a restart). NUNCA mexe em rede/reboot.

Fase 1: heartbeat + service_down + press_without_video.
Fase 2: monitor_died + camera_frozen + gpio_idle_24h + gpio_stuck.
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
DEVICE_PATH = "/etc/gravae/device.json"
DEFAULT_INTERVAL = 45
OBS_VERSION = "1.2.0"
PM2_HOME = "/root/.pm2"

# Fase 2 — parâmetros dos checks (conservadores p/ evitar falso-positivo).
SNAP_EVERY = 6            # reamostra snapshot a cada N ciclos (~4.5min @ 45s)
FROZEN_SAMPLES = 3        # nº de amostras idênticas seguidas p/ "congelado" (~13min)
GPIO_STUCK_PER_3MIN = 40  # apertos no mesmo GPIO em 3min ⇒ botão preso/bouncing
IDLE_HOURS = 24           # botão sem aperto há mais que isto...
ACTIVE_RECENT_HOURS = 2   # ...enquanto a arena teve aperto nas últimas 2h

# Watchdog (auto-heal) — só age com Ultra Watch ATIVO. Remédio do no-record
# silencioso (aperto 200 mas 0 evento/vídeo): pm2 restart camera. Conservador —
# exige que press_without_video persista por vários ciclos + cooldown longo.
AUTOHEAL_PRESS_WITHOUT_VIDEO = True
AUTOHEAL_MIN_CONSECUTIVE = 2   # ciclos seguidos de press_without_video antes de agir (~90s @ 45s)
AUTOHEAL_COOLDOWN = 900        # segundos entre restarts de camera (evita loop; ~70s p/ re-armar)

_state = {}
_thread = None
_stop = threading.Event()
_lock = threading.Lock()
_consecutive = {}   # dedupKey -> ciclos consecutivos
_snap = {}          # mid -> {"hash": str, "identical": int}
_cyc = 0            # contador de ciclos
_last_autoheal = 0.0  # epoch do último pm2 restart camera do watchdog


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
        with open(DEVICE_PATH) as f:
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


def _shinobi_creds():
    try:
        with open(DEVICE_PATH) as f:
            d = json.load(f)
        return d.get("shinobiApiKey"), d.get("shinobiGroupKey")
    except Exception:
        return None, None


# ---------------------------------------------------------------- presses
_PRESS_RE = re.compile(r"\[PRESS\]\s+\S+\s+-\s+GPIO(\d+)\s+-\s+(\S+)")


def _recent_presses(minutes=3):
    """{monitor_name: {"last": epoch, "count": n}} pelos logs [PRESS] do journald."""
    out = {}
    try:
        res = subprocess.run(
            ["journalctl", "-u", "gravae-buttons", "--since", f"-{minutes} min",
             "-o", "short-unix", "--no-pager"],
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
            rec = out.setdefault(mon, {"last": 0.0, "count": 0})
            rec["last"] = max(rec["last"], ts)
            rec["count"] += 1
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- checks
def check_service_down():
    out = []
    st = _local_get("/phoenix/status")
    if not st:
        return out
    for name, ok in (st.get("services", {}) or {}).items():
        if ok is False:
            out.append({
                "type": "service_down", "severity": "critical",
                "detail": f"serviço {name} caído",
                "evidence": {"service": name},
                "dedupKey": f"service_down:{name}",
            })
    return out


def check_press_without_video(presses, tolerance=20):
    """Aperto ([PRESS] no journald) sem vídeo/evento correspondente no Shinobi
    (detector travado). Reconcilia com os eventos de /phoenix/monitors."""
    out = []
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
    for mon, rec in presses.items():
        ptime = rec["last"]
        ev = last_event.get(mon, 0)
        if ptime - ev > tolerance:
            out.append({
                "type": "press_without_video", "severity": "high",
                "detail": f"aperto em {mon} sem vídeo/evento correspondente",
                "evidence": {"monitor": mon, "pressTs": ptime, "lastEventTs": ev, "matchedEvent": False},
                "dedupKey": f"press_without_video:{mon}",
            })
    return out


def check_monitor_died():
    """Monitor Shinobi que deveria estar gravando (mode=start) mas morreu."""
    out = []
    mons = _local_get("/phoenix/monitors")
    if not mons:
        return out
    for mo in (mons.get("monitors", []) or []):
        if mo.get("mode") == "start" and str(mo.get("status", "")).lower() in ("died", "failed", "error"):
            out.append({
                "type": "monitor_died", "severity": "critical",
                "detail": f"câmera {mo.get('name')} caiu (status={mo.get('status')})",
                "evidence": {"mid": mo.get("mid"), "monitor": mo.get("name"), "status": mo.get("status")},
                "dedupKey": f"monitor_died:{mo.get('mid')}",
            })
    return out


def _snapshot(mid, api, gk):
    url = f"http://127.0.0.1:8080/{api}/jpeg/{gk}/{mid}/s.jpg"
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            return r.read()
    except Exception:
        return None


def check_camera_frozen():
    """Stream congelado: mesmo frame por várias amostras seguidas. Reamostra o
    snapshot a cada SNAP_EVERY ciclos; entre amostras mantém o veredito (pra
    acumular consecutiveCount). Conservador (~13min de frame idêntico)."""
    out = []
    api, gk = _shinobi_creds()
    if not api or not gk:
        return out
    mons = _local_get("/phoenix/monitors")
    if not mons:
        return out
    online = [mo for mo in (mons.get("monitors", []) or []) if mo.get("isOnline")]
    sample = (_cyc % SNAP_EVERY == 0)
    for mo in online:
        mid = mo.get("mid")
        if not mid:
            continue
        st = _snap.setdefault(mid, {"hash": None, "identical": 0})
        if sample:
            img = _snapshot(mid, api, gk)
            if img:
                h = hashlib.md5(img).hexdigest()
                st["identical"] = st["identical"] + 1 if st["hash"] == h else 0
                st["hash"] = h
        if st["identical"] >= FROZEN_SAMPLES:
            out.append({
                "type": "camera_frozen", "severity": "high",
                "detail": f"câmera {mo.get('name')} possivelmente congelada (frame idêntico)",
                "evidence": {"mid": mid, "monitor": mo.get("name"), "identicalSamples": st["identical"]},
                "dedupKey": f"camera_frozen:{mid}",
            })
    # limpa estado de monitores que saíram do ar
    alive = {mo.get("mid") for mo in online}
    for mid in list(_snap):
        if mid not in alive:
            del _snap[mid]
    return out


def check_gpio_stuck(presses):
    """Rajada implausível de apertos no mesmo GPIO = botão preso/bouncing."""
    out = []
    for mon, rec in (presses or {}).items():
        if rec["count"] >= GPIO_STUCK_PER_3MIN:
            out.append({
                "type": "gpio_stuck", "severity": "high",
                "detail": f"botão {mon} com {rec['count']} apertos em 3min (preso/bouncing?)",
                "evidence": {"monitor": mon, "pressesIn3min": rec["count"]},
                "dedupKey": f"gpio_stuck:{mon}",
            })
    return out


def check_gpio_idle_24h():
    """Botão conhecido sem aperto há >24h enquanto a arena está ativa (aperto nas
    últimas 2h em outro botão) = provável problema físico. Usa lastPress persistido."""
    out = []
    last = _state.get("lastPress") or {}
    if not last:
        return out
    now = time.time()
    arena_active = any((now - float(ts)) < ACTIVE_RECENT_HOURS * 3600 for ts in last.values())
    if not arena_active:
        return out
    for mon, ts in last.items():
        hours = (now - float(ts)) / 3600.0
        if hours >= IDLE_HOURS:
            out.append({
                "type": "gpio_idle_24h", "severity": "medium",
                "detail": f"botão {mon} sem aperto há {int(hours)}h (arena ativa)",
                "evidence": {"monitor": mon, "hoursSincePress": round(hours, 1)},
                "dedupKey": f"gpio_idle_24h:{mon}",
            })
    return out


# ---------------------------------------------------------------- watchdog
def _restart_camera():
    """pm2 restart camera — mesmo remédio manual do no-record silencioso.
    Roda como root (agent), PM2_HOME=/root/.pm2 (igual ao _restart_shinobi do agent)."""
    env = {**os.environ, "PM2_HOME": PM2_HOME, "HOME": "/root"}
    for name in ("camera", "Shinobi", "shinobi"):
        try:
            r = subprocess.run(["pm2", "restart", name], capture_output=True,
                               text=True, timeout=30, env=env)
            if r.returncode == 0:
                _log(f"auto-heal: pm2 restart {name} ok")
                return True
        except Exception as e:
            _log(f"auto-heal: pm2 restart {name} erro: {e}")
    _log("auto-heal: pm2 restart camera falhou (todos os nomes)")
    return False


def _maybe_autoheal(found, serial, secret, ops):
    """Watchdog: se press_without_video persistir por >=AUTOHEAL_MIN_CONSECUTIVE
    ciclos, dá pm2 restart camera (com cooldown). É o único remédio que recupera o
    no-record silencioso (stop/start por monitor não resolve — só processo novo).
    Cobre Pis ainda não atualizados p/ o fix de raiz (motion_lock) e bordas raras."""
    global _last_autoheal
    if not AUTOHEAL_PRESS_WITHOUT_VIDEO:
        return
    pwv = [a for a in found
           if a.get("type") == "press_without_video"
           and a.get("consecutiveCount", 0) >= AUTOHEAL_MIN_CONSECUTIVE]
    if not pwv:
        return
    now = time.time()
    if now - _last_autoheal < AUTOHEAL_COOLDOWN:
        _log(f"auto-heal: press_without_video persistente mas em cooldown "
             f"({int(AUTOHEAL_COOLDOWN - (now - _last_autoheal))}s restantes)")
        return
    monitors = sorted({(a.get("evidence") or {}).get("monitor") for a in pwv} - {None})
    _log(f"auto-heal: press_without_video persistente em {monitors} -> pm2 restart camera")
    ok = _restart_camera()
    _last_autoheal = now
    # zera os contadores dos monitores afetados p/ dar tempo de re-armar antes de recontar
    for a in pwv:
        _consecutive.pop(a.get("dedupKey"), None)
    # reporta a ação pro OPS (visibilidade — vira anomalia resolvida/ação no painel)
    _post("/api/observation/report", {
        "type": "autoheal_camera_restart", "severity": "high",
        "detail": f"auto-heal (Ultra Watch): pm2 restart camera por press_without_video em {', '.join(monitors)}",
        "evidence": {"monitors": monitors, "restarted": ok, "reason": "press_without_video"},
        "dedupKey": "autoheal_camera_restart",
        "consecutiveCount": 1,
        "firstSeenAt": datetime.now(timezone.utc).isoformat(),
    }, serial, secret, ops)


# ---------------------------------------------------------------- loop
def _cycle():
    global _cyc
    _cyc += 1
    serial = get_serial()
    secret = _state.get("secret")
    ops = _state.get("opsUrl")
    if not secret or not ops:
        return

    _post("/api/observation/heartbeat", {"ts": time.time(), "obsVersion": OBS_VERSION}, serial, secret, ops)

    # apertos recentes (3min) — alimenta press_without_video, gpio_stuck e o
    # lastPress persistido (base do gpio_idle_24h).
    presses = _recent_presses(3)
    if presses:
        lp = _state.setdefault("lastPress", {})
        changed = False
        for mon, rec in presses.items():
            if rec["last"] > float(lp.get(mon, 0)):
                lp[mon] = rec["last"]
                changed = True
        if changed:
            save_state()

    found = []
    for fn, args in (
        (check_service_down, ()),
        (check_press_without_video, (presses,)),
        (check_monitor_died, ()),
        (check_camera_frozen, ()),
        (check_gpio_stuck, (presses,)),
        (check_gpio_idle_24h, ()),
    ):
        try:
            found.extend(fn(*args))
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

    # Watchdog: auto-cura do no-record silencioso (só com Ultra Watch ativo, que é
    # a condição p/ estarmos neste loop). pm2 restart camera se press_without_video
    # persistir. `found` já traz consecutiveCount setado acima.
    try:
        _maybe_autoheal(found, serial, secret, ops)
    except Exception as e:
        _log(f"auto-heal erro: {e}")


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
        prev_lp = _state.get("lastPress", {}) if _state.get("enabled") else {}
        _state = {"enabled": True, "secret": secret, "opsUrl": ops_url,
                  "interval": int(interval or DEFAULT_INTERVAL), "until": until,
                  "lastPress": prev_lp}
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
