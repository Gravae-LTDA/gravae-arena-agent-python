"""
Ultra Watch (Modo Observação) — módulo orquestrado pelo gravae_agent.

Loop de alta frequência (default 45s) que, quando ATIVO, manda heartbeat pro OPS
e roda checks locais baratos (Pi 3B friendly); cada anomalia vira um POST /report
(autenticado por HMAC com o segredo por-device). Estado persiste em
/etc/gravae/observation.json (sobrevive a restart). NUNCA mexe em rede/reboot.

Fase 1: heartbeat + service_down + press_without_video.
Fase 2: monitor_died + camera_frozen + gpio_idle_24h + gpio_stuck.
Fase 4: high_memory + ffmpeg_memory_leak (antecipa o OOM que trava a Pi).
2.0: modo fixo (sem prazo), snapshot de saúde no heartbeat, "caixa preta" do
journald enviada ao OPS (com spool em disco quando a Pi está sem internet) e
checks de hardware/serviços (subtensão, temperatura, disco, SD, OOM, NTP, DNS,
túnel, MariaDB, botões). Checks antigos agora confirmam antes de reportar.
"""
import os
import re
import json
import time
import hmac
import hashlib
import socket
import threading
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

STATE_PATH = "/etc/gravae/observation.json"
DEVICE_PATH = "/etc/gravae/device.json"
DEFAULT_INTERVAL = 45
OBS_VERSION = "2.0.0"
PM2_HOME = "/root/.pm2"

# Fase 2 — parâmetros dos checks (conservadores p/ evitar falso-positivo).
SNAP_EVERY = 6            # reamostra o buffer HLS a cada N ciclos (~4.5min @ 45s)
FROZEN_SAMPLES = 3        # nº de amostras idênticas seguidas p/ "congelado" (~13min)
GPIO_STUCK_PER_3MIN = 40  # apertos no mesmo GPIO em 3min ⇒ botão preso/bouncing
IDLE_HOURS = 24           # botão sem aperto há mais que isto...
ACTIVE_RECENT_HOURS = 2   # ...enquanto a arena teve aperto nas últimas 2h

# Fase 4 — pressão de memória. Motivador: Calçadão Pinheiros (2026-07) travava a
# Pi inteira a cada poucos dias. O OOM killer matava ffmpeg inflados (1-2 GB, o
# normal é ~50 MB) e ~20min depois o kernel travava — só voltava com power-cycle
# físico. Nenhum check existente pegava isso: o Ultra Watch só notava DEPOIS,
# como device_offline. Aqui alertamos ANTES do OOM, com folga pra agir.
MEM_AVAIL_WARN_MB = 700    # RAM disponível abaixo disto ⇒ medium
MEM_AVAIL_CRIT_MB = 350    # ...abaixo disto ⇒ high (OOM iminente)
FFMPEG_RSS_WARN_MB = 600   # um ffmpeg sozinho acima disto já é anômalo
FFMPEG_RSS_CRIT_MB = 900   # nesta faixa o OOM costuma disparar em minutos

# Watchdog (auto-heal) — só age com Ultra Watch ATIVO. Remédio do no-record
# silencioso (aperto 200 mas 0 evento/vídeo): pm2 restart camera. Conservador —
# exige que press_without_video persista por vários ciclos + cooldown longo.
AUTOHEAL_PRESS_WITHOUT_VIDEO = True
AUTOHEAL_MIN_CONSECUTIVE = 2   # ciclos seguidos de press_without_video antes de agir (~90s @ 45s)
AUTOHEAL_COOLDOWN = 900        # segundos entre restarts de camera (evita loop; ~70s p/ re-armar)
AUTOHEAL_SHINOBI_PORT_DEAD = True  # tb reinicia camera se o 8080 do Shinobi estiver morto (pm2 "online" mas porta caída)

# 2.0 — caixa preta (journald → OPS) e checks de hardware.
SPOOL_DIR = "/var/lib/gravae/obs-spool"
SPOOL_MAX_BYTES = 2 * 1024 * 1024     # ring: acima disto descarta os chunks mais antigos
JOURNAL_UNITS = ("gravae-agent", "gravae-phoenix", "gravae-buttons",
                 "gravae-device-client", "cloudflared", "mariadb")
JOURNAL_FETCH_MAX = 2000              # linhas lidas do journald por ciclo
CHUNK_MAX_LINES = 300
MSG_MAX_CHARS = 500
POST_MAX_CHUNKS = 10
POST_MAX_BYTES = 256 * 1024
HB_TIMEOUT = 10                       # heartbeat: 2 tentativas de 10s (não estoura o ciclo)
HB_401_DISABLE = 10                   # OPS recusou 10 heartbeats seguidos ⇒ modo desligado no OPS
TEMP_WARN_C = 75
TEMP_CRIT_C = 80
DISK_CRIT_PCT = 5
DISK_CRIT_MB = 500
DISK_WARN_PCT = 10
CONFIRM_CYCLES = 2                    # estado ruim visto em N ciclos seguidos antes de reportar
NTP_GRACE_SEC = 900                   # NTP leva alguns minutos após o boot
REPROBE_SEC = 5
MODES = ("semana", "fixo")

# Vídeo corrompido. Mesmo layout que o phoenix_daemon (EmptyCutWatchdog /
# PressToVideoAuditor) varre: <base>/<groupKey>/<monitor>/*.mp4.
VIDEO_DIRS = ("/home/Shinobi/videos", "/opt/shinobi/videos")
VIDEO_SETTLE_SEC = 15          # mtime ≥15s ⇒ Shinobi terminou de escrever
VIDEO_LOOKBACK_SEC = 1800      # não sonda arquivo antigo
VIDEO_PROBES_PER_CYCLE = 6     # teto de ffprobe por ciclo (Pi 3B)
VIDEO_SEEN_MAX = 2000          # nomes já sondados (conjunto limitado)
FFPROBE_TIMEOUT = 10
VIDEO_MIN_DURATION = 0.5
_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")

_SD_ERR_RE = re.compile(r"(mmc\d*:.*(error|timeout|stuck|reset)|mmcblk\d.*error|"
                        r"I/O error|EXT4-fs (error|warning)|Buffer I/O error|"
                        r"Remounting filesystem read-only)", re.I)
_OOM_RE = re.compile(r"(Out of memory: Kill|oom-kill:|invoked oom-killer|Killed process \d+)", re.I)

_state = {}
_thread = None
_stop = threading.Event()
_lock = threading.Lock()
_consecutive = {}   # dedupKey -> ciclos consecutivos
_snap = {}          # mid -> {"sig": [seg,size], "identical": int}
_cyc = 0            # contador de ciclos
_last_autoheal = 0.0  # epoch do último pm2 restart camera do watchdog
_local_seen = {}    # chave -> ciclos seguidos em estado ruim (confirmação local)
_prev_throttled = None  # último get_throttled lido (detecta transição do bit 16)
_hb_401 = 0         # heartbeats seguidos recusados com 401
_kernel_lines = []  # linhas do kernel lidas neste ciclo (sd_errors / oom_kill)
_video_seen = {}    # caminho -> None (ordem de inserção = FIFO limitado)
_video_floor = None  # não sonda vídeo anterior ao início da observação
_ffprobe_missing = False
_loaded = False


def _log(msg):
    print(f"[ultra-watch] {msg}", flush=True)


def load_state():
    global _state, _loaded
    _loaded = True
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


def _post_status(path, obj, serial, secret, ops, timeout=20, attempts=3):
    """POST assinado. Devolve (http_status|None, corpo|None). None = rede/DNS."""
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
    last_err = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            if e.code < 500:   # 4xx não adianta retentar
                _log(f"POST {path} HTTP {e.code}")
                return e.code, None
            last_err = f"HTTP {e.code}"
        except Exception as e:
            last_err = str(e)   # DNS/timeout transiente -> retenta
        if attempt + 1 < attempts:
            time.sleep(1 if attempts <= 2 else 2 * (attempt + 1))
    _log(f"POST {path} falhou apos {attempts} tentativa(s): {last_err}")
    return None, None


def _post(path, obj, serial, secret, ops, timeout=20, attempts=3):
    return _post_status(path, obj, serial, secret, ops, timeout, attempts)[1]


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


# ---------------------------------------------------------------- confirmação
def _confirm(key, bad, need=CONFIRM_CYCLES):
    """Conta ciclos seguidos em estado ruim. True só quando visto em `need` ciclos
    seguidos (evita falso positivo de restart/oscilação de segundos)."""
    if not bad:
        _local_seen.pop(key, None)
        return False
    _local_seen[key] = _local_seen.get(key, 0) + 1
    return _local_seen[key] >= need


def _forget_unseen(prefix, keys_seen):
    for k in [k for k in _local_seen if k.startswith(prefix) and k not in keys_seen]:
        del _local_seen[k]


# ---------------------------------------------------------------- checks
def _shinobi_port_ok():
    try:
        req = urllib.request.Request("http://127.0.0.1:8080/", method="GET")
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.status == 200
    except Exception:
        return False


def check_shinobi_8080():
    """Shinobi 8080 morto enquanto o pm2 diz 'online' (hung) — PONTO CEGO do
    check_service_down (que le /phoenix/status, reportado pelo pm2). Bate direto no 8080.
    Re-testa uma vez depois de ~5s: restart do camera.js derruba a porta por segundos."""
    out = []
    if _shinobi_port_ok():
        return out
    time.sleep(REPROBE_SEC)
    if _shinobi_port_ok():
        return out
    out.append({
        "type": "shinobi_port_dead", "severity": "critical",
        "detail": "Shinobi 8080 nao responde (processo pode estar 'online' no pm2 mas travado)",
        "evidence": {"port": 8080, "reprobed": True},
        "dedupKey": "shinobi_port_dead",
    })
    return out


def _down_services():
    st = _local_get("/phoenix/status")
    if not st:
        return None
    return {name for name, ok in (st.get("services", {}) or {}).items() if ok is False}


def check_service_down():
    """Serviço caído segundo o Phoenix. Re-consulta após ~5s e só reporta o que
    continua caído (restart do pm2 aparecia como 'caído' por 1 amostra)."""
    out = []
    down = _down_services()
    if not down:
        return out
    time.sleep(REPROBE_SEC)
    again = _down_services()
    if again is None:
        return out
    for name in sorted(down & again):
        out.append({
            "type": "service_down", "severity": "critical",
            "detail": f"serviço {name} caído",
            "evidence": {"service": name, "reprobed": True},
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
    """Monitor Shinobi que deveria estar gravando (mode=start) mas morreu.
    Só reporta se o status ruim aparece em 2 ciclos seguidos: o Shinobi passa por
    'died' por alguns segundos ao reiniciar o ffmpeg (125 de 310 avisos antigos
    duraram menos de 5 min)."""
    out = []
    mons = _local_get("/phoenix/monitors")
    if not mons:
        return out
    seen = set()
    for mo in (mons.get("monitors", []) or []):
        bad = mo.get("mode") == "start" and str(mo.get("status", "")).lower() in ("died", "failed", "error")
        key = f"monitor_died:{mo.get('mid')}"
        if bad:
            seen.add(key)
        if _confirm(key, bad):
            out.append({
                "type": "monitor_died", "severity": "critical",
                "detail": f"câmera {mo.get('name')} caiu (status={mo.get('status')})",
                "evidence": {"mid": mo.get("mid"), "monitor": mo.get("name"), "status": mo.get("status"),
                             "cyclesSeen": _local_seen.get(key)},
                "dedupKey": key,
            })
    _forget_unseen("monitor_died:", seen)
    return out


# Bases onde o Shinobi escreve o buffer HLS (SIP) — RAM primeiro.
_STREAM_BASES = ("/dev/shm/streams", "/home/Shinobi/streams")


def _stream_dir(gk, mo):
    """Diretório do buffer HLS do monitor. O Shinobi nomeia a pasta pelo NOME do
    monitor (às vezes pelo mid); fica em /dev/shm/streams (RAM) ou
    /home/Shinobi/streams. Legível sem root (dirs 755, .ts 644)."""
    for base in _STREAM_BASES:
        for key in (mo.get("name"), mo.get("mid")):
            if not key:
                continue
            d = os.path.join(base, gk, key)
            if os.path.isdir(d):
                return d
    return None


def _buffer_head(d):
    """Assinatura [nome, tamanho] do segmento .ts mais novo do buffer (None se vazio).
    Enquanto o stream grava, o Shinobi rotaciona segmentos (~1-2s cada), então essa
    assinatura muda a cada amostra; se o stream trava, o segmento mais novo para de
    renovar (mesmo nome e tamanho). Sem decodificar frame."""
    try:
        segs = [f for f in os.listdir(d) if f.endswith(".ts")]
        if not segs:
            return None
        newest = max(segs, key=lambda f: os.path.getmtime(os.path.join(d, f)))
        return [newest, os.path.getsize(os.path.join(d, newest))]
    except Exception:
        return None


def check_camera_frozen():
    """Stream congelado: o buffer HLS (SIP) para de renovar.

    Antes comparava o snapshot (s.jpg) — que em monitor mode:start fica ESTÁTICO
    mesmo com a gravação viva, gerando falso-positivo (câmera ok, só o snapshot-cache
    do Shinobi travado). Agora olha o segmento .ts mais novo do buffer em RAM: o
    Shinobi renova esses segmentos continuamente enquanto grava, então se a assinatura
    (nome+tamanho) do segmento mais novo não muda entre amostras, o stream de fato
    travou. Conservador (~13min). monitor_died cobre o caso de buffer ausente."""
    out = []
    _, gk = _shinobi_creds()
    if not gk:
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
        st = _snap.setdefault(mid, {"sig": None, "identical": 0})
        if sample:
            d = _stream_dir(gk, mo)
            head = _buffer_head(d) if d else None
            if head is None:
                # buffer ausente/ilegível → não afirma congelado (fail-safe, sem alerta)
                st["identical"] = 0
                st["sig"] = None
                continue
            st["identical"] = st["identical"] + 1 if st["sig"] == head else 0
            st["sig"] = head
        if st["identical"] >= FROZEN_SAMPLES:
            out.append({
                "type": "camera_frozen", "severity": "high",
                "detail": f"câmera {mo.get('name')} possivelmente congelada (buffer HLS parou de renovar)",
                "evidence": {"mid": mid, "monitor": mo.get("name"),
                             "identicalSamples": st["identical"], "segment": st["sig"]},
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
    pwv = []
    if AUTOHEAL_PRESS_WITHOUT_VIDEO:
        pwv += [a for a in found
                if a.get("type") == "press_without_video"
                and a.get("consecutiveCount", 0) >= AUTOHEAL_MIN_CONSECUTIVE]
    if AUTOHEAL_SHINOBI_PORT_DEAD:
        pwv += [a for a in found
                if a.get("type") == "shinobi_port_dead"
                and a.get("consecutiveCount", 0) >= AUTOHEAL_MIN_CONSECUTIVE]
    if not pwv:
        return
    now = time.time()
    if now - _last_autoheal < AUTOHEAL_COOLDOWN:
        _log(f"auto-heal: gatilho persistente mas em cooldown "
             f"({int(AUTOHEAL_COOLDOWN - (now - _last_autoheal))}s restantes)")
        return
    reasons = ', '.join(sorted({a.get("type") for a in pwv}))
    monitors = sorted({(a.get("evidence") or {}).get("monitor") for a in pwv} - {None})
    _log(f"auto-heal: {reasons} -> pm2 restart camera (monitors={monitors})")
    ok = _restart_camera()
    _last_autoheal = now
    # zera os contadores dos monitores afetados p/ dar tempo de re-armar antes de recontar
    for a in pwv:
        _consecutive.pop(a.get("dedupKey"), None)
    # reporta a ação pro OPS (visibilidade — vira anomalia resolvida/ação no painel)
    _post("/api/observation/report", {
        "type": "autoheal_camera_restart", "severity": "high",
        "detail": f"auto-heal (Ultra Watch): pm2 restart camera por {reasons}" + (f" em {', '.join(monitors)}" if monitors else ""),
        "evidence": {"monitors": monitors, "restarted": ok, "reason": reasons},
        "dedupKey": "autoheal_camera_restart",
        "consecutiveCount": 1,
        "firstSeenAt": datetime.now(timezone.utc).isoformat(),
    }, serial, secret, ops)


# ---------------------------------------------------------------- loop
def _meminfo_mb():
    """(disponivel_mb, total_mb) do /proc/meminfo. MemAvailable é o número certo
    (conta cache reclaimável), não MemFree."""
    vals = {}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0].rstrip(":") in ("MemAvailable", "MemTotal"):
                    vals[parts[0].rstrip(":")] = int(parts[1]) // 1024
    except Exception:
        return (None, None)
    return (vals.get("MemAvailable"), vals.get("MemTotal"))


def _ffmpeg_rss_mb():
    """RSS de cada ffmpeg, em MB, com o monitor a que pertence (quando dá pra
    inferir pela cmdline). Lê /proc direto — sem ps/awk, barato no Pi 3B."""
    out = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open("/proc/%s/comm" % pid) as fh:
                    if fh.read().strip() != "ffmpeg":
                        continue
                rss = None
                with open("/proc/%s/status" % pid) as fh:
                    for line in fh:
                        if line.startswith("VmRSS:"):
                            rss = int(line.split()[1]) // 1024
                            break
                if rss is None:
                    continue
                mon = None
                with open("/proc/%s/cmdline" % pid, "rb") as fh:
                    cmd = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace")
                m = re.search(r"[A-Za-z0-9]+_camera[0-9]+", cmd)
                if m:
                    mon = m.group(0)
                out.append({"pid": int(pid), "rssMb": rss, "monitor": mon})
            except Exception:
                continue
    except Exception:
        pass
    return out


def check_memory_pressure():
    """RAM apertando ou ffmpeg inflando — antecede o OOM que trava a Pi.

    Dois gatilhos independentes:
      - RAM disponível baixa (o sistema todo está no limite);
      - um ffmpeg individual gigante (o vazamento, antes de derrubar o resto).
    O segundo é o mais útil: aponta a câmera culpada enquanto ainda há folga.
    """
    out = []
    avail, total = _meminfo_mb()
    procs = _ffmpeg_rss_mb()
    worst = max(procs, key=lambda x: x["rssMb"]) if procs else None

    if _confirm("high_memory:device", avail is not None and avail < MEM_AVAIL_WARN_MB):
        sev = "high" if avail < MEM_AVAIL_CRIT_MB else "medium"
        out.append({
            "type": "high_memory", "severity": sev,
            "detail": "RAM disponivel em %d MB de %s — risco de OOM travar a Pi" % (avail, total),
            "evidence": {
                "availMb": avail, "totalMb": total,
                "ffmpeg": sorted(procs, key=lambda x: -x["rssMb"])[:6],
            },
            "dedupKey": "high_memory:device",
        })

    if _confirm("ffmpeg_memory_leak", bool(worst and worst["rssMb"] >= FFMPEG_RSS_WARN_MB)):
        sev = "high" if worst["rssMb"] >= FFMPEG_RSS_CRIT_MB else "medium"
        alvo = worst["monitor"] or ("pid %d" % worst["pid"])
        out.append({
            "type": "ffmpeg_memory_leak", "severity": sev,
            "detail": "ffmpeg de %s com %d MB (normal ~50 MB) — inflando ate o OOM" % (alvo, worst["rssMb"]),
            "evidence": {
                "monitor": worst["monitor"], "pid": worst["pid"], "rssMb": worst["rssMb"],
                "availMb": avail, "ffmpegCount": len(procs),
            },
            "dedupKey": "ffmpeg_memory_leak:%s" % (worst["monitor"] or "device"),
        })

    return out


# ---------------------------------------------------------------- snapshot (2.0)
def _run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except Exception:
        return None, ""


def parse_throttled(text):
    """'throttled=0x50005' -> 0x50005 (int). None se ilegível."""
    m = re.search(r"throttled=(0x[0-9a-fA-F]+)", text or "")
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except ValueError:
        return None


def _read_temp_c():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as fh:
            return round(int(fh.read().strip()) / 1000.0, 1)
    except Exception:
        return None


def _rootfs_readonly(mounts_text=None):
    """True se / está montado ro (última entrada de / em /proc/mounts vence)."""
    try:
        if mounts_text is None:
            with open("/proc/mounts") as fh:
                mounts_text = fh.read()
        opts = None
        for line in mounts_text.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "/":
                opts = parts[3].split(",")
        return None if opts is None else ("ro" in opts)
    except Exception:
        return None


def _uptime_sec():
    try:
        with open("/proc/uptime") as fh:
            return int(float(fh.read().split()[0]))
    except Exception:
        return None


def _ntp_synced():
    code, out = _run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    v = (out or "").strip().lower()
    if code != 0 or v not in ("yes", "no"):
        return None
    return v == "yes"


def _dns_ok(host, timeout=4):
    """Resolve o host do OPS numa thread (getaddrinfo não tem timeout)."""
    if not host:
        return None
    res = {}

    def work():
        try:
            socket.getaddrinfo(host, 443)
            res["ok"] = True
        except Exception:
            res["ok"] = False

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    return res.get("ok", False)


def _unit_active(*names):
    """True/False para uma unit instalada E habilitada; None se não existe ou foi
    desabilitada de propósito (ex.: arena de alarm input sem gravae-buttons)."""
    for name in names:
        code, out = _run(["systemctl", "show", name, "-p", "LoadState", "-p", "ActiveState",
                          "-p", "UnitFileState"])
        if code != 0:
            continue
        kv = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        if kv.get("LoadState") != "loaded":
            continue
        if kv.get("UnitFileState") not in ("enabled", "enabled-runtime", "static"):
            return None
        return kv.get("ActiveState") == "active"
    return None


def _spool_files():
    try:
        return sorted(f for f in os.listdir(SPOOL_DIR) if f.endswith(".json"))
    except Exception:
        return []


def build_snapshot():
    """Retrato barato da saúde da Pi, enviado em todo heartbeat. Cada campo é
    best-effort (None quando não dá pra ler)."""
    thr = parse_throttled(_run(["vcgencmd", "get_throttled"])[1])
    avail, total = _meminfo_mb()
    disk_mb = disk_pct = None
    try:
        st = os.statvfs("/")
        free = st.f_bavail * st.f_frsize
        disk_mb = int(free / (1024 * 1024))
        disk_pct = round(100.0 * free / (st.f_blocks * st.f_frsize), 1) if st.f_blocks else None
    except Exception:
        pass
    try:
        load1 = round(os.getloadavg()[0], 2)
    except Exception:
        load1 = None
    host = None
    try:
        host = urllib.parse.urlparse(_state.get("opsUrl") or "").hostname
    except Exception:
        pass
    return {
        "tempC": _read_temp_c(),
        "throttled": hex(thr) if thr is not None else None,
        "undervoltageNow": bool(thr & 0x1) if thr is not None else None,
        "memAvailMb": avail,
        "memTotalMb": total,
        "diskFreeMb": disk_mb,
        "diskFreePct": disk_pct,
        "rootfsReadOnly": _rootfs_readonly(),
        "load1": load1,
        "uptimeSec": _uptime_sec(),
        "ntpSynced": _ntp_synced(),
        "dnsOk": _dns_ok(host),
        "cloudflaredActive": _unit_active("cloudflared"),
        "mariadbActive": _unit_active("mariadb", "mysql"),
        "buttonsActive": _unit_active("gravae-buttons"),
        "spoolChunks": len(_spool_files()),
    }


# ---------------------------------------------------------------- checks 2.0
def _bucket(seconds):
    return int(time.time() // seconds)


def check_undervoltage(snap):
    """Subtensão agora (bit 0) ou nova ocorrência desde o boot (bit 16 passou de
    0 para 1 enquanto observávamos). Se a Pi já bootou com o bit 16 ligado não
    dá para saber quando foi: não reporta (conservador)."""
    global _prev_throttled
    out = []
    thr = parse_throttled(snap.get("throttled") and f"throttled={snap['throttled']}")
    if thr is None:
        return out
    if thr & 0x1:
        out.append({
            "type": "undervoltage", "severity": "high",
            "detail": "subtensão AGORA (fonte/cabo fraco) — causa travamento, SD corrompido e câmera caindo",
            "evidence": {"throttled": hex(thr)},
            "dedupKey": "undervoltage",
        })
    elif _prev_throttled is not None and not (_prev_throttled & 0x10000) and (thr & 0x10000):
        out.append({
            "type": "undervoltage", "severity": "high",
            "detail": "houve subtensão desde a última checagem (fonte/cabo fraco)",
            "evidence": {"throttled": hex(thr), "previous": hex(_prev_throttled)},
            "dedupKey": f"undervoltage_event:{_bucket(3600)}",
        })
    _prev_throttled = thr
    return out


def check_high_temperature(snap):
    t = snap.get("tempC")
    if not _confirm("high_temperature", t is not None and t >= TEMP_WARN_C):
        return []
    sev = "high" if t >= TEMP_CRIT_C else "medium"
    return [{
        "type": "high_temperature", "severity": sev,
        "detail": f"Pi a {t}°C (CPU estrangula acima de 80°C)",
        "evidence": {"tempC": t, "throttled": snap.get("throttled")},
        "dedupKey": "high_temperature",
    }]


def check_disk_full(snap):
    pct, mb = snap.get("diskFreePct"), snap.get("diskFreeMb")
    if pct is None or mb is None:
        return []
    if pct < DISK_CRIT_PCT or mb < DISK_CRIT_MB:
        sev = "high"
    elif pct < DISK_WARN_PCT:
        sev = "medium"
    else:
        return []
    return [{
        "type": "disk_full", "severity": sev,
        "detail": f"disco com {mb} MB livres ({pct}%)",
        "evidence": {"diskFreeMb": mb, "diskFreePct": pct},
        "dedupKey": "disk_full",
    }]


def check_sd_readonly(snap):
    if snap.get("rootfsReadOnly") is not True:
        return []
    return [{
        "type": "sd_readonly", "severity": "critical",
        "detail": "sistema de arquivos em SOMENTE LEITURA — SD com defeito; botões e gravação param",
        "evidence": {"rootfsReadOnly": True},
        "dedupKey": "sd_readonly",
    }]


def _match_kernel(regex):
    return [l["m"] for l in _kernel_lines if regex.search(l.get("m") or "")]


def check_sd_errors():
    hits = _match_kernel(_SD_ERR_RE)
    if not hits:
        return []
    return [{
        "type": "sd_errors", "severity": "high",
        "detail": f"{len(hits)} erro(s) de SD/disco no kernel",
        "evidence": {"lines": hits[:10]},
        "dedupKey": f"sd_errors:{_bucket(600)}",
    }]


def check_oom_kill():
    hits = _match_kernel(_OOM_RE)
    if not hits:
        return []
    return [{
        "type": "oom_kill", "severity": "high",
        "detail": "kernel matou processo por falta de memória (OOM)",
        "evidence": {"lines": hits[:10]},
        "dedupKey": f"oom_kill:{_bucket(600)}",
    }]


def check_clock_unsynced(snap):
    up = snap.get("uptimeSec") or 0
    bad = snap.get("ntpSynced") is False and up > NTP_GRACE_SEC
    if not _confirm("clock_unsynced", bad, need=4):
        return []
    return [{
        "type": "clock_unsynced", "severity": "medium",
        "detail": "relógio sem sincronizar com NTP — apertos podem cair fora da janela do vídeo",
        "evidence": {"ntpSynced": False, "uptimeSec": up},
        "dedupKey": "clock_unsynced",
    }]


def check_dns_failure(snap):
    if not _confirm("dns_failure", snap.get("dnsOk") is False):
        return []
    return [{
        "type": "dns_failure", "severity": "medium",
        "detail": "a Pi não consegue resolver DNS (o OPS) — internet/roteador/DNS",
        "evidence": {"dnsOk": False},
        "dedupKey": "dns_failure",
    }]


def _unit_down_check(snap, field, type_, severity, detail):
    if not _confirm(type_, snap.get(field) is False):
        return []
    return [{
        "type": type_, "severity": severity, "detail": detail,
        "evidence": {field: False},
        "dedupKey": type_,
    }]


def check_tunnel_down(snap):
    return _unit_down_check(snap, "cloudflaredActive", "tunnel_down", "high",
                            "cloudflared (túnel de acesso remoto) parado")


def check_database_down(snap):
    return _unit_down_check(snap, "mariadbActive", "database_down", "critical",
                            "MariaDB parado — Shinobi não registra eventos/vídeos")


def check_buttons_service_down(snap):
    return _unit_down_check(snap, "buttonsActive", "buttons_service_down", "critical",
                            "serviço gravae-buttons parado — apertos não disparam gravação")


# ---------------------------------------------------------------- vídeo corrompido
def _video_candidates(group_key, now):
    """[(mtime, size, path, monitor)] dos MP4 prontos, recentes e ainda não sondados,
    do mais antigo para o mais novo."""
    floor = now - VIDEO_LOOKBACK_SEC
    if _video_floor is not None:
        floor = max(floor, _video_floor)
    out = []
    for base in VIDEO_DIRS:
        root = os.path.join(base, group_key)
        try:
            monitors = os.listdir(root)
        except OSError:
            continue
        for mon in monitors:
            d = os.path.join(root, mon)
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for n in names:
                if not n.endswith(".mp4"):
                    continue
                path = os.path.join(d, n)
                if path in _video_seen:
                    continue
                try:
                    st = os.stat(path)
                except OSError:
                    continue   # a fila já puxou e apagou
                if st.st_mtime < floor or now - st.st_mtime < VIDEO_SETTLE_SEC:
                    continue
                out.append((st.st_mtime, st.st_size, path, mon))
    out.sort()
    return out


def _mark_video_seen(path):
    _video_seen[path] = None
    while len(_video_seen) > VIDEO_SEEN_MAX:
        del _video_seen[next(iter(_video_seen))]


def probe_video(path):
    """Motivo da corrupção, None se o vídeo está bom, ou "skip" quando não dá para
    afirmar nada (arquivo sumiu — a fila puxa e apaga —, ffprobe ausente/lento)."""
    global _ffprobe_missing
    try:
        size = os.path.getsize(path)
    except OSError:
        return "skip"
    if size == 0:
        return "zero_bytes"
    if _ffprobe_missing:
        return "skip"
    cmd = ["nice", "-n", "19", "ffprobe", "-v", "error", "-select_streams", "v:0",
           "-show_entries", "stream=codec_type:format=duration", "-of", "json", path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=FFPROBE_TIMEOUT)
    except FileNotFoundError:
        _ffprobe_missing = True
        _log("ffprobe não instalado — check de vídeo corrompido só vê arquivo de 0 byte")
        return "skip"
    except subprocess.TimeoutExpired:
        return "skip"   # Pi carregada; lento não é corrompido
    if not os.path.exists(path):
        return "skip"
    if r.returncode != 0:
        err = (r.stderr or "").strip().splitlines()
        return "ffprobe_failed" + (": " + err[0][:200] if err else "")
    try:
        info = json.loads(r.stdout or "{}")
    except ValueError:
        return "ffprobe_failed: saída ilegível"
    if not any((s or {}).get("codec_type") == "video" for s in info.get("streams") or []):
        return "no_video_stream"
    try:
        dur = float((info.get("format") or {}).get("duration"))
    except (TypeError, ValueError):
        dur = None
    if dur is None or dur <= VIDEO_MIN_DURATION:
        return "too_short"
    return None


def check_video_corrupted(deadline=None):
    """MP4 que o Shinobi terminou e não abre: 0 byte, ffprobe falha, sem trilha
    de vídeo ou duração ≤0,5s. Cada arquivo é sondado uma vez; no máximo
    VIDEO_PROBES_PER_CYCLE por ciclo. Um aviso por monitor a cada 10 min."""
    global _video_floor
    now = time.time()
    if _video_floor is None:
        _video_floor = now - 600
    _, gk = _shinobi_creds()
    if not gk or not _KEY_RE.fullmatch(gk):
        return []
    per_mon = {}
    probes = 0
    for _mt, _size, path, mon in _video_candidates(gk, now):
        if probes >= VIDEO_PROBES_PER_CYCLE or (deadline and time.time() >= deadline):
            break
        probes += 1
        reason = probe_video(path)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = _size
        _mark_video_seen(path)
        rec = per_mon.setdefault(mon, {"probed": 0, "files": []})
        rec["probed"] += 1
        if reason and reason != "skip":
            rec["files"].append({"name": os.path.basename(path), "sizeBytes": size, "reason": reason})
    out = []
    bucket = _bucket(600)
    for mon, rec in per_mon.items():
        if not rec["files"]:
            continue
        out.append({
            "type": "video_corrupted", "severity": "high",
            "detail": f"{len(rec['files'])} vídeo(s) corrompido(s) em {mon} ({rec['files'][0]['reason']})",
            "evidence": {"monitor": mon, "files": rec["files"][:5],
                         "probed": rec["probed"], "corrupted": len(rec["files"])},
            "dedupKey": f"video_corrupted:{mon}:{bucket}",
        })
    return out


# ---------------------------------------------------------------- caixa preta (journald)
def _entry_unit(e):
    if e.get("_TRANSPORT") == "kernel":
        return "kernel"
    u = e.get("_SYSTEMD_UNIT") or e.get("SYSLOG_IDENTIFIER") or "?"
    return u[:-8] if u.endswith(".service") else u


def _entry_msg(e):
    m = e.get("MESSAGE")
    if isinstance(m, list):
        try:
            m = bytes(m).decode("utf-8", "replace")
        except Exception:
            m = ""
    return (m or "")[:MSG_MAX_CHARS]


def parse_journal(stdout):
    """journalctl -o json → (linhas filtradas, linhas do kernel, último cursor)."""
    keep, kernel, cursor = [], [], None
    for raw in (stdout or "").splitlines():
        try:
            e = json.loads(raw)
        except Exception:
            continue
        cursor = e.get("__CURSOR") or cursor
        try:
            p = int(e.get("PRIORITY", 6))
        except (TypeError, ValueError):
            p = 6
        try:
            t = int(e.get("__REALTIME_TIMESTAMP")) / 1e6
        except (TypeError, ValueError):
            t = time.time()
        u = _entry_unit(e)
        line = {"t": t, "u": u, "p": p, "m": _entry_msg(e)}
        if u == "kernel":
            kernel.append(line)
        if u in JOURNAL_UNITS or (u == "kernel" and p <= 4) or p <= 3:
            keep.append(line)
    return keep, kernel, cursor


def collect_journal():
    """Lê do journald o que é novo desde o cursor salvo."""
    cursor = _state.get("journalCursor")
    cmd = ["journalctl", "-o", "json", "--no-pager", "-n", str(JOURNAL_FETCH_MAX)]
    cmd += ["--after-cursor", cursor] if cursor else ["--since", "-5 min"]
    code, out = _run(cmd, timeout=15)
    if code not in (0, None) and not out and cursor:
        _state.pop("journalCursor", None)   # cursor inválido (journal rotacionou)
        return [], []
    keep, kernel, new_cursor = parse_journal(out)
    if new_cursor:
        _state["journalCursor"] = new_cursor
    return keep, kernel


def make_chunks(lines):
    chunks = []
    for i in range(0, len(lines), CHUNK_MAX_LINES):
        part = lines[i:i + CHUNK_MAX_LINES]
        seq = int(_state.get("journalSeq") or 0) + 1
        _state["journalSeq"] = seq
        chunks.append({
            "seq": seq,
            "from": datetime.fromtimestamp(part[0]["t"], timezone.utc).isoformat(),
            "to": datetime.fromtimestamp(part[-1]["t"], timezone.utc).isoformat(),
            "lines": part,
        })
    return chunks


def _spool_path(seq):
    return os.path.join(SPOOL_DIR, "%012d.json" % seq)


def spool_write(chunks):
    """Guarda chunks não enviados e aplica o ring (descarta os mais antigos)."""
    if not chunks:
        return
    try:
        os.makedirs(SPOOL_DIR, exist_ok=True)
        for c in chunks:
            with open(_spool_path(c["seq"]), "w") as fh:
                json.dump(c, fh)
        files = _spool_files()
        sizes = {f: os.path.getsize(os.path.join(SPOOL_DIR, f)) for f in files}
        total = sum(sizes.values())
        for f in files:
            if total <= SPOOL_MAX_BYTES:
                break
            os.remove(os.path.join(SPOOL_DIR, f))
            total -= sizes[f]
    except Exception as e:
        _log(f"spool falhou: {e}")


def spool_read():
    out = []
    for f in _spool_files():
        try:
            with open(os.path.join(SPOOL_DIR, f)) as fh:
                out.append(json.load(fh))
        except Exception:
            try:
                os.remove(os.path.join(SPOOL_DIR, f))
            except Exception:
                pass
    return out


def spool_prune(accepted_seq):
    for f in _spool_files():
        try:
            if int(f.split(".")[0]) <= accepted_seq:
                os.remove(os.path.join(SPOOL_DIR, f))
        except Exception:
            pass


def _batch(chunks):
    """Até POST_MAX_CHUNKS chunks, corpo ≤ POST_MAX_BYTES (sempre ao menos 1)."""
    out, size = [], 0
    for c in chunks[:POST_MAX_CHUNKS]:
        n = len(json.dumps(c))
        if out and size + n > POST_MAX_BYTES:
            break
        out.append(c)
        size += n
    return out


def ship_journal(new_chunks, serial, secret, ops, deadline, online=True):
    """Envia spool (mais antigo primeiro) + chunks novos. O que não sair fica no
    spool em disco — é o que mostra o que aconteceu enquanto a Pi estava sem
    internet."""
    pending_spool = spool_read()
    pending_new = list(new_chunks)
    sent_any = False
    while online and (pending_spool or pending_new) and time.time() < deadline:
        batch = _batch(pending_spool + pending_new)
        code, body = _post_status("/api/observation/journal",
                                  {"obsVersion": OBS_VERSION, "chunks": batch},
                                  serial, secret, ops, timeout=10, attempts=1)
        if code != 200 or not isinstance(body, dict) or "acceptedSeq" not in body:
            break
        try:
            acc = int(body["acceptedSeq"])
        except (TypeError, ValueError):
            break
        sent_any = True
        spool_prune(acc)
        before = len(pending_spool) + len(pending_new)
        pending_spool = [c for c in pending_spool if c["seq"] > acc]
        pending_new = [c for c in pending_new if c["seq"] > acc]
        if len(pending_spool) + len(pending_new) == before:
            break   # OPS não avançou: tenta no próximo ciclo
    spool_write(pending_new)
    return sent_any


def _cycle():
    global _cyc, _hb_401, _kernel_lines
    _cyc += 1
    started = time.time()
    interval = int(_state.get("interval") or DEFAULT_INTERVAL)
    deadline = started + max(10, interval - 5)
    serial = get_serial()
    secret = _state.get("secret")
    ops = _state.get("opsUrl")
    if not secret or not ops:
        return

    # 1) heartbeat primeiro, com prazo curto, levando o retrato da saúde.
    try:
        snap = build_snapshot()
    except Exception as e:
        _log(f"snapshot erro: {e}")
        snap = {}
    code, _ = _post_status("/api/observation/heartbeat",
                           {"ts": time.time(), "obsVersion": OBS_VERSION, "snapshot": snap},
                           serial, secret, ops, timeout=HB_TIMEOUT, attempts=2)
    online = code is not None
    if code == 401:
        _hb_401 += 1
        if _hb_401 >= HB_401_DISABLE:
            _log(f"OPS recusou {_hb_401} heartbeats seguidos (401) — modo desligado no OPS; desligando")
            _hb_401 = 0
            disable()
            return
    elif code is not None:
        _hb_401 = 0

    # 2) caixa preta: lê o journald novo. Sem internet vai para o spool em disco.
    try:
        lines, _kernel_lines = collect_journal()
        new_chunks = make_chunks(lines)
    except Exception as e:
        _log(f"journal erro: {e}")
        _kernel_lines, new_chunks = [], []

    # apertos recentes (3min) — alimenta press_without_video, gpio_stuck e o
    # lastPress persistido (base do gpio_idle_24h).
    presses = _recent_presses(3)
    if presses:
        lp = _state.setdefault("lastPress", {})
        for mon, rec in presses.items():
            if rec["last"] > float(lp.get(mon, 0)):
                lp[mon] = rec["last"]

    found = []
    for fn, args in (
        (check_service_down, ()),
        (check_shinobi_8080, ()),
        (check_press_without_video, (presses,)),
        (check_monitor_died, ()),
        (check_camera_frozen, ()),
        (check_gpio_stuck, (presses,)),
        (check_gpio_idle_24h, ()),
        (check_memory_pressure, ()),
        (check_undervoltage, (snap,)),
        (check_high_temperature, (snap,)),
        (check_disk_full, (snap,)),
        (check_sd_readonly, (snap,)),
        (check_sd_errors, ()),
        (check_oom_kill, ()),
        (check_clock_unsynced, (snap,)),
        (check_dns_failure, (snap,)),
        (check_tunnel_down, (snap,)),
        (check_database_down, (snap,)),
        (check_buttons_service_down, (snap,)),
        (check_video_corrupted, (deadline,)),
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
        # Sem internet não adianta reportar (o watchdog do OPS já vê o offline);
        # a anomalia continua no próximo ciclo e o journal guarda o contexto.
        if online and time.time() < deadline:
            _post("/api/observation/report", a, serial, secret, ops, timeout=10, attempts=2)
    for dk in list(_consecutive):
        if dk not in seen:
            del _consecutive[dk]

    # Watchdog: auto-cura do no-record silencioso (só com Ultra Watch ativo, que é
    # a condição p/ estarmos neste loop). pm2 restart camera se press_without_video
    # persistir. `found` já traz consecutiveCount setado acima.
    try:
        if _state.get("autoheal", True):
            _maybe_autoheal(found, serial, secret, ops)
    except Exception as e:
        _log(f"auto-heal erro: {e}")

    # 3) envia a caixa preta por último, dentro do que sobra do ciclo.
    try:
        ship_journal(new_chunks, serial, secret, ops, deadline, online=online)
    except Exception as e:
        _log(f"envio do journal erro: {e}")
    save_state()


def _loop():
    while not _stop.is_set():
        interval = int(_state.get("interval") or DEFAULT_INTERVAL)
        until = _state.get("until")
        if until:   # modo "fixo" vem sem prazo e roda até ser desligado
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
        if not _state.get("enabled"):
            return
        _stop.wait(interval)


def enable(secret, ops_url, interval=DEFAULT_INTERVAL, until=None, autoheal=True, mode=None):
    global _thread, _state, _loaded
    if type(autoheal) is not bool:
        raise ValueError("autoheal must be boolean")
    if mode is not None and mode not in MODES:
        raise ValueError("mode must be 'semana' or 'fixo'")
    with _lock:
        _loaded = True
        keep = _state if _state.get("enabled") else {}
        _state = {"enabled": True, "secret": secret, "opsUrl": ops_url,
                  "interval": int(interval or DEFAULT_INTERVAL), "until": until,
                  "lastPress": keep.get("lastPress", {}), "autoheal": autoheal, "mode": mode,
                  # cursor/seq da caixa preta sobrevivem a re-ativações (o OPS
                  # descarta seq já aceito; zerar perderia o journal).
                  "journalCursor": keep.get("journalCursor") or _state.get("journalCursor"),
                  "journalSeq": max(int(keep.get("journalSeq") or 0), int(_state.get("journalSeq") or 0))}
        save_state()
        _stop.clear()
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_loop, daemon=True)
            _thread.start()
    _log(f"ativado (interval={interval}s, until={until}, mode={mode})")
    return True


def disable():
    global _state, _loaded
    with _lock:
        _loaded = True
        # Mantém o seq da caixa preta: uma nova ativação continua a numeração.
        _state = {"enabled": False, "journalSeq": int(_state.get("journalSeq") or 0)}
        save_state()
        _stop.set()
    _log("desativado")
    return True


def resume_if_enabled():
    load_state()
    if _state.get("enabled") and _state.get("secret") and _state.get("opsUrl"):
        enable(_state["secret"], _state["opsUrl"], int(_state.get("interval") or DEFAULT_INTERVAL),
               _state.get("until"), _state.get("autoheal", True), mode=_state.get("mode"))
        return True
    return False


def status():
    # Logo após update/restart o /observation/status pode chegar antes da thread
    # de resume_if_enabled: lê o estado persistido para não responder "desligado".
    if not _loaded:
        load_state()
    return {
        "enabled": bool(_state.get("enabled")),
        "interval": _state.get("interval"),
        "until": _state.get("until"),
        "mode": _state.get("mode"),
        "running": _thread is not None and _thread.is_alive(),
        "obsVersion": OBS_VERSION,
        "supportsAutohealPolicy": True,
        "supportsJournal": True,
        "autohealEnabled": bool(_state.get("enabled")) and _state.get("autoheal", True),
    }
