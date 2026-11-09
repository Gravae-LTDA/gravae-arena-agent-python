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
import shutil
import signal
import socket
import threading
import subprocess
try:
    import resource
except ImportError:  # pragma: no cover
    resource = None
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
# Limites RELATIVOS à RAM (Pi 3 ≈ 900 MB úteis; Pi 4/5 2–8 GB). Os fixos antigos
# (700 MB livres) disparavam sempre num Pi 3 e nunca a tempo num Pi 4 de 8 GB.
# Ver mem_thresholds().
# Guardião de memória (AAB, Pi 3 1 GB: ffmpeg "sangrando" até o OOM travar a Pi,
# que só volta com power-cycle). Age sozinho quando a política de autoheal permite.
GUARD_TICK_SEC = 10            # via rápida: só lê /proc/meminfo
GUARD_KILL_COOLDOWN = 600      # por monitor
GUARD_RECUR_WINDOW = 7200
GUARD_RECUR_KILLS = 3          # 3 kills em 2 h ⇒ escala como config (e continua protegendo)
GUARD_VERIFY_SEC = 60          # ainda no limite 60s depois ⇒ pm2 restart camera
GUARD_TERM_WAIT = 5
LEAK_GROWTH_MB = 150
LEAK_WINDOW_SEC = 1800
LEAK_MIN_SPAN_SEC = 300
_LEAK_CONFIG_KEYS = ("wall_clock_timestamp_ignore", "detector_buffer", "detector_use_motion",
                     "acodec", "vcodec", "detector_buffer_acodec", "detector_buffer_vcodec",
                     "stream_type", "fps")

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

# Orçamento: o Ultra Watch divide a Pi com Shinobi + ffmpeg. Meta < 2% de 1
# núcleo do Pi 3B, ≤3 processos por ciclo barato, ≤1 escrita pequena no SD por
# minuto. Checks caros rodam em camadas e são pulados quando a Pi está apertada.
NET_EVERY_CYCLES = 3          # pings (thread em segundo plano, nunca bloqueia)
UPLOAD_EVERY_CYCLES = 13      # ~10 min: consulta de vídeos parados (1 SQL)
SAVE_EVERY_CYCLES = 2         # estado no SD a cada ~90s (mudança crítica salva na hora)
SEQ_RESTART_GAP = 1000        # seq pula isto no boot do módulo (estado salvo em lote)
BACKOFF_MEM_MB = 350          # abaixo disto (ou load1 > núcleos) só roda o essencial
WATCHED_UNITS = ("cloudflared", "mariadb", "mysql", "gravae-buttons", "gravae-phoenix")

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
_cycle_cache = {}   # respostas locais reaproveitadas dentro do mesmo ciclo
_press_log = []     # (ts, gpio, monitor) dos [PRESS] dos últimos minutos (do journal do ciclo)
_ionice = None
_cost = {"cpuMs": None, "skipped": 0}
_dirty = False      # estado mudou e ainda não foi gravado


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
    # O estado é salvo em lote; após reiniciar, o seq salvo pode estar atrás do
    # último chunk enviado. Pular adiante garante que o OPS não descarte chunks
    # novos como "já aceitos".
    if _state.get("journalSeq"):
        _state["journalSeq"] = int(_state["journalSeq"]) + SEQ_RESTART_GAP
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


def _local_get_cached(path):
    """Uma consulta local por ciclo para cada rota (vários checks leem a mesma)."""
    key = ("get", path)
    if key not in _cycle_cache:
        _cycle_cache[key] = _local_get(path)
    return _cycle_cache[key]


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
# Formatos do daemon de botões (variam por geração de instalação):
#   [PRESS] 2026-08-07 18:16:18 - GPIO6 - quadra01_camera01 [1 monitors]
#   [PRESS] 2026-08-07 18:16:18 - quadra01_camera01 (GPIO6)
#   [PRESS] GPIO13 -> quadra01_camera01 (Quadra 1) HTTP 200
_PRESS_RES = (
    (re.compile(r"\[PRESS\].*?GPIO(\d+)\s+-\s+(\S+)"), 1, 2),
    (re.compile(r"\[PRESS\].*?-\s+(\S+)\s+\(GPIO(\d+)\)"), 2, 1),
    (re.compile(r"\[PRESS\]\s+GPIO(\d+)\s+->\s+(\S+)"), 1, 2),
)


def parse_press(msg):
    """(gpio, monitor) de uma linha [PRESS], ou None."""
    for rx, gi, mi in _PRESS_RES:
        m = rx.search(msg or "")
        if m:
            return m.group(gi), m.group(mi)
    return None


def _feed_presses(lines, now=None):
    now = now or time.time()
    for l in lines:
        if l.get("u") != "gravae-buttons":
            continue
        p = parse_press(l.get("m"))
        if p:
            _press_log.append((l.get("t") or now, p[0], p[1]))
    _press_log[:] = [x for x in _press_log if now - x[0] <= 600]


def _recent_presses(minutes=3, now=None):
    """{monitor: {"last": epoch, "count": n}} dos [PRESS] dos últimos minutos.
    Vem do journal já lido no ciclo (sem journalctl extra)."""
    now = now or time.time()
    out = {}
    for ts, _gpio, mon in _press_log:
        if now - ts > minutes * 60:
            continue
        rec = out.setdefault(mon, {"last": 0.0, "count": 0})
        rec["last"] = max(rec["last"], ts)
        rec["count"] += 1
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


def _down_services(fresh=False):
    st = _local_get("/phoenix/status") if fresh else _local_get_cached("/phoenix/status")
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
    again = _down_services(fresh=True)
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
    mons = _local_get_cached("/phoenix/monitors")
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
    mons = _local_get_cached("/phoenix/monitors")
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
    mons = _local_get_cached("/phoenix/monitors")
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


def _proc_list():
    """Uma varredura do /proc por ciclo (sem ps). Detalha só node e ffmpeg."""
    key = ("procs",)
    if key in _cycle_cache:
        return _cycle_cache[key]
    out = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        try:
            with open("/proc/%s/comm" % pid) as fh:
                comm = fh.read().strip()
            if comm not in ("ffmpeg", "node"):
                continue
            with open("/proc/%s/cmdline" % pid, "rb") as fh:
                argv = [a.decode("utf-8", "replace") for a in fh.read().split(b"\x00") if a]
            rss = uid = None
            with open("/proc/%s/status" % pid) as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1]) // 1024
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
            item = {"pid": int(pid), "comm": comm, "argv": argv, "rssMb": rss, "uid": uid}
            if comm == "node":
                try:
                    item["cwd"] = os.readlink("/proc/%s/cwd" % pid)
                except OSError:
                    item["cwd"] = None
            out.append(item)
        except (OSError, ValueError):
            continue
    _cycle_cache[key] = out
    return out


def _ffmpeg_rss_mb():
    """RSS de cada ffmpeg, em MB, com o monitor a que pertence (quando dá pra
    inferir pela cmdline)."""
    out = []
    for p in _proc_list():
        if p["comm"] != "ffmpeg" or p["rssMb"] is None:
            continue
        m = re.search(r"[A-Za-z0-9]+_camera[0-9]+", " ".join(p["argv"]))
        out.append({"pid": p["pid"], "rssMb": p["rssMb"], "monitor": m.group(0) if m else None})
    return out


# ---------------------------------------------------------------- guardião de memória
def mem_thresholds(total_mb):
    """Limites em MB para a RAM total da Pi."""
    t = float(total_mb or 1024)
    return {"warnRss": max(300.0, 0.20 * t), "actRss": max(450.0, 0.35 * t),
            "warnAvail": 0.20 * t, "actAvail": 0.12 * t}


_guard = {"pids": [], "kills": {}, "lastKill": {}, "pending": None, "events": [], "rss": {},
          "recurReported": {}}
_guard_lock = threading.Lock()
_guard_thread = None
_MON_RE = re.compile(r"[A-Za-z0-9]+_camera[0-9]+")


def _pid_info(pid):
    """{pid, rssMb, monitor} de um ffmpeg pelo /proc; None se já morreu."""
    try:
        rss = None
        with open("/proc/%d/status" % pid) as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) // 1024
                    break
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            cmd = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    if rss is None:
        return None
    m = _MON_RE.search(cmd)
    return {"pid": pid, "rssMb": rss, "monitor": m.group(0) if m else None}


def _scan_ffmpeg_pids():
    out = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        try:
            with open("/proc/%s/comm" % pid) as fh:
                if fh.read().strip() == "ffmpeg":
                    out.append(int(pid))
        except OSError:
            continue
    return out


def _top_rss_is_ffmpeg():
    """O processo que mais ocupa RAM na Pi é um ffmpeg? (só chamado no aperto)"""
    page = 4096
    try:
        page = os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        pass
    best, best_pid = -1, None
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return False
    for pid in pids:
        try:
            with open("/proc/%s/statm" % pid) as fh:
                res = int(fh.read().split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if res > best:
            best, best_pid = res, pid
    if best_pid is None:
        return False
    try:
        with open("/proc/%s/comm" % best_pid) as fh:
            return fh.read().strip() == "ffmpeg"
    except OSError:
        return False


def guard_target(avail, total, procs, top_is_ffmpeg=None):
    """ffmpeg que deve ser derrubado agora, ou None.
    Age quando um ffmpeg passa de max(450 MB, 35% da RAM), ou quando a RAM
    disponível cai abaixo de 12% e o maior processo da Pi é um ffmpeg."""
    if not procs:
        return None
    th = mem_thresholds(total)
    worst = max(procs, key=lambda x: x["rssMb"])
    if worst["rssMb"] >= th["actRss"]:
        return worst
    if avail is not None and avail < th["actAvail"]:
        if top_is_ffmpeg is None:
            top_is_ffmpeg = _top_rss_is_ffmpeg()
        if top_is_ffmpeg:
            return worst
    return None


def _guard_policy():
    return bool(_state.get("autoheal", True))


def _queue(ev):
    with _guard_lock:
        _guard["events"].append(ev)


def drain_guard_events():
    with _guard_lock:
        ev, _guard["events"] = _guard["events"], []
    return ev


def _leak_config(monitor):
    """Campos do details do monitor que costumam causar o vazamento (1 SQL)."""
    _, gk = _shinobi_creds()
    if not monitor or not gk or not _KEY_RE.fullmatch(gk):
        return None
    rows = _mysql(f"SELECT mid, name, details FROM Monitors WHERE ke='{gk}'") or []
    for r in rows:
        if len(r) >= 3 and monitor in (r[0], r[1]):
            try:
                d = json.loads(r[2]) if r[2] else {}
            except ValueError:
                d = {}
            return {"mid": r[0], **{k: d.get(k) for k in _LEAK_CONFIG_KEYS}}
    return None


def _kill_pid(pid):
    """SIGTERM, espera até 5s, SIGKILL se ainda vivo. True se morreu.
    Só mata se o PID ainda é um ffmpeg (PID reciclado nunca é atingido)."""
    try:
        with open("/proc/%d/comm" % pid) as fh:
            if fh.read().strip() != "ffmpeg":
                return False
    except OSError:
        return True   # já morreu
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    end = time.time() + GUARD_TERM_WAIT
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            break
        time.sleep(0.5)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return True


def _action_event(action, target, avail, total, freed, extra=None):
    mon = target.get("monitor") or "pid %s" % target.get("pid")
    ev = {"monitor": target.get("monitor"), "pid": target.get("pid"), "rssMb": target.get("rssMb"),
          "memAvailMb": avail, "memTotalMb": total, "action": action, "freedMb": freed}
    ev.update(extra or {})
    return {
        "type": "memory_guard_action", "severity": "high",
        "detail": ("memória no limite: derrubei o ffmpeg de %s (%s MB) — Shinobi sobe outro" % (mon, target.get("rssMb"))
                   if action == "kill_ffmpeg" else
                   "memória continuou no limite após derrubar o ffmpeg: pm2 restart camera"),
        "evidence": ev,
        "dedupKey": "memory_guard_action:%s:%d" % (action, int(time.time())),
    }


def guard_act(target, avail, total, now=None):
    """Age (ou só reporta, com a política de autoheal desligada) sobre o ffmpeg alvo."""
    now = now or time.time()
    mon = target.get("monitor") or "pid %s" % target.get("pid")
    if not _guard_policy():
        _queue({
            "type": "ffmpeg_memory_leak", "severity": "high",
            "detail": "ffmpeg de %s com %s MB e RAM em %s/%s MB — risco de OOM travar a Pi (autoheal desligado: só aviso)"
                      % (mon, target.get("rssMb"), avail, total),
            "evidence": {"monitor": target.get("monitor"), "pid": target.get("pid"), "rssMb": target.get("rssMb"),
                         "memAvailMb": avail, "memTotalMb": total, "autoheal": False},
            "dedupKey": "ffmpeg_memory_leak:%s" % (target.get("monitor") or "device"),
        })
        return "reported"
    kills = [t for t in _guard["kills"].get(mon, []) if now - t <= GUARD_RECUR_WINDOW]
    _guard["kills"][mon] = kills
    recurring = len(kills) >= GUARD_RECUR_KILLS
    if recurring:
        # Recorrente é problema de configuração, mas a proteção NÃO para: a Pi
        # não pode travar por OOM. Escala no máximo 1× a cada 2 h por monitor.
        last_rep = _guard["recurReported"].get(mon)
        if last_rep is None or now - last_rep >= GUARD_RECUR_WINDOW:
            _guard["recurReported"][mon] = now
            _queue({
                "type": "ffmpeg_leak_recurring", "severity": "high",
                "detail": "ffmpeg de %s vazou memória %d vezes em 2 h — o guardião continua derrubando, "
                          "mas é configuração do monitor" % (mon, len(kills)),
                "evidence": {"monitor": target.get("monitor"), "pid": target.get("pid"), "rssMb": target.get("rssMb"),
                             "killsIn2h": len(kills), "memAvailMb": avail, "memTotalMb": total,
                             "config": _leak_config(target.get("monitor"))},
                "dedupKey": "ffmpeg_leak_recurring:%s:%d" % (mon, int(now // GUARD_RECUR_WINDOW)),
            })
    last = _guard["lastKill"].get(mon)
    if last is not None and now - last < GUARD_KILL_COOLDOWN:
        return "cooldown"
    _log("memory-guard: RAM %s/%s MB, ffmpeg de %s (pid %s) com %s MB — derrubando (SIGTERM→SIGKILL)"
         % (avail, total, mon, target.get("pid"), target.get("rssMb")))
    _kill_pid(int(target["pid"]))
    time.sleep(3)
    after, _ = _meminfo_mb()
    freed = (after - avail) if (after is not None and avail is not None) else None
    kills.append(now)
    _guard["kills"][mon] = kills
    _guard["lastKill"][mon] = now
    _guard["pending"] = {"ts": now, "target": target}
    _log("memory-guard: ffmpeg de %s derrubado, liberou %s MB" % (mon, freed))
    _queue(_action_event("kill_ffmpeg", target, avail, total, freed))
    return "killed_recurring" if recurring else "killed"


def _current_ffmpeg(pids=None):
    procs = []
    for pid in (pids if pids is not None else (_guard["pids"] or _scan_ffmpeg_pids())):
        info = _pid_info(pid)
        if info:
            procs.append(info)
    return procs


def _guard_verify(avail, total, now):
    """60s após derrubar: se ainda no limite, pm2 restart camera (com cooldown)."""
    global _last_autoheal
    pend = _guard["pending"]
    _guard["pending"] = None
    procs = _current_ffmpeg(_scan_ffmpeg_pids())
    if not guard_target(avail, total, procs):
        return "recovered"
    if not _guard_policy():
        return "reported"
    if now - _last_autoheal < AUTOHEAL_COOLDOWN:
        _log("memory-guard: ainda no limite, mas pm2 restart camera em cooldown")
        return "cooldown"
    _log("memory-guard: memória continua no limite após derrubar o ffmpeg — pm2 restart camera")
    ok = _restart_camera()
    _last_autoheal = now
    time.sleep(5)
    after, _ = _meminfo_mb()
    freed = (after - avail) if (after is not None and avail is not None) else None
    _queue(_action_event("restart_camera", pend["target"], avail, total, freed, {"restarted": ok}))
    return "restarted"


def guard_tick(now=None):
    """Via rápida (a cada 10s): só /proc/meminfo; lê os ffmpeg apenas quando a
    RAM disponível está abaixo da linha de aviso. Nunca abre processo."""
    now = now or time.time()
    avail, total = _meminfo_mb()
    if avail is None:
        return "noread"
    if _guard["pending"] and now - _guard["pending"]["ts"] >= GUARD_VERIFY_SEC:
        return _guard_verify(avail, total, now)
    if avail >= mem_thresholds(total)["warnAvail"]:
        return "ok"
    target = guard_target(avail, total, _current_ffmpeg())
    if not target:
        return "warn"
    return guard_act(target, avail, total, now)


def _guard_loop():
    while not _stop.wait(GUARD_TICK_SEC):
        try:
            guard_tick()
        except Exception as e:
            _log(f"memory-guard erro: {e}")


def _start_guard():
    global _guard_thread
    if _guard_thread is None or not _guard_thread.is_alive():
        _guard_thread = threading.Thread(target=_guard_loop, daemon=True)
        _guard_thread.start()


def leak_trend(samples, act_rss):
    """Amostras [(ts, rssMb)] de um ffmpeg (≤30 min). Devolve dict com o
    crescimento e a projeção quando o RSS cresce de forma contínua e (a) já
    cresceu ≥150 MB ou (b) chega ao limite de ação em ≤30 min. Senão None."""
    if len(samples) < 3:
        return None
    span = samples[-1][0] - samples[0][0]
    if span <= 0 or span > LEAK_WINDOW_SEC:
        return None
    for (_, a), (_, b) in zip(samples, samples[1:]):
        if b < a - 5:      # caiu: não é vazamento contínuo
            return None
    growth = samples[-1][1] - samples[0][1]
    if growth <= 0:
        return None
    slope = growth / span                       # MB/s
    eta = (act_rss - samples[-1][1]) / slope if samples[-1][1] < act_rss else 0
    if growth >= LEAK_GROWTH_MB or (span >= LEAK_MIN_SPAN_SEC and eta <= LEAK_WINDOW_SEC):
        return {"growthMb": int(growth), "windowMin": round(span / 60, 1),
                "mbPerMin": round(slope * 60, 1), "projectedActInMin": round(eta / 60, 1)}
    return None


def _track_rss(procs, now):
    alive = set()
    for p in procs:
        alive.add(p["pid"])
        hist = _guard["rss"].setdefault(p["pid"], [])
        hist.append((now, p["rssMb"]))
        hist[:] = [x for x in hist if now - x[0] <= LEAK_WINDOW_SEC]
    for pid in list(_guard["rss"]):
        if pid not in alive:
            del _guard["rss"][pid]


def check_memory_pressure(now=None):
    """RAM apertando ou ffmpeg inflando — antecede o OOM que trava a Pi.
    Limites relativos à RAM (mem_thresholds). Além do aviso, acompanha a
    tendência de cada ffmpeg (vazamento contínuo é avisado antes do limite) e
    aciona o guardião quando passa da linha de ação."""
    now = now or time.time()
    out = []
    avail, total = _meminfo_mb()
    procs = _ffmpeg_rss_mb()
    _guard["pids"] = [p["pid"] for p in procs]
    _track_rss(procs, now)
    th = mem_thresholds(total)
    worst = max(procs, key=lambda x: x["rssMb"]) if procs else None
    policy_off = not _guard_policy()

    if _confirm("high_memory:device", avail is not None and avail < th["warnAvail"]):
        sev = "high" if (avail < th["actAvail"] or policy_off) else "medium"
        out.append({
            "type": "high_memory", "severity": sev,
            "detail": "RAM disponivel em %d MB de %s — risco de OOM travar a Pi" % (avail, total),
            "evidence": {
                "availMb": avail, "totalMb": total, "thresholds": {k: int(v) for k, v in th.items()},
                "ffmpeg": sorted(procs, key=lambda x: -x["rssMb"])[:6],
            },
            "dedupKey": "high_memory:device",
        })

    reported = set()
    if _confirm("ffmpeg_memory_leak", bool(worst and worst["rssMb"] >= th["warnRss"])):
        sev = "high" if (worst["rssMb"] >= th["actRss"] or policy_off) else "medium"
        alvo = worst["monitor"] or ("pid %d" % worst["pid"])
        reported.add(worst["pid"])
        out.append({
            "type": "ffmpeg_memory_leak", "severity": sev,
            "detail": "ffmpeg de %s com %d MB (normal ~50 MB) — inflando ate o OOM" % (alvo, worst["rssMb"]),
            "evidence": {
                "monitor": worst["monitor"], "pid": worst["pid"], "rssMb": worst["rssMb"],
                "availMb": avail, "ffmpegCount": len(procs), "actRssMb": int(th["actRss"]),
                "trend": leak_trend(_guard["rss"].get(worst["pid"], []), th["actRss"]),
            },
            "dedupKey": "ffmpeg_memory_leak:%s" % (worst["monitor"] or "device"),
        })
    for p in procs:
        if p["pid"] in reported:
            continue
        tr = leak_trend(_guard["rss"].get(p["pid"], []), th["actRss"])
        if tr:
            alvo = p["monitor"] or ("pid %d" % p["pid"])
            out.append({
                "type": "ffmpeg_memory_leak", "severity": "high" if policy_off else "medium",
                "detail": "ffmpeg de %s crescendo %s MB/min (%s MB em %s min) — chega ao limite em ~%s min"
                          % (alvo, tr["mbPerMin"], tr["growthMb"], tr["windowMin"], tr["projectedActInMin"]),
                "evidence": {"monitor": p["monitor"], "pid": p["pid"], "rssMb": p["rssMb"], "availMb": avail,
                             "actRssMb": int(th["actRss"]), "trend": tr},
                "dedupKey": "ffmpeg_memory_leak:%s" % (p["monitor"] or "device"),
            })

    # linha de ação: o guardião age (ou só avisa, sem autoheal)
    target = guard_target(avail, total, procs) if avail is not None else None
    if target:
        guard_act(target, avail, total, now)
    out.extend(drain_guard_events())
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
    """Sem processo: o systemd-timesyncd cria este arquivo quando sincroniza.
    None quando a Pi não usa timesyncd (chrony/ntpd) — não dá para afirmar."""
    if os.path.exists("/run/systemd/timesync/synchronized"):
        return True
    if os.path.isdir("/run/systemd/timesync"):
        return False
    return None


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


def parse_units(text):
    """Saída de `systemctl show -p Id,LoadState,ActiveState,UnitFileState u1 u2 …`
    (blocos separados por linha vazia) → {unit: True/False/None}.
    None = não instalada ou desabilitada de propósito."""
    out = {}
    for block in (text or "").split("\n\n"):
        kv = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        uid = kv.get("Id", "")
        name = uid[:-8] if uid.endswith(".service") else uid
        if not name:
            continue
        if kv.get("LoadState") != "loaded" or kv.get("UnitFileState") not in ("enabled", "enabled-runtime", "static"):
            out[name] = None
        else:
            out[name] = kv.get("ActiveState") == "active"
    return out


def _units_state():
    """Estado de todas as units vigiadas numa única chamada ao systemctl (1×/ciclo)."""
    key = ("units",)
    if key not in _cycle_cache:
        code, out = _run(["systemctl", "show", "-p", "Id,LoadState,ActiveState,UnitFileState"]
                         + [u + ".service" for u in WATCHED_UNITS])
        _cycle_cache[key] = parse_units(out) if code == 0 else {}
    return _cycle_cache[key]


def _unit_active(*names):
    st = _units_state()
    for n in names:
        if st.get(n) is not None:
            return st[n]
    return None


def _read_throttled():
    """get_throttled pelo sysfs do firmware (sem processo); vcgencmd só se não houver."""
    for path in ("/sys/devices/platform/soc/soc:firmware/get_throttled",):
        try:
            with open(path) as fh:
                return int(fh.read().strip(), 16)
        except (OSError, ValueError):
            pass
    return parse_throttled(_run(["vcgencmd", "get_throttled"])[1])


def _self_rss_mb():
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return None


def _spool_files():
    try:
        return sorted(f for f in os.listdir(SPOOL_DIR) if f.endswith(".json"))
    except Exception:
        return []


def build_snapshot():
    """Retrato barato da saúde da Pi, enviado em todo heartbeat. Só /proc, /sys,
    statvfs e 1 chamada ao systemctl. Cada campo é best-effort (None se ilegível)."""
    thr = _read_throttled()
    avail, total = _meminfo_mb()
    disk_mb = disk_pct = disk_total = None
    try:
        st = os.statvfs("/")
        free = st.f_bavail * st.f_frsize
        disk_mb = int(free / (1024 * 1024))
        disk_total = int(st.f_blocks * st.f_frsize / (1024 * 1024))
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
        "diskTotalMb": disk_total,
        "rootfsReadOnly": _rootfs_readonly(),
        "load1": load1,
        "uptimeSec": _uptime_sec(),
        "ntpSynced": _ntp_synced(),
        "dnsOk": _dns_ok(host),
        "cloudflaredActive": _unit_active("cloudflared"),
        "mariadbActive": _unit_active("mariadb", "mysql"),
        "buttonsActive": _unit_active("gravae-buttons"),
        "phoenixActive": _unit_active("gravae-phoenix"),
        "spoolChunks": len(_spool_files()),
        "tz": _timezone(),
        "bootId": _boot_id(),
        "obsCpuMs": _cost["cpuMs"],
        "obsRssMb": _self_rss_mb(),
        "obsSkipped": _cost["skipped"],
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


def _low_prio(cmd):
    """nice 19 + ionice idle: o ffprobe só usa CPU/disco que sobrar do Shinobi."""
    global _ionice
    if _ionice is None:
        _ionice = bool(shutil.which("ionice"))
    return (["ionice", "-c3"] if _ionice else []) + ["nice", "-n", "19"] + cmd


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
    cmd = _low_prio(["ffprobe", "-v", "error", "-select_streams", "v:0",
                     "-show_entries", "stream=codec_type:format=duration", "-of", "json", path])
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


# ---------------------------------------------------------------- sistema de vídeo (2.0, rodada 3)
# Checks que preveem ou pegam rápido o que para a gravação. Padrões de log e
# causas vêm da base de casos da Grazi (gpio stuck LOW, API key recusada,
# EACCES na pasta de vídeos, camera.js duplicado, Ethernet instável, campos
# numéricos no details, H.265 etc.).
_ALERT_LOW_RE = re.compile(r"\[ALERT\]\s+(?:\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s+)?(\S+)\s+\(GPIO(\d+)\)\s+stuck LOW")
_REJECT_RE = re.compile(r"\[REJECT\].*?GPIO(\d+)")
_HTTP_RE = re.compile(r"\[HTTP\]\s+(?:\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s+)?(\S+)\s+->\s*(\d{3}|ERRO)")
_REFUSED_RE = re.compile(r"RECUSADO|Not Authorized", re.I)
_SYNC_FAIL_RE = re.compile(r"ARENA_CONFIG_SYNC_FAILED|HTTP\s*403|status(?:\s*code)?[=: ]+403|error code:?\s*1010", re.I)
_SHINOBI_LOG_RE = re.compile(r"EACCES|permission denied|ENOSPC|EADDRINUSE|Not Authorized", re.I)
_LINK_DOWN_RE = re.compile(r"\beth\d+: Link is Down")
_CLEAN_SHUTDOWN_RE = re.compile(r"Reached target (Shutdown|System Reboot|System Power Off|Final Step)|"
                                r"systemd-shutdown|Power-Off|reboot: Restarting system|System is (rebooting|powering down)",
                                re.I)
PM2_LOG_DIR = "/root/.pm2/logs"
PM2_LOG_READ_MAX = 512 * 1024
GHOST_WINDOW_SEC = 600
GHOST_MIN_REJECTS = 20
UPLOAD_DB_STUCK_MIN = 20
UPLOAD_FILE_STUCK_MIN = 30
FLAP_WINDOW_SEC = 1800
UNSTABLE_WINDOW_SEC = 3600
UNSTABLE_MIN_RECOVERIES = 3
CPU_LOAD_FACTOR = 1.5
DISK_PREDICT_WINDOW_SEC = 3600
DISK_PREDICT_MIN_SPAN_SEC = 2700
DISK_PREDICT_HOURS = 12
DRIFT_EVERY_SEC = 3600
PING_TIMEOUT = 6
NET_CONFIRM = 3
_NUMERIC_DETAIL_KEYS = ("detector", "detector_trigger", "detector_save", "detector_buffer",
                        "detector_send_video_length", "detector_use_motion", "detector_record_method")
_GOOD_STATUS = ("watching", "recording")
_BAD_STATUS = ("died", "failed", "error")

_cycle_lines = []      # linhas do journal lidas neste ciclo (todas as units mantidas)
_rejects = {}          # gpio -> [ts]
_link_downs = []       # ts das quedas de eth
_mon_status = {}       # mid -> último status
_mon_recoveries = {}   # mid -> [ts] (died → watching)
_disk_samples = []     # (ts, freeMb, totalMb)
_upload_cache = {"out": []}
_drift_cache = {"ts": 0.0, "out": []}
_net = {"thread": None, "result": None, "fresh": False}
_top_cache = {"cyc": None, "top": []}


def _unit_lines(unit):
    return [l for l in _cycle_lines if l.get("u") == unit]


def _gpio_level(n):
    """0/1 pelo raspi-gpio ou pinctrl (Pi 5). None se nenhum existe/legível."""
    for cmd in (["raspi-gpio", "get", str(n)], ["pinctrl", "get", str(n)]):
        code, out = _run(cmd, timeout=3)
        if code != 0 or not out:
            continue
        m = re.search(r"level=(\d)", out)
        if m:
            return int(m.group(1))
        if re.search(r"\|\s*lo\b", out):
            return 0
        if re.search(r"\|\s*hi\b", out):
            return 1
    return None


def check_gpio_held_low():
    """Botão preso/fio em curto: o daemon já esperou ~20s com o pino em LOW e
    escreveu `[ALERT] ... stuck LOW`. Se o nível lido agora é HIGH, já soltou."""
    out, done = [], set()
    for l in _unit_lines("gravae-buttons"):
        m = _ALERT_LOW_RE.search(l.get("m") or "")
        if not m or m.group(2) in done:
            continue
        btn, gpio = m.group(1), m.group(2)
        done.add(gpio)
        level = _gpio_level(gpio)
        if level == 1:
            continue
        last = (_state.get("lastPress") or {}).get(btn)
        out.append({
            "type": "gpio_held_low", "severity": "critical",
            "detail": f"botão {btn} (GPIO{gpio}) preso em LOW — não dispara gravação; checar botão/fio em curto",
            "evidence": {"gpio": int(gpio), "button": btn, "level": level, "lastPressTs": last,
                         "line": (l.get("m") or "")[:200]},
            "dedupKey": f"gpio_held_low:GPIO{gpio}",
        })
    return out


def check_gpio_ghost_presses(now=None):
    """Muitas rejeições de glitch ([REJECT]) num botão em 10 min = ruído/fiação
    que antecede disparo fantasma."""
    now = now or time.time()
    for l in _unit_lines("gravae-buttons"):
        m = _REJECT_RE.search(l.get("m") or "")
        if m:
            _rejects.setdefault(m.group(1), []).append(l.get("t") or now)
    out = []
    for gpio in list(_rejects):
        ts = [t for t in _rejects[gpio] if now - t <= GHOST_WINDOW_SEC]
        if not ts:
            del _rejects[gpio]
            continue
        _rejects[gpio] = ts
        if len(ts) >= GHOST_MIN_REJECTS:
            out.append({
                "type": "gpio_ghost_presses", "severity": "medium",
                "detail": f"GPIO{gpio} com {len(ts)} glitches rejeitados em 10 min — ruído/fiação (risco de disparo fantasma)",
                "evidence": {"gpio": int(gpio), "rejectsIn10min": len(ts)},
                "dedupKey": f"gpio_ghost_presses:GPIO{gpio}",
            })
    return out


def check_trigger_rejected():
    """Shinobi recusou o trigger do botão (API key inválida, HTTP != 200, erro de
    conexão): o cliente apertou e nenhum vídeo vai nascer."""
    per_mon = {}
    for l in _unit_lines("gravae-buttons"):
        msg = l.get("m") or ""
        if "[HTTP]" not in msg:
            continue
        m = _HTTP_RE.search(msg)
        refused = bool(_REFUSED_RE.search(msg))
        bad_code = bool(m and m.group(2) != "200")
        if not (refused or bad_code):
            continue
        mon = m.group(1) if m else "desconhecido"
        per_mon.setdefault(mon, []).append(msg[:200])
    bucket = _bucket(600)
    return [{
        "type": "trigger_rejected", "severity": "critical",
        "detail": f"Shinobi recusou o disparo do botão em {mon} — aperto não vira vídeo",
        "evidence": {"monitor": mon, "count": len(lines), "lines": lines[:5]},
        "dedupKey": f"trigger_rejected:{mon}:{bucket}",
    } for mon, lines in per_mon.items()]


def _mysql_unescape(s):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "0": "\0", "\\": "\\"}.get(m.group(1), m.group(1)), s)


def _shinobi_db():
    for path in ("/home/Shinobi/conf.json", "/opt/shinobi/conf.json"):
        try:
            with open(path) as fh:
                return (json.load(fh) or {}).get("db") or {}
        except Exception:
            continue
    return None


def _mysql(sql, timeout=8):
    """Linhas (lista de colunas) da consulta no ccio, como o agent já faz
    (cliente mysql + MYSQL_PWD). None se não deu para consultar."""
    db = _shinobi_db()
    if db is None:
        return None
    env = dict(os.environ)
    env["MYSQL_PWD"] = db.get("password") or ""
    cmd = ["mysql", "-N", "-B", "-u", db.get("user", "majesticflame"), "-h", db.get("host", "localhost"),
           db.get("database", "ccio"), "-e", sql]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return [[_mysql_unescape(c) for c in line.split("\t")] for line in r.stdout.splitlines() if line]


def _stuck_local_files(gk, now):
    old, sample = [], []
    for base in VIDEO_DIRS:
        root = os.path.join(base, gk)
        try:
            mons = os.listdir(root)
        except OSError:
            continue
        for mon in mons:
            d = os.path.join(root, mon)
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for n in names:
                if not n.endswith(".mp4"):
                    continue
                try:
                    st = os.stat(os.path.join(d, n))
                except OSError:
                    continue
                age = now - st.st_mtime
                if st.st_size > 0 and UPLOAD_FILE_STUCK_MIN * 60 <= age <= 2 * 86400:
                    old.append(age)
                    if len(sample) < 5:
                        sample.append(f"{mon}/{n}")
    return old, sample


def check_upload_stuck(run=True):
    """Vídeo com conteúdo parado na Pi: a fila puxa e apaga em minutos.
    Videos status=1 (não lido) com tamanho real há >20 min, ou mp4 >0 byte há
    >30 min na pasta. `run` (camada de ~10 min) faz 1 SQL + 1 varredura de
    pasta; nos outros ciclos repete o último resultado (anomalia persistente)."""
    if not run:
        return list(_upload_cache["out"])
    _, gk = _shinobi_creds()
    out = []
    if gk and _KEY_RE.fullmatch(gk):
        now = time.time()
        rows = _mysql(
            "SELECT mid, time, TIMESTAMPDIFF(MINUTE, time, NOW()) FROM Videos "
            f"WHERE ke='{gk}' AND status=1 AND size>0 AND time < NOW() - INTERVAL {UPLOAD_DB_STUCK_MIN} MINUTE "
            "AND time > NOW() - INTERVAL 2 DAY ORDER BY time LIMIT 200") or []
        db_count = len(rows)
        db_oldest = 0
        try:
            db_oldest = int(rows[0][2]) if rows else 0
        except (ValueError, IndexError):
            pass
        db_sample = [f"{r[0]} {r[1]}" for r in rows[:5] if len(r) >= 2]
        files, fsample = _stuck_local_files(gk, now)
        if db_count >= 2 or len(files) >= 2:
            out.append({
                "type": "upload_stuck", "severity": "high",
                "detail": f"vídeos parados na Pi sem subir (banco: {db_count}, pasta: {len(files)})",
                "evidence": {"dbUnread": db_count, "dbOldestMin": db_oldest, "dbSample": db_sample,
                             "localFiles": len(files),
                             "localOldestMin": int(max(files) / 60) if files else 0,
                             "localSample": fsample},
                "dedupKey": "upload_stuck",
            })
    _upload_cache["out"] = out
    return list(out)


def check_upload_sync_failed():
    hits = [(l.get("m") or "")[:200] for l in _unit_lines("gravae-device-client")
            if _SYNC_FAIL_RE.search(l.get("m") or "")]
    if not hits:
        return []
    return [{
        "type": "upload_sync_failed", "severity": "high",
        "detail": "device-client não sincroniza com a nuvem (403/1010/ARENA_CONFIG_SYNC_FAILED) — vídeos não chegam ao app",
        "evidence": {"lines": hits[:5], "count": len(hits)},
        "dedupKey": f"upload_sync_failed:{_bucket(600)}",
    }]


def _pm2_logs():
    try:
        names = os.listdir(PM2_LOG_DIR)
    except OSError:
        return []
    return sorted(os.path.join(PM2_LOG_DIR, n) for n in names
                  if n.endswith(".log") and re.match(r"(camera|shinobi)", n, re.I))


def check_shinobi_log_errors():
    """Erros do Shinobi que param a gravação em silêncio: EACCES/permissão na
    pasta de vídeos, disco cheio (ENOSPC), 8080 ocupado (EADDRINUSE), API key
    recusada. Lê só o que é novo desde o último offset de cada log do pm2."""
    offsets = _state.setdefault("pm2Offsets", {})
    hits, kinds = [], set()
    for path in _pm2_logs():
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        off = offsets.get(path)
        if off is None or off > size:
            offsets[path] = size if off is None else 0   # 1ª vez: não relê histórico; rotação: do zero
            if off is None:
                continue
            off = 0
        if size == off:
            continue
        start = max(off, size - PM2_LOG_READ_MAX)
        try:
            with open(path, "rb") as fh:
                fh.seek(start)
                data = fh.read(size - start).decode("utf-8", "replace")
        except OSError:
            continue
        offsets[path] = size
        for line in data.splitlines():
            m = _SHINOBI_LOG_RE.search(line)
            if m:
                kinds.add(m.group(0).upper().replace(" ", "_"))
                if len(hits) < 5:
                    hits.append(line.strip()[:300])
    if not hits:
        return []
    return [{
        "type": "shinobi_log_errors", "severity": "high",
        "detail": "erro no log do Shinobi que impede gravar: " + ", ".join(sorted(kinds)),
        "evidence": {"kinds": sorted(kinds), "lines": hits},
        "dedupKey": f"shinobi_log_errors:{_bucket(600)}",
    }]


def _camera_js_procs():
    out = []
    for p in _proc_list():
        argv = p["argv"]
        if p["comm"] != "node" or len(argv) < 2:
            continue
        if any(os.path.basename(a) == "camera.js" for a in argv[1:]):
            out.append({"pid": p["pid"], "uid": p["uid"], "cwd": p.get("cwd")})
    return out


def check_shinobi_duplicate():
    """Mais de um camera.js (pm2 root duplicado): os dois brigam pela 8080 e um
    mata o ffmpeg do outro — monitores sobem e caem."""
    procs = _camera_js_procs()
    if not _confirm("shinobi_duplicate", len(procs) > 1):
        return []
    return [{
        "type": "shinobi_duplicate", "severity": "critical",
        "detail": f"{len(procs)} processos camera.js rodando — Shinobi duplicado derruba os monitores",
        "evidence": {"processes": procs[:5]},
        "dedupKey": "shinobi_duplicate",
    }]


def _boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id") as fh:
            return fh.read().strip()
    except OSError:
        return None


def check_unexpected_reboot(snap):
    """A Pi reiniciou desde a última checagem. Junta as últimas linhas do boot
    anterior (journal persistente) e diz se foi desligamento limpo."""
    bid = snap.get("bootId") or _boot_id()
    if not bid:
        return []
    prev = _state.get("bootId")
    _state["bootId"] = bid
    if not prev or prev == bid:
        return []
    code, out = _run(["journalctl", "-b", "-1", "-n", "40", "--no-pager", "-o", "short-iso"], timeout=10)
    lines = [l[:300] for l in (out or "").splitlines() if l and not l.startswith("-- ")] if code == 0 else []
    clean = any(_CLEAN_SHUTDOWN_RE.search(l) for l in lines) if lines else None
    thr = parse_throttled(snap.get("throttled") and f"throttled={snap['throttled']}")
    return [{
        "type": "unexpected_reboot", "severity": "medium" if clean else "high",
        "detail": "a Pi reiniciou" + (" (desligamento limpo)" if clean else
                                      " sem desligamento limpo — queda de energia/travamento"),
        "evidence": {"previousBootId": prev, "bootId": bid, "cleanShutdown": clean,
                     "undervoltageSinceBoot": bool(thr & 0x10000) if thr is not None else None,
                     "uptimeSec": snap.get("uptimeSec"), "previousBootLastLines": lines[-40:]},
        "dedupKey": f"unexpected_reboot:{bid}",
    }]


def _default_gateway():
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                p = line.split()
                if len(p) > 2 and p[1] == "00000000":
                    g = int(p[2], 16)
                    return ".".join(str((g >> s) & 0xFF) for s in (0, 8, 16, 24))
    except Exception:
        pass
    return None


def parse_ping(text):
    """(perda %, rtt médio ms) do resumo do ping. (None, None) se ilegível."""
    loss = rtt = None
    m = re.search(r"([\d.]+)% packet loss", text or "")
    if m:
        loss = float(m.group(1))
    m = re.search(r"= [\d.]+/([\d.]+)/", text or "")
    if m:
        rtt = float(m.group(1))
    return loss, rtt


def _ping(host, res, key):
    code, out = _run(["ping", "-c", "3", "-W", "1", "-i", "0.3", "-q", host], timeout=PING_TIMEOUT)
    res[key] = parse_ping(out) if out else (None, None)


def _ping_worker():
    res = {}
    gw = _default_gateway()
    for key, host in (("gw", gw), ("net", "1.1.1.1")):
        if host:
            _ping(host, res, key)
    _net["result"] = (gw, res)
    _net["fresh"] = True


def start_ping_round():
    """Dispara os pings numa thread e volta na hora. O resultado é lido pelo
    check no ciclo seguinte; uma rodada pendurada não abre outra."""
    t = _net.get("thread")
    if t is not None and t.is_alive():
        return False
    t = threading.Thread(target=_ping_worker, daemon=True)
    _net["thread"] = t
    t.start()
    return True


def check_network_degraded():
    """Perda de pacote no gateway (≥34%) ou na internet (≥50%), ou latência da
    internet >400ms, em 3 medições seguidas (uma a cada 3 ciclos)."""
    if not _net.get("fresh"):
        return list(_net.get("last_out") or [])
    _net["fresh"] = False
    gw, res = _net["result"]
    gl, _ = res.get("gw", (None, None))
    nl, nr = res.get("net", (None, None))
    bad = (gl is not None and gl >= 34) or (nl is not None and nl >= 50) or (nr is not None and nr > 400)
    out = []
    if _confirm("network_degraded", bad, need=NET_CONFIRM):
        out = [{
            "type": "network_degraded", "severity": "medium",
            "detail": "rede instável na arena (perda de pacote/latência alta)",
            "evidence": {"gateway": gw, "gatewayLossPct": gl, "internetLossPct": nl, "internetRttMs": nr},
            "dedupKey": "network_degraded",
        }]
    _net["last_out"] = out
    return list(out)


def check_ethernet_flapping(now=None):
    now = now or time.time()
    for l in _kernel_lines:
        if _LINK_DOWN_RE.search(l.get("m") or ""):
            _link_downs.append(l.get("t") or now)
    _link_downs[:] = [t for t in _link_downs if now - t <= FLAP_WINDOW_SEC]
    if len(_link_downs) < 2:
        return []
    return [{
        "type": "ethernet_flapping", "severity": "high",
        "detail": f"cabo de rede caiu {len(_link_downs)} vezes em 30 min — cabo/porta/switch",
        "evidence": {"linkDownsIn30min": len(_link_downs)},
        "dedupKey": "ethernet_flapping",
    }]


def check_camera_unstable(now=None):
    """Monitor que morre e volta ≥3 vezes em 1 h: câmera/cabo/PoE falhando
    antes de cair de vez."""
    now = now or time.time()
    mons = _local_get_cached("/phoenix/monitors")
    if not mons:
        return []
    out, alive = [], set()
    for mo in (mons.get("monitors", []) or []):
        mid = mo.get("mid")
        if not mid:
            continue
        alive.add(mid)
        st = str(mo.get("status", "")).lower()
        prev = _mon_status.get(mid)
        if prev in _BAD_STATUS and st in _GOOD_STATUS:
            _mon_recoveries.setdefault(mid, []).append(now)
        _mon_status[mid] = st
        rec = [t for t in _mon_recoveries.get(mid, []) if now - t <= UNSTABLE_WINDOW_SEC]
        if rec:
            _mon_recoveries[mid] = rec
        else:
            _mon_recoveries.pop(mid, None)
        if len(rec) >= UNSTABLE_MIN_RECOVERIES:
            out.append({
                "type": "camera_unstable", "severity": "medium",
                "detail": f"câmera {mo.get('name')} caiu e voltou {len(rec)} vezes em 1 h — cabo/PoE/câmera",
                "evidence": {"mid": mid, "monitor": mo.get("name"), "recoveriesIn1h": len(rec)},
                "dedupKey": f"camera_unstable:{mid}",
            })
    for mid in list(_mon_status):
        if mid not in alive:
            _mon_status.pop(mid, None)
            _mon_recoveries.pop(mid, None)
    return out


def _proc_ticks():
    out = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        try:
            with open(f"/proc/{pid}/stat") as fh:
                raw = fh.read()
            rest = raw[raw.rindex(")") + 2:].split()
            comm = raw[raw.index("(") + 1:raw.rindex(")")]
            out[int(pid)] = (comm, int(rest[11]) + int(rest[12]))
        except (OSError, ValueError, IndexError):
            continue
    return out


def _top_cpu(n=3, interval=1.0):
    a = _proc_ticks()
    time.sleep(interval)
    b = _proc_ticks()
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    rows = []
    for pid, (comm, ticks) in b.items():
        if pid in a:
            rows.append((round(100.0 * (ticks - a[pid][1]) / hz / interval, 1), pid, comm))
    rows.sort(reverse=True)
    top = []
    for pct, pid, comm in rows[:n]:
        item = {"pid": pid, "comm": comm, "cpuPct": pct}
        if comm == "ffmpeg":
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
                m = re.search(r"[A-Za-z0-9]+_camera[0-9]+", cmd)
                item["monitor"] = m.group(0) if m else None
                item["libx264"] = "libx264" in cmd
            except OSError:
                pass
        top.append(item)
    return top


def check_high_cpu(snap):
    load = snap.get("load1")
    cores = os.cpu_count() or 4
    if not _confirm("high_cpu", load is not None and load >= CPU_LOAD_FACTOR * cores, need=4):
        return []
    if _top_cache["cyc"] is None or _cyc - _top_cache["cyc"] >= 10:
        _top_cache.update(cyc=_cyc, top=_top_cpu())   # 2 leituras do /proc + 1s; no máx. a cada ~7 min
    top = _top_cache["top"]
    x264 = [p.get("monitor") for p in top if p.get("libx264")]
    return [{
        "type": "high_cpu", "severity": "medium",
        "detail": f"CPU sobrecarregada (load {load} em {cores} núcleos)"
                  + (f" — ffmpeg reencodando com libx264 em {', '.join(m or '?' for m in x264)}" if x264 else ""),
        "evidence": {"load1": load, "cores": cores, "top": top},
        "dedupKey": "high_cpu",
    }]


def check_phoenix_down(snap):
    return _unit_down_check(snap, "phoenixActive", "phoenix_down", "high",
                            "gravae-phoenix parado — sem auto-recuperação nem alertas da Pi")


def predict_disk_eta_hours(samples, target_pct=DISK_CRIT_PCT):
    """Horas até o disco chegar a `target_pct` livre pela regressão linear das
    amostras (ts, freeMb, totalMb). None se não está enchendo."""
    if len(samples) < 3:
        return None
    t0 = samples[0][0]
    xs = [(s[0] - t0) / 3600.0 for s in samples]
    ys = [float(s[1]) for s in samples]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den   # MB/h
    if slope >= 0:
        return None
    target = samples[-1][2] * target_pct / 100.0
    left = ys[-1] - target
    if left <= 0:
        return 0.0
    return left / -slope


def check_disk_filling(snap, now=None):
    now = now or time.time()
    free, total = snap.get("diskFreeMb"), snap.get("diskTotalMb")
    if free is None or not total:
        return []
    _disk_samples.append((now, free, total))
    _disk_samples[:] = [s for s in _disk_samples if now - s[0] <= DISK_PREDICT_WINDOW_SEC]
    if now - _disk_samples[0][0] < DISK_PREDICT_MIN_SPAN_SEC:
        return []
    if 100.0 * free / total < DISK_CRIT_PCT:
        return []   # disk_full já cobre
    eta = predict_disk_eta_hours(_disk_samples)
    if eta is None or eta >= DISK_PREDICT_HOURS:
        return []
    rate = (_disk_samples[0][1] - free) / max((now - _disk_samples[0][0]) / 3600.0, 1e-6)
    return [{
        "type": "disk_filling", "severity": "medium",
        "detail": f"disco enchendo ~{int(rate)} MB/h — chega a 5% livre em ~{eta:.1f} h",
        "evidence": {"diskFreeMb": free, "diskTotalMb": total, "etaHours": round(eta, 1),
                     "rateMbPerHour": int(rate)},
        "dedupKey": "disk_filling",
    }]


def monitor_config_problems(mid, mode, details, buttons=(), name=None, hevc=False):
    """Lista de problemas conhecidos de configuração de um monitor."""
    probs = []
    d = details if isinstance(details, dict) else {}
    for k in _NUMERIC_DETAIL_KEYS:
        v = d.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            probs.append(f"details.{k} salvo como número ({v}) — Shinobi compara com '1' e não grava")
    if d.get("det_trigger_tags") and d.get("tagLegend") in (None, "", "{}", "[]", {}, []):
        probs.append("det_trigger_tags com tagLegend vazio — trigger quebra (TypeError)")
    if str(d.get("vcodec", "")).lower() == "libx264":
        probs.append("vcodec=libx264 (deveria ser copy) — CPU alta/temperatura")
    if str(d.get("detector_use_motion", "")) == "1":
        probs.append("detector_use_motion=1 (fora do padrão; infla memória do ffmpeg)")
    if mode not in ("start", "record") and (mid in buttons or (name and name in buttons)):
        probs.append(f"mode={mode} num monitor com botão — aperto não grava")
    if str(mid).startswith("mon_"):
        probs.append("mid 'mon_…' quebra o encoding do vídeo no app — renomear p/ canchaNN_cameraNN")
    if hevc:
        probs.append("câmera em H.265 — vídeo não reproduz; trocar para H.264 na câmera")
    return probs


def _hls_codec(gk, mid, name):
    d = _stream_dir(gk, {"mid": mid, "name": name})
    if not d or _ffprobe_missing:
        return None
    try:
        segs = [f for f in os.listdir(d) if f.endswith(".ts")]
        newest = max(segs, key=lambda f: os.path.getmtime(os.path.join(d, f))) if segs else None
    except OSError:
        return None
    if not newest:
        return None
    code, out = _run(_low_prio(["ffprobe", "-v", "error", "-select_streams", "v:0",
                                "-show_entries", "stream=codec_name", "-of", "csv=p=0", os.path.join(d, newest)]),
                     timeout=FFPROBE_TIMEOUT)
    return (out or "").strip().lower() or None if code == 0 else None


def check_config_drift(run=None, now=None):
    """No máximo 1×/hora, só leitura: configuração de monitor que já parou
    gravação em arenas reais. Um aviso por monitor com a lista de problemas
    (repetido a cada ciclo até a próxima leitura)."""
    now = now or time.time()
    if run is None:
        run = now - _drift_cache["ts"] >= DRIFT_EVERY_SEC
    if not run:
        return list(_drift_cache["out"])
    _drift_cache["ts"] = now
    _, gk = _shinobi_creds()
    if not gk or not _KEY_RE.fullmatch(gk):
        return list(_drift_cache["out"])
    rows = _mysql(f"SELECT mid, mode, name, details FROM Monitors WHERE ke='{gk}'")
    if rows is None:
        return list(_drift_cache["out"])
    buttons = set((_state.get("lastPress") or {}).keys())
    out = []
    for r in rows:
        if len(r) < 4:
            continue
        mid, mode, name, raw = r[0], r[1], r[2], r[3]
        try:
            details = json.loads(raw) if raw else {}
        except ValueError:
            details = {}
        hevc = mode in ("start", "record") and _hls_codec(gk, mid, name) == "hevc"
        probs = monitor_config_problems(mid, mode, details, buttons, name, hevc)
        if probs:
            out.append({
                "type": "config_drift", "severity": "medium",
                "detail": f"monitor {name or mid}: " + "; ".join(probs),
                "evidence": {"mid": mid, "monitor": name, "mode": mode, "problems": probs},
                "dedupKey": f"config_drift:{mid}",
            })
    _drift_cache["out"] = out
    return list(out)


def _timezone():
    try:
        p = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in p:
            return p.split("zoneinfo/", 1)[1]
    except OSError:
        pass
    try:
        with open("/etc/timezone") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


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
    global _cycle_lines
    _cycle_lines = keep
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


def _tiers(snap):
    """Quais camadas caras rodam neste ciclo. Com a Pi apertada (load1 > núcleos
    ou RAM < 350 MB) pula todas e registra quantas pulou."""
    want = {
        "net": _cyc % NET_EVERY_CYCLES == 1,
        "upload": _cyc % UPLOAD_EVERY_CYCLES == 1,
        "drift": time.time() - _drift_cache["ts"] >= DRIFT_EVERY_SEC,
        "video": True,
    }
    load, mem = snap.get("load1"), snap.get("memAvailMb")
    tight = (load is not None and load > (os.cpu_count() or 4)) or (mem is not None and mem < BACKOFF_MEM_MB)
    if tight:
        skipped = sum(1 for v in want.values() if v)
        return {k: False for k in want}, skipped
    return want, 0


def _cpu_now():
    t = time.thread_time()
    if resource is not None:
        try:
            ru = resource.getrusage(resource.RUSAGE_CHILDREN)
            t += ru.ru_utime + ru.ru_stime
        except Exception:
            pass
    return t


def _cycle():
    global _cyc, _hb_401, _kernel_lines, _cycle_lines, _dirty
    _cyc += 1
    _cycle_cache.clear()
    cpu0 = _cpu_now()
    started = time.time()
    interval = int(_state.get("interval") or DEFAULT_INTERVAL)
    deadline = started + max(10, interval - 5)
    serial = get_serial()
    secret = _state.get("secret")
    ops = _state.get("opsUrl")
    if not secret or not ops:
        return

    # 1) heartbeat primeiro, com prazo curto, levando o retrato da saúde e o
    #    custo do próprio módulo no ciclo anterior.
    try:
        snap = build_snapshot()
    except Exception as e:
        _log(f"snapshot erro: {e}")
        snap = {}
    tiers, skipped = _tiers(snap)
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

    # 2) caixa preta: UMA leitura do journald por ciclo alimenta todos os checks
    #    de log (botões, device-client, kernel, phoenix). Sem internet vai pro spool.
    try:
        lines, _kernel_lines = collect_journal()
        new_chunks = make_chunks(lines)
    except Exception as e:
        _log(f"journal erro: {e}")
        _kernel_lines, _cycle_lines, new_chunks = [], [], []
    if new_chunks:
        _dirty = True

    _feed_presses(_cycle_lines)
    presses = _recent_presses(3)
    if presses:
        lp = _state.setdefault("lastPress", {})
        for mon, rec in presses.items():
            if rec["last"] > float(lp.get(mon, 0)):
                lp[mon] = rec["last"]
                _dirty = True

    if tiers["net"]:
        start_ping_round()   # resultado entra no check do ciclo seguinte

    found = []
    for fn, args in (
        # camada barata (todo ciclo): /proc, /sys, journal do ciclo, rotas locais
        (check_service_down, ()),
        (check_shinobi_8080, ()),
        (check_press_without_video, (presses,)),
        (check_monitor_died, ()),
        (check_camera_frozen, ()),
        (check_camera_unstable, ()),
        (check_gpio_stuck, (presses,)),
        (check_gpio_idle_24h, ()),
        (check_gpio_held_low, ()),
        (check_gpio_ghost_presses, ()),
        (check_trigger_rejected, ()),
        (check_upload_sync_failed, ()),
        (check_shinobi_log_errors, ()),
        (check_shinobi_duplicate, ()),
        (check_memory_pressure, ()),
        (check_high_cpu, (snap,)),
        (check_undervoltage, (snap,)),
        (check_high_temperature, (snap,)),
        (check_disk_full, (snap,)),
        (check_disk_filling, (snap,)),
        (check_sd_readonly, (snap,)),
        (check_sd_errors, ()),
        (check_oom_kill, ()),
        (check_ethernet_flapping, ()),
        (check_unexpected_reboot, (snap,)),
        (check_clock_unsynced, (snap,)),
        (check_dns_failure, (snap,)),
        (check_tunnel_down, (snap,)),
        (check_database_down, (snap,)),
        (check_buttons_service_down, (snap,)),
        (check_phoenix_down, (snap,)),
        (check_network_degraded, ()),
        # camadas caras (repetem o último resultado quando não rodam)
        (check_upload_stuck, (tiers["upload"],)),
        (check_config_drift, (tiers["drift"],)),
    ):
        try:
            found.extend(fn(*args))
        except Exception as e:
            _log(f"check {fn.__name__} erro: {e}")
    if tiers["video"]:
        try:
            found.extend(check_video_corrupted(deadline))
        except Exception as e:
            _log(f"check check_video_corrupted erro: {e}")

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

    # Estado no SD em lote (cursor, offsets, lastPress): ≤1 escrita a cada ~90s.
    if _cyc % SAVE_EVERY_CYCLES == 0 or _state.get("bootId") != _state.get("_savedBootId"):
        _state["_savedBootId"] = _state.get("bootId")
        save_state()
        _dirty = False
    _cost["cpuMs"] = int((_cpu_now() - cpu0) * 1000)
    _cost["skipped"] = skipped


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
        _start_guard()
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
