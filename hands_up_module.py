"""Ponte do agente para o detector de bracos levantados (No-hands).

POR QUE ISTO EXISTE
    O detector (repo `hands-up-detector`) roda ao lado do Shinobi e escuta em
    `localhost:8090`. Essa porta NAO tem rota no `cloudflared` da arena - o
    tunel publica Shinobi (8080), o agente (8888) e o ssh (22). Como o agente
    JA e alcancavel de fora e ja e o caminho oficial pra mexer na Raspberry,
    e ele quem fala com o detector: o OPS chama o agente, o agente chama o
    localhost.

    Vale a regra do parque: tudo que precisa acontecer na Pi passa por aqui.
    Nada de porta nova, nada de servico exposto direto na internet.

O QUE ELE NAO FAZ
    Nao decide nada. Quais quadras e cameras ficam ligadas e decisao do
    operador no OPS; este modulo so entrega o recado e devolve o que o
    detector respondeu.
"""
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request

# Porta local do detector. Nunca exposta no tunel - e o ponto do modulo.
DETECTOR_URL = os.environ.get("HANDS_UP_URL", "http://127.0.0.1:8090")
SERVICO = "gravae-hands-up"
DIR_PADRAO = "/opt/hands-up-detector"
REPO = "https://github.com/Gravae-Tecnologia/hands-up-detector"

# Curto de proposito: o OPS espera esta chamada dentro de um request HTTP dele.
# Detector pendurado nao pode virar timeout no painel do operador.
TIMEOUT = 8


def _http(caminho, dados=None, timeout=TIMEOUT):
    """Fala com o detector no localhost. Devolve (ok, payload)."""
    url = DETECTOR_URL.rstrip("/") + caminho
    req = urllib.request.Request(
        url,
        data=json.dumps(dados).encode() if dados is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if dados is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            corpo = r.read().decode() or "{}"
        return True, json.loads(corpo)
    except urllib.error.URLError as e:
        # Recusa de conexao = detector nao instalado ou parado. E o caso comum
        # (a frota inteira comeca assim), entao vira resposta normal com
        # `instalado: false`, nao erro - o OPS precisa distinguir os dois.
        return False, {"erro": "detector nao responde", "detalhe": str(getattr(e, "reason", e))}
    except Exception as e:
        return False, {"erro": type(e).__name__, "detalhe": str(e)}


def _systemd(*args):
    try:
        p = subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=20)
        return p.returncode, (p.stdout or p.stderr or "").strip()
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"


def instalado():
    """O servico existe nesta Pi?"""
    rc, _ = _systemd("list-unit-files", f"{SERVICO}.service")
    if rc != 0:
        return False
    rc, saida = _systemd("cat", f"{SERVICO}.service")
    return rc == 0 and bool(saida)


def status():
    """Estado completo pro painel: servico + o que o detector diz de si."""
    rc, ativo = _systemd("is-active", SERVICO)
    ok, dados = _http("/api/config")
    fora = {
        "instalado": instalado(),
        "servico": ativo or "desconhecido",
        "respondendo": ok,
        "instalacao": instalacao_status(),
    }
    if ok:
        fora["config"] = dados
        # `quadras_detalhe` ja vem no formato que o OPS desenha - repassar
        # inteiro evita o agente ter que entender a estrutura.
        fora["quadras"] = dados.get("quadras_detalhe", [])
    else:
        fora["erro"] = dados.get("erro")
    return fora


def aplica(config):
    """Aplica os switches vindos do OPS.

    `config` = {"ativo": bool, "quadras": {...}, "cameras": {...}}.

    Manda um POST por chave porque e essa a API do detector; sao poucas e
    locais (localhost), entao o custo e irrelevante perto de inventar um
    endpoint novo la e ter que versionar os dois juntos.
    """
    if not isinstance(config, dict):
        return {"ok": False, "erro": "config invalida"}

    passos = []

    # Endereco do worker de inferencia e do webhook do gesto vem do OPS, nao
    # do arquivo local. Sem isto, uma Pi instalada apontando pra um endpoint
    # antigo ficava presa nele: `main()` do detector da PRECEDENCIA a config
    # sobre a linha de comando, entao reinstalar nao corrigia. Foi o que
    # aconteceu na primeira arena real - detector rodando, apontando pro worker
    # errado e com webhook vazio, ou seja, detectando pra ninguem.
    #
    # Vao primeiro: se o resto da aplicacao falhar no meio, pelo menos o
    # destino ficou certo.
    for chave in ("nuvem", "webhook"):
        if config.get(chave) is not None:
            ok, _ = _http("/api/config", {chave: config[chave]})
            passos.append({chave: config[chave], "ok": ok})

    if "ativo" in config:
        ok, r = _http("/api/config", {"ativo": bool(config["ativo"])})
        passos.append({"ativo": config["ativo"], "ok": ok})
        if not ok:
            return {"ok": False, "erro": r.get("erro"), "passos": passos}

    for quadra, valor in (config.get("quadras") or {}).items():
        ok, _ = _http("/api/config", {"quadra": quadra, "valor": bool(valor)})
        passos.append({"quadra": quadra, "valor": bool(valor), "ok": ok})

    # As cameras vao DEPOIS das quadras de proposito: ligar a quadra liga as
    # cameras dela no detector, entao aplicar camera antes seria sobrescrito.
    for camera, valor in (config.get("cameras") or {}).items():
        ok, _ = _http("/api/config", {"camera": camera, "valor": bool(valor)})
        passos.append({"camera": camera, "valor": bool(valor), "ok": ok})

    # `nuvem` e `webhook` sao lidos no BOOT do detector (viram `H.cfg`), nao a
    # cada quadro: gravar no arquivo nao basta, tem que reiniciar. Os switches
    # de quadra/camera, esses sim, valem na hora.
    if any(k in config and config[k] is not None for k in ("nuvem", "webhook")):
        rc, _ = _systemd("restart", SERVICO)
        passos.append({"restart": SERVICO, "ok": rc == 0})

    return {"ok": all(p["ok"] for p in passos), "passos": passos, "estado": status()}


#: Estado da instalacao em curso. Existe porque a instalacao NAO cabe numa
#: resposta HTTP: o `cloudflared` da arena corta a requisicao em ~100 s e o
#: clone + venv leva minutos - a primeira tentativa em producao voltou 502 com
#: o processo ainda rodando do outro lado. Agora quem chama recebe "comecou" na
#: hora e acompanha por `/hands-up/status`.
_instalacao = {"estado": "ocioso", "desde": None, "etapa": None,
               "ok": None, "erro": None, "saida": None}
_lock_instalacao = threading.Lock()


def instalacao_status():
    return dict(_instalacao)


def instala(ops_evento_url="", nuvem_url="", diretorio=DIR_PADRAO):
    """Dispara a instalacao em segundo plano e devolve na hora.

    Uma instalacao por vez: duas em paralelo brigariam pelo mesmo diretorio.
    """
    with _lock_instalacao:
        if _instalacao["estado"] == "rodando":
            return {"ok": False, "ja_rodando": True, "instalacao": instalacao_status()}
        _instalacao.update({"estado": "rodando", "desde": time.time(),
                            "etapa": "clone", "ok": None, "erro": None,
                            "saida": None})

    threading.Thread(
        target=_instala_agora,
        args=(ops_evento_url, nuvem_url, diretorio),
        daemon=True,
    ).start()
    return {"ok": True, "iniciado": True, "instalacao": instalacao_status()}


def _instala_agora(ops_evento_url, nuvem_url, diretorio):
    try:
        r = _instala_bloqueante(ops_evento_url, nuvem_url, diretorio)
    except Exception as e:
        r = {"ok": False, "etapa": "excecao", "erro": f"{type(e).__name__}: {e}"}
    with _lock_instalacao:
        _instalacao.update({
            "estado": "concluido" if r.get("ok") else "falhou",
            "etapa": r.get("etapa"), "ok": bool(r.get("ok")),
            "erro": r.get("erro"), "saida": (r.get("saida") or "")[-800:],
        })


def _instala_bloqueante(ops_evento_url="", nuvem_url="", diretorio=DIR_PADRAO):
    """Clona (ou atualiza) o detector e sobe o servico.

    Idempotente: rodar de novo numa Pi que ja tem so atualiza o codigo. O
    instalador do proprio repo NAO sobrescreve `/etc/gravae/hands-up.json`,
    entao os switches que o operador ligou sobrevivem a atualizacao.
    """
    if not os.path.isdir(os.path.join(diretorio, ".git")):
        rc = subprocess.run(
            ["git", "clone", "--depth", "1", REPO, diretorio],
            capture_output=True, text=True, timeout=600,
        )
        if rc.returncode != 0:
            return {"ok": False, "etapa": "clone", "erro": (rc.stderr or "")[-500:]}
    else:
        subprocess.run(["git", "-C", diretorio, "pull", "--ff-only"],
                       capture_output=True, text=True, timeout=300)

    cmd = ["./instalar.sh"]
    if nuvem_url:
        cmd += ["--nuvem", nuvem_url]
    else:
        cmd += ["--local"]
    if ops_evento_url:
        cmd += ["--webhook", ops_evento_url]

    p = subprocess.run(cmd, cwd=os.path.join(diretorio, "rasp"),
                       capture_output=True, text=True, timeout=900)
    return {
        "ok": p.returncode == 0,
        "etapa": "instalar.sh",
        "saida": (p.stdout or "")[-2000:],
        "erro": (p.stderr or "")[-1000:] if p.returncode != 0 else None,
        "estado": status(),
    }


def para():
    """Desliga tudo e para o servico.

    Desliga ANTES de parar: se o servico voltar sozinho (Restart=always, ou um
    reboot), ele volta com as cameras desligadas em vez de retomar consumo que
    o operador mandou parar.
    """
    _http("/api/config", {"ativo": False})
    rc, saida = _systemd("stop", SERVICO)
    return {"ok": rc == 0, "saida": saida, "estado": status()}
