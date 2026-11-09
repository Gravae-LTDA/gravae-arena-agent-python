# Gravae Arena Agent (Python)

Agent de monitoramento e controle para Raspberry Pi nas arenas Gravae/Replayme.

### Ultra Watch 2.0 (agent 4.2.0)

- `POST /observation/enable` aceita `mode` (`semana` ou `fixo`). Sem `until` o modo roda até ser desligado. `/observation/status` informa `mode`, `obsVersion` e `supportsJournal`.
- O heartbeat leva `snapshot` com temperatura, `get_throttled`, memória, disco, rootfs somente leitura, load, uptime, NTP, DNS e estado do cloudflared, MariaDB e gravae-buttons.
- Caixa preta: as linhas novas do journald (serviços Gravaê, cloudflared, MariaDB, kernel com prioridade warning ou mais grave e qualquer erro) vão para `POST /api/observation/journal` em chunks com `seq`. Sem internet, os chunks ficam em `/var/lib/gravae/obs-spool/` (até 2 MB, descarta os mais antigos) e são enviados quando a conexão volta.
- Checks novos: `undervoltage`, `high_temperature`, `disk_full`, `sd_readonly`, `sd_errors`, `oom_kill`, `clock_unsynced`, `dns_failure`, `tunnel_down`, `database_down` e `buttons_service_down`.
- `video_corrupted`: MP4 terminado (mtime de 15 s ou mais) com 0 byte, ffprobe com falha, sem trilha de vídeo ou com 0,5 s ou menos. Cada arquivo é sondado uma vez, até 6 por ciclo, com `nice`. Arquivo que a fila apagou não conta.
- `/observation/status` lê o estado salvo mesmo antes da retomada, logo após update ou restart.
- Menos falso positivo: `monitor_died`, memória e os checks de serviço exigem 2 ciclos seguidos. `service_down` e `shinobi_port_dead` testam de novo após 5 s.
- Checks do sistema de vídeo:
  - Botões: `gpio_held_low`, `gpio_ghost_presses` e `trigger_rejected`.
  - Upload: `upload_stuck` e `upload_sync_failed`.
  - Shinobi: `shinobi_log_errors` e `shinobi_duplicate`.
  - Pi e rede: `unexpected_reboot`, `network_degraded`, `ethernet_flapping`, `high_cpu`, `phoenix_down` e `disk_filling`.
  - Câmeras e configuração: `camera_unstable` e `config_drift`.
- Guardião de memória:
  - Limites relativos à RAM: aviso com ffmpeg em max(300 MB, 20%) ou RAM livre abaixo de 20%; ação com ffmpeg em max(450 MB, 35%) ou RAM livre abaixo de 12% com um ffmpeg no topo.
  - Acompanha a tendência de cada ffmpeg e tem uma via rápida a cada 10 s.
  - Com autoheal ligado, derruba o ffmpeg que está vazando (SIGTERM, depois SIGKILL). Se a memória continua no limite 60 s depois, roda `pm2 restart camera`.
  - Cooldown de 10 min por monitor. Com 3 kills em 2 h, para de derrubar e escala com `ffmpeg_leak_recurring`.
- Orçamento de recursos:
  - Ciclo barato abre no máximo 3 processos: 1 `journalctl` para todos os checks de log, 1 `systemctl show` para todas as units e o `vcgencmd` só se não houver sysfs.
  - Pings a cada 3 ciclos, numa thread que não bloqueia o ciclo.
  - Consulta de vídeos parados a cada ~10 min. `config_drift` 1 vez por hora.
  - `ffprobe` com `ionice -c3` e `nice 19`.
  - Com load acima do nº de núcleos ou RAM livre abaixo de 350 MB, pula as camadas caras.
  - Estado gravado no SD a cada ~90 s.
  - O snapshot leva `obsCpuMs`, `obsRssMb`, `obsSkipped`, `tz` e `bootId`.
- Heartbeat com 2 tentativas de 10 s. Após 10 respostas 401 seguidas (modo desligado no OPS), a Pi desliga a observação.

### Correções 4.0.4

- Instalação Hands-up aceita `revision` com SHA completo e verifica o checkout antes de executar o instalador. Alterações locais impedem a instalação fixada.
- Falhas de atualização Git interrompem a instalação; chamadas legadas continuam aceitas sem revisão.

### Correções 4.0.3

- Observação aceita `autoheal: false`, persistido e preservado na retomada, para diagnosticar sem reiniciar o processo de câmeras.
- `/observation/status` informa `supportsAutohealPolicy` e `autohealEnabled`; o OPS verifica a capacidade antes de ativar o piloto.
- Chamadas legadas sem esse campo preservam a política anterior. A atualização controlada continua restrita à Raspberry piloto.

### Correções 4.0.2

- Diagnóstico NetworkManager consulta o método IPv4 do perfil ativo por UUID, sem criar ou alterar conexões. Interfaces sem perfil confirmado retornam DHCP desconhecido.
- Consulta `GET /observation/status` retorna estado aplicado e execução da observação sem segredo HMAC.
- Atualizador controlado do piloto aceita 4.0.2 e preserva processos de gateway, upload e mídia. Atualização da frota continua sendo uma operação explícita pelo OPS.

## Funcionalidades

### gravae_agent.py
- **Sistema**: Monitoramento de CPU, memória, disco, temperatura
- **Shinobi**: Configuração de conta, API keys, monitores, FTP events (alarm input)
- **Cloudflare Tunnel**: Setup de tunnels (quick ou named)
- **Terminal**: Acesso remoto via PTY
- **Buttons**: Deploy e controle do button daemon
- **Phoenix**: Integração com daemon de self-healing
- **Updates**: Auto-atualização via git pull

### phoenix_daemon.py
- **Service Guardian**: Monitora e reinicia serviços críticos
- **Connectivity Sentinel**: Detecta e recupera perda de conexão
- **Network Recovery**: Troca entre IP estático e DHCP
- **Resource Monitor**: Alerta sobre temperatura, disco, memória
- **Alert Queue**: Armazena alertas offline para sync posterior

## Instalação

### Via Script (Recomendado)
```bash
sudo ./install.sh [arena_type] [arena_user]

# Exemplos:
sudo ./install.sh gravae pi
sudo ./install.sh replayme gravae
```

### Manual
```bash
# Copiar arquivos
sudo mkdir -p /opt/gravae-agent
sudo cp gravae_agent.py /opt/gravae-agent/
sudo cp phoenix_daemon.py /opt/gravae-agent/
sudo chmod +x /opt/gravae-agent/*.py

# Criar diretórios
sudo mkdir -p /etc/gravae
sudo mkdir -p /var/log/gravae

# Criar serviços (ver install.sh)
# ...

# Iniciar
sudo systemctl enable gravae-agent gravae-phoenix
sudo systemctl start gravae-agent gravae-phoenix
```

## API Endpoints

### GET
| Endpoint | Descrição |
|----------|-----------|
| `/` | Status básico do agent |
| `/health` | Health check |
| `/system/info` | Informações completas do sistema |
| `/system/memory` | Uso de memória |
| `/system/cpu` | Uso de CPU |
| `/system/disk` | Uso de disco |
| `/system/uptime` | Uptime do sistema |
| `/hardware/info` | Modelo, serial, GPIO |
| `/buttons/status` | Status do button daemon |
| `/discovery` | Discovery completo (para import) |
| `/phoenix/status` | Status do Phoenix daemon |
| `/phoenix/alerts` | Alertas pendentes |
| `/phoenix/logs` | Logs recentes |
| `/update/check` | Verificar atualizações |
| `/update/status` | Status da atualização |

### POST
| Endpoint | Body | Descrição |
|----------|------|-----------|
| `/shinobi/setup` | `{groupKey, email, password, hasAlarmInput?}` | Configurar conta Shinobi (com FTP events opcional) |
| `/shinobi/cleanup` | `{groupKey, email, password}` | Limpar conta Shinobi |
| `/tunnel/setup` | `{type, tunnelToken?, ...}` | Configurar tunnel |
| `/tunnel/run` | `{tunnelToken, tunnelName?}` | Rodar tunnel com token |
| `/buttons/deploy` | `{script}` | Deploy do button daemon |
| `/update/perform` | - | Executar atualização |
| `/terminal/create` | - | Criar sessão terminal |
| `/terminal/input` | `{sessionId, data}` | Enviar input |
| `/terminal/resize` | `{sessionId, cols, rows}` | Redimensionar |
| `/terminal/close` | `{sessionId}` | Fechar sessão |

## Atualização

O agent pode ser atualizado remotamente:

1. **Via Plataforma**: Clique em "Atualizar" na página de monitoramento
2. **Via API**: `POST /update/perform`
3. **Manual**:
```bash
cd /opt/gravae-agent
git pull origin main
sudo systemctl restart gravae-agent gravae-phoenix
```

## Logs

```bash
# Agent logs
journalctl -u gravae-agent -f

# Phoenix logs (JSON)
tail -f /var/log/gravae/phoenix.log

# Button daemon logs
journalctl -u gravae-buttons -f
```

## Versão

- Agent: 2.10.2
- Phoenix: 1.4.0

## Requisitos

- Python 3.7+
- Raspberry Pi OS (Bookworm/Trixie recomendado)
- Node.js (para button daemon)
- Shinobi NVR instalado

## Licença

Proprietary - Gravae/Replayme
# Fila de upload DIRECT (4.0.10)

O uploader mantém no máximo quatro vídeos em processamento simultâneo por Raspberry.
Os demais permanecem na fila SQLite e só são reservados quando uma vaga é liberada
por conclusão ou falha. Retries respeitam o backoff e a fila sobrevive a reboot.
O limite adaptativo de banda é compartilhado pelos quatro envios, inclusive durante
live. No transporte curl, cada envio recebe um quarto do limite configurado e pausa
quando uma live começa. O status expõe `maxConcurrentUploads`, `activeUploadCount`
e `occupiedSlots` (incluindo notificações de falha em andamento).
