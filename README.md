# Gravae Arena Agent (Python)

Agent de monitoramento e controle para Raspberry Pi nas arenas Gravae/Replayme.

## Funcionalidades

### gravae_agent.py
- **Sistema**: Monitoramento de CPU, memória, disco, temperatura
- **Shinobi**: Configuração de conta, API keys, monitores
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
| `/shinobi/setup` | `{groupKey, email, password}` | Configurar conta Shinobi |
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

- Agent: 2.8.3
- Phoenix: 1.0.0

## Requisitos

- Python 3.7+
- Raspberry Pi OS (Bookworm/Trixie recomendado)
- Node.js (para button daemon)
- Shinobi NVR instalado

## Licença

Proprietary - Gravae/Replayme
