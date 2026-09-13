# Agent 4.0.0 — DIRECT

Este repositório contém o agent HTTP existente e o runtime DIRECT. A atualização do agent HTTP não altera automaticamente o modo da arena nem instala a malha privada. A migração é feita pelo instalador do OPS, em coordenação com o backend e WireGuard.

## Conteúdo

- `device_gateway_client.py`: Socket.IO /devices, identidade mediaDeviceId=shinobi.id, reconexão, ACK de aplicação e outbox persistente.
- `direct_publisher.py`: uma live por monitor, múltiplos monitores, RTSP nativo em copy e destino RTMP/RTMPS recebido no comando. Sem HLS como fonte da live. Retry inicial até 60 segundos.
- `direct_upload_queue.py`, `adaptive_upload.py`: fila durável e upload direto com token individual; redução de banda em live e pausa sob degradação severa.
- `shinobi_upload_hook.js`, `video_completion_webhook.py`: evento de MP4 finalizado, webhook autenticado somente em loopback e reconciliação a cada 300 segundos.
- `device_readiness.py`: checks leves por ciclo de 15 segundos; decode estrito por monitor a cada 300 segundos, uma thread e nice 15; falhas estruturais invalidam o cache e falhas de decode são reavaliadas após 60 segundos.
- `confirmed_video_cleanup.py`: exclusão local pela API Shinobi apenas após upload confirmado; preserva a fila e o histórico.
- `direct_installer.py`: instalador root-only usado pelo OPS, com identidade física, backup, instalação privada e verificação antes de ativar DIRECT. As unidades systemd ficam junto dele.

## Upload somente em DIRECT

O uploader exige `/etc/gravae/media-mode.json`, gravado atomicamente pelo OPS via SSH autenticado. Ele valida arena, mediaDeviceId, modo e prazo. LEGACY, identidade incorreta, modo ausente ou confirmação expirada bloqueiam coleta e envio. A fila é preservada.

O worker OPS renova a confirmação a cada 30 segundos, com validade de 120 segundos. Antes de voltar para LEGACY pelo OPS, fecha a permissão local e só então chama o backend. Alterações externas dependem da reconciliação; a expiração é contada desde a última renovação local. Envios adaptativos verificam o bloqueio entre blocos.

**Não instalar o uploader 4.0 isoladamente sem a renovação de modo pelo worker OPS.** Sem renovação, uploads ficam bloqueados intencionalmente. O modo só é alterado pelo endpoint oficial do backend; a Raspberry não recebe EXTERNAL_KEY nem credencial permanente de R2.

## Instalação e compatibilidade

O instalador OPS copia estes módulos para `/opt/gravae-device-client` e `/opt/gravae-direct-queue`, configura dependências de `requirements-direct.txt`, VPN, identidade, RTSP e webhook. Requer Python 3.9+, FFmpeg/ffprobe com RTSP, WireGuard, systemd e Shinobi com a extensão nativa de vídeo concluído. O hot reload requer credencial super já configurada localmente; falha bloqueia a instalação sem reiniciar Shinobi.

`install.sh` continua instalando o agent HTTP legado. O `VERSION=4.0.0` do HTTP não prova que a arena está em DIRECT; usar o mediaMode confirmado e a verificação do runtime. Monitores, gravações, fila e configuração legada são preservados. Nenhuma migração da frota é disparada por este merge.

## Validação

Executar `python3 -m unittest discover -s tests -p 'test_*.py'` e `node tests/shinobi_upload_hook.test.cjs`.

O núcleo anterior à regra de modo foi testado na Raspberry piloto: lives RTSP simultâneas, upload por evento e menor uso periódico de CPU. A nova sincronização de modo e o instalador completo do OPS ainda exigem homologação LEGACY/DIRECT antes do rollout de frota. ACK com eventId e HLS de todas as câmeras são requisitos de aceite, não são afrouxados por esta versão.
