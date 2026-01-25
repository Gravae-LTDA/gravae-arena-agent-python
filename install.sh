#!/bin/bash
# Gravae Arena Agent - Installation Script
# Run as root or with sudo

set -e

INSTALL_DIR="/opt/gravae-agent"
CONFIG_DIR="/etc/gravae"
LOG_DIR="/var/log/gravae"

echo "=== Gravae Arena Agent Installer ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

# Detect arena type from argument or prompt
ARENA_TYPE=${1:-"gravae"}
ARENA_USER=${2:-"pi"}

echo "Arena Type: $ARENA_TYPE"
echo "Arena User: $ARENA_USER"
echo ""

# Create directories
echo "Creating directories..."
mkdir -p $INSTALL_DIR
mkdir -p $CONFIG_DIR
mkdir -p $LOG_DIR
mkdir -p $LOG_DIR/network_backup

# Get device serial
DEVICE_SERIAL=$(cat /proc/cpuinfo | grep Serial | awk '{print $3}' || echo "unknown")
echo "Device Serial: $DEVICE_SERIAL"

# Copy agent files
echo "Installing agent files..."
cp gravae_agent.py $INSTALL_DIR/
cp phoenix_daemon.py $INSTALL_DIR/
chmod +x $INSTALL_DIR/gravae_agent.py
chmod +x $INSTALL_DIR/phoenix_daemon.py

# Create config file
echo "Creating configuration..."
cat > $CONFIG_DIR/device.json << EOF
{
  "arenaType": "$ARENA_TYPE",
  "arenaUser": "$ARENA_USER",
  "deviceId": "$DEVICE_SERIAL",
  "installedAt": "$(date -Iseconds)"
}
EOF

# Create Agent systemd service
echo "Creating Agent service..."
cat > /etc/systemd/system/gravae-agent.service << 'EOF'
[Unit]
Description=Gravae Arena Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/gravae-agent/gravae_agent.py
Restart=always
RestartSec=10
User=root
WorkingDirectory=/opt/gravae-agent

[Install]
WantedBy=multi-user.target
EOF

# Create Phoenix systemd service
echo "Creating Phoenix service..."
cat > /etc/systemd/system/gravae-phoenix.service << 'EOF'
[Unit]
Description=Gravae Phoenix Self-Healing Daemon
After=network.target gravae-agent.service
Wants=gravae-agent.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/gravae-agent/phoenix_daemon.py
Restart=always
RestartSec=30
User=root
WorkingDirectory=/opt/gravae-agent
# Memory limit to keep Phoenix lightweight
MemoryMax=50M
MemoryHigh=40M

[Install]
WantedBy=multi-user.target
EOF

# Create Button Daemon service (placeholder)
ARENA_DIR="/home/$ARENA_USER/Documents/${ARENA_TYPE^}"
mkdir -p $ARENA_DIR

cat > /etc/systemd/system/gravae-buttons.service << EOF
[Unit]
Description=Gravae Button Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node $ARENA_DIR/button-daemon.js
Restart=always
RestartSec=10
User=root
WorkingDirectory=$ARENA_DIR

[Install]
WantedBy=multi-user.target
EOF

# Create placeholder button daemon
if [ ! -f "$ARENA_DIR/button-daemon.js" ]; then
    echo "console.log('Button daemon placeholder - waiting for config');" > $ARENA_DIR/button-daemon.js
fi

# Fix ownership
chown -R $ARENA_USER:$ARENA_USER /home/$ARENA_USER/Documents || true

# Reload and enable services
echo "Enabling services..."
systemctl daemon-reload
systemctl enable gravae-agent
systemctl enable gravae-phoenix
systemctl enable gravae-buttons || true

# Start services
echo "Starting services..."
systemctl restart gravae-agent
sleep 3
systemctl restart gravae-phoenix

# Test agent
echo ""
echo "Testing agent..."
if curl -s http://localhost:8888/health | grep -q "ok"; then
    echo "Agent health check: OK"
else
    echo "Agent health check: FAILED"
fi

# Check Phoenix status
if systemctl is-active --quiet gravae-phoenix; then
    echo "Phoenix daemon: RUNNING"
else
    echo "Phoenix daemon: NOT RUNNING"
fi

echo ""
echo "=== Installation Complete ==="
echo "Device ID: $DEVICE_SERIAL"
echo ""
echo "Agent API: http://localhost:8888"
echo "Logs: $LOG_DIR"
echo ""
echo "Commands:"
echo "  systemctl status gravae-agent     # Check agent status"
echo "  systemctl status gravae-phoenix   # Check phoenix status"
echo "  journalctl -u gravae-agent -f     # Follow agent logs"
echo "  cat $LOG_DIR/phoenix.log          # View phoenix logs"
