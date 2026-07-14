#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/kungfunici/Sentinel.git"
SENTINEL_DIR="/opt/sentinel"
SENTINEL_USER="${1:-pi}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root (or with sudo)."
    exit 1
fi

echo "==> Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git tcpdump

echo "==> Cloning / updating repository..."
if [ -d "$SENTINEL_DIR" ]; then
    cd "$SENTINEL_DIR"
    git fetch origin
    git reset --hard origin/main
else
    git clone "$REPO_URL" "$SENTINEL_DIR"
fi
chown -R "$SENTINEL_USER:$SENTINEL_USER" "$SENTINEL_DIR"

echo "==> Setting up Python virtual environment..."
su -c "python3 -m venv '$SENTINEL_DIR/.venv'" "$SENTINEL_USER"
su -c "'$SENTINEL_DIR/.venv/bin/pip' install -e '$SENTINEL_DIR' --quiet" "$SENTINEL_USER"

if [ ! -f "$SENTINEL_DIR/sentinel.json" ]; then
    cp "$SENTINEL_DIR/sentinel.example.json" "$SENTINEL_DIR/sentinel.json"
    chown "$SENTINEL_USER:$SENTINEL_USER" "$SENTINEL_DIR/sentinel.json"
    echo "==> Created sentinel.json from example."
    echo "    Edit it before starting: sudo nano $SENTINEL_DIR/sentinel.json"
fi

echo "==> Writing update helper script..."
cat > "$SENTINEL_DIR/scripts/update.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
DIR="/opt/sentinel"
cd "$DIR"
echo "Fetching latest code..."
git fetch origin 2>/dev/null || echo "  git fetch failed (offline?)"
git reset --hard origin/main 2>/dev/null || echo "  git reset failed (offline?)"
.venv/bin/pip install -e "$DIR" --quiet 2>/dev/null || echo "  pip install failed"
SCRIPT

chmod +x "$SENTINEL_DIR/scripts/update.sh"

echo "==> Installing systemd service..."
cat > /etc/systemd/system/sentinel.service <<SYSTEMD
[Unit]
Description=Sentinel Network Security Monitor
Documentation=https://github.com/kungfunici/Sentinel
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$SENTINEL_DIR
ExecStartPre=$SENTINEL_DIR/scripts/update.sh
ExecStart=$SENTINEL_DIR/.venv/bin/python -m sentinel.main
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
SYSTEMD

echo "==> Installing daily update service..."
cat > /etc/systemd/system/sentinel-update.service <<SYSTEMD
[Unit]
Description=Sentinel daily update (fetch + restart)

[Service]
Type=oneshot
ExecStart=$SENTINEL_DIR/scripts/update.sh
ExecStart=/usr/bin/systemctl restart sentinel.service
SYSTEMD

echo "==> Installing daily timer..."
cat > /etc/systemd/system/sentinel-update.timer <<SYSTEMD
[Unit]
Description=Trigger sentinel daily update

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1800

[Install]
WantedBy=timers.target
SYSTEMD

echo "==> Enabling and starting services..."
systemctl daemon-reload
systemctl enable sentinel.service
systemctl enable sentinel-update.timer
systemctl start sentinel-update.timer

echo ""
echo "========================"
echo "Setup complete!"
echo ""
echo "Before starting, edit config:"
echo "  sudo nano $SENTINEL_DIR/sentinel.json"
echo ""
echo "Then start Sentinel:"
echo "  sudo systemctl start sentinel"
echo ""
echo "To check status:"
echo "  sudo systemctl status sentinel"
echo "  sudo journalctl -fu sentinel"
echo ""
echo "Daily updates run automatically at ~midnight."
echo "========================"
