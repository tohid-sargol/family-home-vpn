#!/usr/bin/env bash
set -e

if [ -z "${BASH_SOURCE[0]}" ] || [ ! -f "${BASH_SOURCE[0]}" ]; then
    INSTALL_DIR="$HOME/family-home-vpn"
    if [ ! -f "$INSTALL_DIR/portal.py" ]; then
        echo "Cloning family-home-vpn repository to $INSTALL_DIR..."
        if command -v git >/dev/null 2>&1; then
            git clone https://github.com/tohid-sargol/family-home-vpn.git "$INSTALL_DIR"
        else
            echo "Downloading repository archive..."
            mkdir -p "$INSTALL_DIR"
            curl -fsSL https://github.com/tohid-sargol/family-home-vpn/archive/refs/heads/main.tar.gz | tar -xz -C /tmp/
            cp -r /tmp/family-home-vpn-main/* "$INSTALL_DIR/" 2>/dev/null || true
            rm -rf /tmp/family-home-vpn-main
        fi
    fi
    SCRIPT_DIR="$INSTALL_DIR"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
cd "$SCRIPT_DIR"

LOG_FILE="$SCRIPT_DIR/setup-diagnostics.log"

log() {
    local level="$1"
    local msg="$2"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$ts] [$level] $msg" | tee -a "$LOG_FILE"
}

clear
echo "=========================================================================="
echo "   HOME VPN PLATFORM -- LINUX & MACOS ZERO-TOUCH INSTALLER (v3.0)        "
echo "   Zero Router Port Forwarding | Zero Domain Cost | Bilingual Support    "
echo "=========================================================================="
echo ""

log "HEADER" "Starting Home VPN setup session on $(uname -s) ($(uname -m))..."

# 1. User Prompts
echo ""
echo "Please provide 3 quick settings (or press Enter to accept defaults):"
echo ""

read -r -p "1) Enter Admin Password [Press ENTER to auto-generate]: " rawPass
if [ -z "$rawPass" ]; then
    adminPassword="Admin-$(openssl rand -hex 4 2>/dev/null || tr -dc A-Za-z0-9 </dev/urandom | head -c 8)"
    log "SUCCESS" "Auto-generated secure Admin Password: $adminPassword"
else
    adminPassword="$rawPass"
    log "INFO" "Custom Admin Password provided."
fi

read -r -p "2) Enter Family Invite Code [Press ENTER for 'FAMILY2026']: " rawInvite
if [ -z "$rawInvite" ]; then
    inviteCode="FAMILY2026"
else
    inviteCode="$(echo "$rawInvite" | tr '[:lower:]' '[:upper:]')"
fi
log "SUCCESS" "Family Invite Code: $inviteCode"

read -r -p "3) Configure Telegram Alerts? (y/N): " rawTg
tgEnabled=false
tgToken=""
tgChatId=""
if [[ "$rawTg" =~ ^[yY] ]]; then
    read -r -p "   -> Enter Telegram Bot Token: " tgToken
    read -r -p "   -> Enter Your Telegram Chat ID: " tgChatId
    if [ -n "$tgToken" ] && [ -n "$tgChatId" ]; then
        tgEnabled=true
        log "SUCCESS" "Telegram alerts configured."
    fi
fi

# 2. Python Runtime Detection
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    log "ERROR" "Python 3 is required. Please install python3 and pip."
    exit 1
fi
log "SUCCESS" "Python runtime detected: $($PYTHON_BIN --version)"

# Install dependencies
log "INFO" "Checking and installing required pip dependencies..."
$PYTHON_BIN -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet --disable-pip-version-check || true

# 3. Port Conflict Detection
get_free_port() {
    local port=$1
    while true; do
        if ! command -v nc >/dev/null 2>&1 || ! nc -z 127.0.0.1 "$port" 2>/dev/null; then
            echo "$port"
            return
        fi
        port=$((port + 1))
    done
}

portalPort=$(get_free_port 8080)
xuiPort=$(get_free_port 2053)
vpnPort=$(get_free_port 10000)
log "SUCCESS" "Assigned ports: Portal=$portalPort, 3x-ui=$xuiPort, VPN=$vpnPort"

# 4. Power & Sleep Configuration
OS_TYPE="$(uname -s)"
if [ "$OS_TYPE" = "Darwin" ]; then
    log "INFO" "Configuring macOS power management..."
    sudo pmset -c disablesleep 1 2>/dev/null || true
    log "SUCCESS" "Sleep disabled on AC power for macOS."
elif [ "$OS_TYPE" = "Linux" ]; then
    log "INFO" "Configuring Linux power management..."
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target 2>/dev/null || true
        log "SUCCESS" "Systemd sleep targets masked."
    fi
fi

# 5. Save Configuration Files
cat <<EOF > "$SCRIPT_DIR/config.json"
{
  "PORTAL_PORT": $portalPort,
  "XUI_PORT": $xuiPort,
  "VPN_PORT": $vpnPort,
  "INVITE_CODE": "$inviteCode",
  "XUI_API_TOKEN": "hUNP2ShXYRwWigG7zvKFoAwC7edTVAAv9hBuh93FMyJdY0zt"
}
EOF
log "SUCCESS" "Saved config.json."

# Calculate PBKDF2 hash using python
$PYTHON_BIN -c "
import os, json, secrets, hashlib, datetime

salt_hex = secrets.token_hex(16)
salt = bytes.fromhex(salt_hex)
pwd = '''$adminPassword'''.strip()
pwd_hash = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt, 100000).hex()

auth_data = {
    'username': 'admin',
    'salt': salt_hex,
    'password_hash': pwd_hash,
    'initial_password': pwd,
    'is_custom': True,
    'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}
with open('admin_auth.json', 'w') as f:
    json.dump(auth_data, f, indent=2)
"
log "SUCCESS" "Saved admin_auth.json."

cat <<EOF > "$SCRIPT_DIR/telegram_config.json"
{
  "enabled": $tgEnabled,
  "bot_token": "$tgToken",
  "chat_id": "$tgChatId"
}
EOF
log "SUCCESS" "Saved telegram_config.json."

# 6. Launch Portal in Background
log "HEADER" "Launching Home VPN Portal in background..."
nohup "$PYTHON_BIN" "$SCRIPT_DIR/portal.py" > /dev/null 2>&1 &
echo $! > "$SCRIPT_DIR/portal.pid"

# Wait for server ready
echo -n "Waiting for portal on port $portalPort..."
for i in {1..20}; do
    sleep 1
    echo -n "."
    if curl -s "http://127.0.0.1:$portalPort/api/status" >/dev/null 2>&1; then
        break
    fi
done
echo ""

# 7. Open Browser
ADMIN_URL="http://127.0.0.1:$portalPort/admin"
log "SUCCESS" "Opening browser to $ADMIN_URL..."
if [ "$OS_TYPE" = "Darwin" ]; then
    open "$ADMIN_URL" 2>/dev/null || true
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$ADMIN_URL" 2>/dev/null || true
fi

echo ""
echo "=========================================================================="
echo "                  INSTALLATION COMPLETED SUCCESSFULLY!                    "
echo "=========================================================================="
echo ""
echo "  🔑 Admin Username:       admin"
echo "  🔑 Admin Password:       $adminPassword"
echo "  🎫 Family Invite Code:   $inviteCode"
echo "  🌐 Local Admin URL:      $ADMIN_URL"
echo ""
echo "  💡 Keep this computer plugged in for 24/7 family access."
echo "=========================================================================="
echo ""
