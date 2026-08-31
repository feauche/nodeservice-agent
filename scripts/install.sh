#!/bin/sh
# Установка агента NodeService: релиз с GitHub, systemd-юнит, привязка к панели.
# Запуск (команду с токеном выдаёт панель):
#   curl -fsSL https://raw.githubusercontent.com/LumaxDev/nodeservice-agent/main/scripts/install.sh \
#     | sh -s -- --panel https://panel.example.com --token nse_...
set -eu

REPO="LumaxDev/nodeservice-agent"
BIN_PATH="/usr/local/bin/nodeservice-agent"
STATE_DIR="/var/lib/nodeservice-agent"
ENV_FILE="/etc/nodeservice-agent.env"
UNIT_PATH="/etc/systemd/system/nodeservice-agent.service"
AGENT_USER="nodesvc-agent"

say()  { printf '\033[36m→\033[0m %s\n' "$1"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

PANEL="" TOKEN="" VERSION="latest"
while [ $# -gt 0 ]; do
  case "$1" in
    --panel)   PANEL="$2"; shift 2 ;;
    --token)   TOKEN="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    *) fail "неизвестный аргумент: $1" ;;
  esac
done
[ -n "$PANEL" ] || fail "нужен --panel URL панели"
[ -n "$TOKEN" ] || fail "нужен --token (выпускается в панели на карточке сервера)"
[ "$(id -u)" = "0" ] || fail "запусти от root"
command -v systemctl >/dev/null 2>&1 || fail "нужен systemd"
command -v curl >/dev/null 2>&1 || fail "нужен curl"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "архитектура $(uname -m) не поддерживается (нужна x86_64 или aarch64)" ;;
esac

if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi
FILE="nodeservice-agent_linux_$ARCH"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "скачиваю $FILE ($VERSION)"
curl -fsSL -o "$TMP/$FILE" "$BASE/$FILE" || fail "не скачался бинарь: $BASE/$FILE"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt" || fail "не скачался checksums.txt"
( cd "$TMP" && grep " $FILE\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) \
  || fail "контрольная сумма не сошлась — файл повреждён или подменён"
ok "контрольная сумма сходится"

# Останавливаем старый агент перед заменой бинаря (обновление поверх).
systemctl stop nodeservice-agent 2>/dev/null || true
install -m 0755 "$TMP/$FILE" "$BIN_PATH"
ok "бинарь установлен: $BIN_PATH ($("$BIN_PATH" version))"

id "$AGENT_USER" >/dev/null 2>&1 \
  || useradd --system --no-create-home --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$AGENT_USER"
mkdir -p "$STATE_DIR"
chown "$AGENT_USER:$AGENT_USER" "$STATE_DIR"
chmod 0700 "$STATE_DIR"

# Токен одноразовый: после привязки агент его игнорирует, файл можно удалить.
umask 077
cat > "$ENV_FILE" <<EOF
NODESERVICE_PANEL_URL=$PANEL
NODESERVICE_TOKEN=$TOKEN
EOF
chmod 0600 "$ENV_FILE"

# Копия deploy/nodeservice-agent.service из репозитория агента.
cat > "$UNIT_PATH" <<'EOF'
[Unit]
Description=NodeService agent (метрики и heartbeat ноды)
Documentation=https://github.com/LumaxDev/nodeservice-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nodesvc-agent
Group=nodesvc-agent
EnvironmentFile=-/etc/nodeservice-agent.env
Environment=NODESERVICE_STATE_DIR=/var/lib/nodeservice-agent
ExecStart=/usr/local/bin/nodeservice-agent run
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/nodeservice-agent
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nodeservice-agent
ok "агент запущен и добавлен в автозагрузку"
say "журнал: journalctl -u nodeservice-agent -f"
