#!/bin/sh
# Установка агента NodeService: релиз с GitHub, systemd-юнит и защищённый канал панели.
# Запуск (команду с токеном выдаёт панель):
#   curl -fsSL https://raw.githubusercontent.com/feauche/nodeservice-agent/main/scripts/install.sh \
#     | sh -s -- --panel https://panel.example.com --token nse_...
set -eu

REPO="feauche/nodeservice-agent"
BIN_PATH="/usr/local/bin/nodeservice-agent"
STATE_DIR="/var/lib/nodeservice-agent"
ENV_FILE="/etc/nodeservice-agent.env"
UNIT_PATH="/etc/systemd/system/nodeservice-agent.service"
AGENT_USER="nodesvc-agent"

say()  { printf '\033[36m→\033[0m %s\n' "$1"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

PANEL="" FALLBACK_PANELS="" TOKEN="" VERSION="latest"
LISTEN_PORT="" SERVER_ID="" SERVER_NAME="" PANEL_IP="" ACCESS_KEY_STDIN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --panel)          PANEL="$2"; shift 2 ;;
    --fallback-panels) FALLBACK_PANELS="$2"; shift 2 ;;
    --token)          TOKEN="$2"; shift 2 ;;
    --version)        VERSION="$2"; shift 2 ;;
    --listen-port)    LISTEN_PORT="$2"; shift 2 ;;
    --server-id)      SERVER_ID="$2"; shift 2 ;;
    --server-name)    SERVER_NAME="$2"; shift 2 ;;
    --panel-ip)       PANEL_IP="$2"; shift 2 ;;
    --access-key-stdin) ACCESS_KEY_STDIN=1; shift ;;
    *) fail "неизвестный аргумент: $1" ;;
  esac
done
PULL_MODE=0 ACCESS_KEY=""
if [ -n "$LISTEN_PORT" ]; then
  PULL_MODE=1
  case "$LISTEN_PORT" in *[!0-9]*|'') fail "порт агента должен быть числом" ;; esac
  [ "$LISTEN_PORT" -ge 10000 ] && [ "$LISTEN_PORT" -le 65535 ] \
    || fail "порт агента должен быть пятизначным: 10000–65535"
  [ -n "$SERVER_ID" ] || fail "нужен --server-id"
  [ -n "$SERVER_NAME" ] || fail "нужен --server-name"
  [ -n "$PANEL_IP" ] || fail "нужен --panel-ip для точечного правила UFW"
  [ "$ACCESS_KEY_STDIN" = 1 ] || fail "ключ агента должен передаваться через --access-key-stdin"
  ACCESS_KEY="$(cat)"
  [ "${#ACCESS_KEY}" -ge 32 ] || fail "ключ агента не получен или слишком короткий"
else
  [ -n "$PANEL" ] || fail "нужен --panel URL панели"
  [ -n "$TOKEN" ] || fail "нужен --token (выпускается в панели на карточке сервера)"
fi
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
WAS_ACTIVE=0 WAS_ENABLED=0 INSTALL_CHANGED=0 INSTALL_COMMITTED=0
HAD_BIN=0 HAD_STATE=0 HAD_ENV=0 HAD_UNIT=0

backup_file() {
  src="$1" name="$2"
  if [ -e "$src" ]; then
    cp -a "$src" "$TMP/$name"
    return 0
  fi
  return 1
}

restore_file() {
  dst="$1" name="$2" had="$3"
  if [ "$had" = 1 ]; then
    cp -a "$TMP/$name" "$dst"
  else
    rm -f "$dst"
  fi
}

cleanup() {
  rc=$?
  trap - 0
  if [ "$rc" -ne 0 ] && [ "$INSTALL_CHANGED" = 1 ] && [ "$INSTALL_COMMITTED" = 0 ]; then
    say "установка не завершилась — возвращаю прежний агент"
    systemctl stop nodeservice-agent 2>/dev/null || true
    restore_file "$BIN_PATH" old-bin "$HAD_BIN"
    restore_file "$ENV_FILE" old-env "$HAD_ENV"
    restore_file "$UNIT_PATH" old-unit "$HAD_UNIT"
    rm -rf "$STATE_DIR"
    if [ "$HAD_STATE" = 1 ]; then cp -a "$TMP/old-state" "$STATE_DIR"; fi
    systemctl daemon-reload 2>/dev/null || true
    if [ "$WAS_ENABLED" = 1 ]; then
      systemctl enable nodeservice-agent 2>/dev/null || true
    else
      systemctl disable nodeservice-agent 2>/dev/null || true
    fi
    if [ "$WAS_ACTIVE" = 1 ]; then
      systemctl start nodeservice-agent 2>/dev/null || true
    else
      systemctl stop nodeservice-agent 2>/dev/null || true
    fi
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT

say "скачиваю $FILE ($VERSION)"
curl -fsSL -o "$TMP/$FILE" "$BASE/$FILE" || fail "не скачался бинарь: $BASE/$FILE"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt" || fail "не скачался checksums.txt"
( cd "$TMP" && grep " $FILE\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) \
  || fail "контрольная сумма не сошлась — файл повреждён или подменён"
ok "контрольная сумма сходится"

# До первой правки сохраняем всю прежнюю установку. При любой следующей ошибке cleanup вернёт её
# целиком: одного запуска старой службы недостаточно, если бинарь, state.json или unit уже заменены.
backup_file "$BIN_PATH" old-bin && HAD_BIN=1 || true
backup_file "$ENV_FILE" old-env && HAD_ENV=1 || true
backup_file "$UNIT_PATH" old-unit && HAD_UNIT=1 || true
if [ -d "$STATE_DIR" ]; then cp -a "$STATE_DIR" "$TMP/old-state"; HAD_STATE=1; fi
systemctl is-active --quiet nodeservice-agent 2>/dev/null && WAS_ACTIVE=1
systemctl is-enabled --quiet nodeservice-agent 2>/dev/null && WAS_ENABLED=1
systemctl stop nodeservice-agent 2>/dev/null || true
INSTALL_CHANGED=1
if [ "$PULL_MODE" = 1 ]; then
  PORT_HEX="$(printf '%04X' "$LISTEN_PORT")"
  if awk -v p="$PORT_HEX" '$2 ~ (":" p "$") && $4 == "0A" { f=1 } END { exit !f }' \
    /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
    fail "порт $LISTEN_PORT уже занят другой службой"
  fi
fi
install -m 0755 "$TMP/$FILE" "$BIN_PATH"
ok "бинарь установлен: $BIN_PATH ($("$BIN_PATH" version))"

id "$AGENT_USER" >/dev/null 2>&1 \
  || useradd --system --no-create-home --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$AGENT_USER"
mkdir -p "$STATE_DIR"
chown "$AGENT_USER:$AGENT_USER" "$STATE_DIR"
chmod 0700 "$STATE_DIR"

umask 077
if [ "$PULL_MODE" = 1 ]; then
  # Ключ идёт через stdin и ни на секунду не появляется в аргументах процесса или журнале systemd.
  printf '%s\n' "$ACCESS_KEY" | "$BIN_PATH" configure-pull \
    --state-dir "$STATE_DIR" --server-id "$SERVER_ID" --server-name "$SERVER_NAME" \
    --port "$LISTEN_PORT" --access-key-stdin
  ACCESS_KEY=""
  chown -R "$AGENT_USER:$AGENT_USER" "$STATE_DIR"
  chmod 0700 "$STATE_DIR"
  chmod 0600 "$STATE_DIR"/*
  cat > "$ENV_FILE" <<EOF
NODESERVICE_STATE_DIR=$STATE_DIR
EOF
else
  # Токен одноразовый: после привязки агент его игнорирует, файл можно удалить.
  cat > "$ENV_FILE" <<EOF
NODESERVICE_PANEL_URL=$PANEL
NODESERVICE_PANEL_URLS=$FALLBACK_PANELS
NODESERVICE_TOKEN=$TOKEN
EOF
fi
chmod 0600 "$ENV_FILE"

# Копия deploy/nodeservice-agent.service из репозитория агента.
cat > "$UNIT_PATH" <<'EOF'
[Unit]
Description=NodeService agent (метрики и heartbeat сервера)
Documentation=https://github.com/feauche/nodeservice-agent
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

# `systemctl enable --now` может вернуть 0, хотя процесс тут же упал и ушёл в цикл рестартов.
# Ждём устойчивого active; для входящего режима вдобавок проверяем, что агент действительно слушает порт.
STARTED=0 TRY=0
while [ "$TRY" -lt 10 ]; do
  TRY=$((TRY + 1))
  ACTIVE=0 LISTENING=1
  systemctl is-active --quiet nodeservice-agent 2>/dev/null && ACTIVE=1
  if [ "$PULL_MODE" = 1 ]; then
    LISTENING=0
    PORT_HEX="$(printf '%04X' "$LISTEN_PORT")"
    awk -v p="$PORT_HEX" '$2 ~ (":" p "$") && $4 == "0A" { f=1 } END { exit !f }' \
      /proc/net/tcp /proc/net/tcp6 2>/dev/null && LISTENING=1
  fi
  if [ "$ACTIVE" = 1 ] && [ "$LISTENING" = 1 ]; then STARTED=1; break; fi
  sleep 1
done
[ "$STARTED" = 1 ] || fail "служба агента не запустилась или не открыла назначенный порт"
ok "агент запущен и добавлен в автозагрузку"
if [ "$PULL_MODE" = 1 ]; then
  if command -v ufw >/dev/null 2>&1; then
    ufw allow from "$PANEL_IP" to any port "$LISTEN_PORT" proto tcp comment 'NodeService agent' >/dev/null
    if ufw status 2>/dev/null | grep -q '^Status: active'; then
      ok "UFW разрешает панели $PANEL_IP подключаться к порту $LISTEN_PORT"
    else
      say "правило UFW добавлено; сам UFW выключен, чтобы не закрыть действующие VPN- и SSH-порты"
    fi
  elif ! command -v ufw >/dev/null 2>&1; then
    say "UFW не установлен; порт слушает агент, проверь внешний firewall провайдера"
  fi
fi
INSTALL_COMMITTED=1
say "журнал: journalctl -u nodeservice-agent -f"
