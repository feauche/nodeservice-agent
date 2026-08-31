# nodeservice-agent

Агент NodeService для ноды: один статический Go-бинарь, который сам ходит к панели
по исходящему WebSocket (входящих портов не открывает), шлёт heartbeat и метрики
(CPU, память, диск, сеть bps/pps, conntrack, load, uptime).

**Отдельный git-репозиторий** со своими релизами (GitHub Releases:
`nodeservice-agent_linux_amd64`, `nodeservice-agent_linux_arm64`, `checksums.txt`).

## Установка

Команду с одноразовым токеном выдаёт панель (карточка сервера → токен агента):

```sh
curl -fsSL https://raw.githubusercontent.com/LumaxDev/nodeservice-agent/main/scripts/install.sh \
  | sh -s -- --panel https://panel.example.com --token nse_...
```

Скрипт скачивает релиз под архитектуру, сверяет sha256, ставит systemd-юнит с
закалкой (отдельный пользователь `nodesvc-agent`, `ProtectSystem=strict`,
`CapabilityBoundingSet=`), кладёт токен в `/etc/nodeservice-agent.env` и запускает
агента. При первом запуске агент генерирует ключ ed25519, меняет токен на привязку
(`POST /api/agent/v1/enroll`) и сохраняет состояние в
`/var/lib/nodeservice-agent/state.json` (0600). Токен одноразовый: после привязки
он игнорируется, `state.json` — единственный источник доступа.

Перепривязка к другой панели/серверу: `rm /var/lib/nodeservice-agent/state.json`,
выпустить в панели новый токен и перезапустить агента с ним.

## Протокол

Версионированный JSON-конверт `{v:1, type, id, ts, payload}` поверх WebSocket.
Аутентификация — challenge-response: панель шлёт nonce, агент подписывает его
своим ключом ed25519 (ключ пиннится панелью при энроллменте, TOFU). Источник
правды по схемам — `panel/packages/shared/src/agent-protocol.ts` монорепо панели.
Частоты heartbeat и метрик агенту сообщает панель (настройки → «Автопроверки»).

## Разработка

```sh
make test        # go test ./...
make vet         # go vet ./...
make build       # локальный бинарь → dist/nodeservice-agent
make build-all VERSION=v0.5.0   # релизные linux amd64+arm64 + checksums.txt
```

## Структура

```
main.go, cmd_run.go, cmd_version.go   — cobra CLI (run, version)
internal/proto      — конверт и сообщения протокола v1, подпись nonce
internal/state      — state.json: ключ и привязка (0600, атомарная запись)
internal/enroll     — HTTP-энроллмент по одноразовому токену
internal/metrics    — gopsutil/v4, сетевые скорости дельтами между тиками
internal/transport  — WebSocket-клиент: рукопожатие, heartbeat, метрики, backoff
deploy/             — systemd-юнит с закалкой
scripts/install.sh  — установка одной командой
```
