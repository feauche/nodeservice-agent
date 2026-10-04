// Package vpnprobe performs one short, real VPN request in-process.
// Xray is started only for the duration of the probe; no extra daemon, container or port is created.
package vpnprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/proxy/hysteria"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

const maxResponseBytes = 128 << 10

// Request contains only a single route and a one-time panel token. The agent never accepts a command or URL.
type Request struct {
	Link  string `json:"link"`
	Token string `json:"token"`
}

type Result struct {
	OK        bool   `json:"ok"`
	Stage     string `json:"stage"`
	Detail    string `json:"detail"`
	LatencyMS int64  `json:"latencyMs"`
	Bytes     int64  `json:"bytes"`
}

type route struct {
	protocol     string
	address      string
	port         int
	id           string
	flow         string
	network      string
	security     string
	serverName   string
	fingerprint  string
	publicKey    string
	shortID      string
	path         string
	host         string
	serviceName  string
	mode         string
	auth         string
	insecure     bool
	pinnedCert   string
	obfs         string
	obfsPassword string
}

func one(q url.Values, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(q.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func parseVLESS(raw string) (route, error) {
	if len(raw) > 8192 {
		return route{}, fmt.Errorf("ссылка длиннее 8192 символов")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "vless" || u.User == nil {
		return route{}, fmt.Errorf("ожидается ссылка VLESS")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Hostname() == "" {
		return route{}, fmt.Errorf("в ссылке нет корректного адреса и порта")
	}
	q := u.Query()
	r := route{
		protocol:    "vless-reality",
		address:     u.Hostname(),
		port:        port,
		id:          u.User.Username(),
		flow:        one(q, "flow"),
		network:     one(q, "type"),
		security:    one(q, "security"),
		serverName:  one(q, "sni", "serverName"),
		fingerprint: one(q, "fp", "fingerprint"),
		publicKey:   one(q, "pbk", "publicKey"),
		shortID:     one(q, "sid", "shortId"),
		path:        one(q, "path"),
		host:        one(q, "host"),
		serviceName: one(q, "serviceName"),
		mode:        one(q, "mode"),
	}
	if r.id == "" {
		return route{}, fmt.Errorf("в ссылке нет UUID")
	}
	if r.network == "" || r.network == "raw" {
		r.network = "tcp"
	}
	if r.security != "reality" {
		return route{}, fmt.Errorf("маршрут использует %q вместо REALITY", r.security)
	}
	if r.serverName == "" || r.publicKey == "" {
		return route{}, fmt.Errorf("в ссылке нет SNI или публичного ключа REALITY")
	}
	if r.fingerprint == "" {
		r.fingerprint = "chrome"
	}
	switch r.network {
	case "tcp", "ws", "grpc", "httpupgrade", "xhttp", "splithttp", "http", "h2":
	default:
		return route{}, fmt.Errorf("транспорт %q пока не поддерживается пробой", r.network)
	}
	return r, nil
}

func parseBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "1" || value == "true" || value == "yes"
}

func parseHysteria2(raw string) (route, error) {
	if len(raw) > 8192 {
		return route{}, fmt.Errorf("ссылка длиннее 8192 символов")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "hysteria2" && u.Scheme != "hy2") {
		return route{}, fmt.Errorf("ожидается ссылка Hysteria2")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Hostname() == "" {
		return route{}, fmt.Errorf("в ссылке нет корректного адреса и порта")
	}
	q := u.Query()
	auth := one(q, "auth")
	if u.User != nil {
		auth = u.User.Username()
		if password, ok := u.User.Password(); ok {
			auth += ":" + password
		}
	}
	if auth == "" {
		return route{}, fmt.Errorf("в ссылке нет пароля Hysteria2")
	}
	obfs := strings.ToLower(one(q, "obfs"))
	obfsPassword := one(q, "obfs-password", "obfsPassword")
	if obfs != "" && obfs != "salamander" {
		return route{}, fmt.Errorf("маскировка Hysteria2 %q пока не поддерживается", obfs)
	}
	if obfs == "salamander" && obfsPassword == "" {
		return route{}, fmt.Errorf("для salamander нет пароля маскировки")
	}
	return route{
		protocol:     "hysteria2",
		address:      u.Hostname(),
		port:         port,
		serverName:   one(q, "sni", "peer"),
		fingerprint:  one(q, "fp", "fingerprint"),
		auth:         auth,
		insecure:     parseBool(one(q, "insecure", "allowInsecure")),
		pinnedCert:   one(q, "pinSHA256", "pinnedPeerCertSha256", "pcs"),
		obfs:         obfs,
		obfsPassword: obfsPassword,
	}, nil
}

func parseRoute(raw string) (route, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return route{}, fmt.Errorf("ссылка не разобрана")
	}
	switch strings.ToLower(u.Scheme) {
	case "vless":
		return parseVLESS(raw)
	case "hysteria2", "hy2":
		return parseHysteria2(raw)
	default:
		return route{}, fmt.Errorf("протокол %q пока не поддерживается пробой", u.Scheme)
	}
}

func streamSettings(r route) map[string]any {
	settings := map[string]any{
		"network":  r.network,
		"security": "reality",
		"realitySettings": map[string]any{
			"serverName":  r.serverName,
			"fingerprint": r.fingerprint,
			"publicKey":   r.publicKey,
			"shortId":     r.shortID,
		},
	}
	switch r.network {
	case "ws":
		ws := map[string]any{"path": r.path}
		if r.host != "" {
			ws["headers"] = map[string]any{"Host": r.host}
		}
		settings["wsSettings"] = ws
	case "grpc":
		settings["grpcSettings"] = map[string]any{"serviceName": r.serviceName}
	case "httpupgrade":
		settings["httpupgradeSettings"] = map[string]any{"path": r.path, "host": r.host}
	case "xhttp":
		settings["xhttpSettings"] = map[string]any{"path": r.path, "host": r.host, "mode": r.mode}
	case "splithttp":
		settings["splithttpSettings"] = map[string]any{"path": r.path, "host": r.host, "mode": r.mode}
	case "http", "h2":
		hosts := []string{}
		if r.host != "" {
			hosts = strings.Split(r.host, ",")
		}
		settings["httpSettings"] = map[string]any{"path": r.path, "host": hosts}
	}
	return settings
}

func vlessConfig(r route) ([]byte, error) {
	user := map[string]any{"id": r.id, "encryption": "none"}
	if r.flow != "" {
		user["flow"] = r.flow
	}
	return json.Marshal(map[string]any{
		"outbounds": []any{map[string]any{
			"tag":      "probe",
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": r.address,
				"port":    r.port,
				"users":   []any{user},
			}}},
			"streamSettings": streamSettings(r),
		}},
	})
}

func hysteria2Config(r route) ([]byte, error) {
	if r.insecure && r.pinnedCert == "" {
		return nil, fmt.Errorf("маршрут Hysteria2 использует insecure=1 без pinSHA256; актуальный Xray требует доверенный сертификат или его отпечаток")
	}
	tlsSettings := map[string]any{"serverName": r.serverName}
	if r.fingerprint != "" {
		tlsSettings["fingerprint"] = r.fingerprint
	}
	if r.pinnedCert != "" {
		tlsSettings["pinnedPeerCertSha256"] = r.pinnedCert
	}
	stream := map[string]any{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tlsSettings,
		"hysteriaSettings": map[string]any{"version": 2, "auth": r.auth},
	}
	if r.obfs == "salamander" {
		stream["finalmask"] = map[string]any{
			"udp": []any{map[string]any{
				"type":     "salamander",
				"settings": map[string]any{"password": r.obfsPassword},
			}},
		}
	}
	return json.Marshal(map[string]any{
		"outbounds": []any{map[string]any{
			"tag":      "probe",
			"protocol": "hysteria",
			"settings": map[string]any{
				"version": 2,
				"address": r.address,
				"port":    r.port,
			},
			"streamSettings": stream,
		}},
	})
}

func xrayConfig(r route) ([]byte, error) {
	if r.protocol == "hysteria2" {
		return hysteria2Config(r)
	}
	return vlessConfig(r)
}

func start(raw []byte) (*core.Instance, error) {
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	built, err := decoded.Build()
	if err != nil {
		return nil, err
	}
	instance, err := core.New(built)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return instance, nil
}

func targetURL(panelURL, token string) (string, error) {
	base, err := url.Parse(panelURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return "", fmt.Errorf("у агента нет корректного HTTPS-адреса панели")
	}
	base.Path = "/api/agent/v1/probe-target"
	base.RawQuery = url.Values{"token": []string{token}}.Encode()
	base.Fragment = ""
	return base.String(), nil
}

// Run downloads the panel's one-time 64 KiB marker through the supplied VPN route.
func Run(ctx context.Context, panelURL string, req Request) Result {
	r, err := parseRoute(req.Link)
	if err != nil {
		return Result{Stage: "config", Detail: "Маршрут подписки не разобран: " + err.Error()}
	}
	target, err := targetURL(panelURL, req.Token)
	if err != nil {
		return Result{Stage: "config", Detail: err.Error()}
	}
	config, err := xrayConfig(r)
	if err != nil {
		return Result{Stage: "config", Detail: "Конфигурация пробы не собрана: " + err.Error()}
	}
	instance, err := start(config)
	if err != nil {
		return Result{Stage: "start", Detail: "Временный Xray не запустился: " + err.Error()}
	}
	defer instance.Close()

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dialCtx context.Context, _, address string) (net.Conn, error) {
			host, portRaw, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			port, convErr := strconv.Atoi(portRaw)
			if convErr != nil {
				return nil, convErr
			}
			return core.Dial(dialCtx, instance, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	started := time.Now()
	response, err := client.Do(request)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		return Result{Stage: "connect", Detail: "Настоящее VPN-подключение не прошло: " + err.Error(), LatencyMS: latency}
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return Result{Stage: "download", Detail: "VPN подключился, но контрольные данные не скачались.", LatencyMS: latency, Bytes: int64(len(body))}
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-NodeService-Probe") != "v1" || len(body) != 64<<10 {
		return Result{Stage: "download", Detail: "Через VPN пришёл неполный или чужой контрольный ответ.", LatencyMS: latency, Bytes: int64(len(body))}
	}
	protocol := "VLESS/REALITY"
	if r.protocol == "hysteria2" {
		protocol = "Hysteria2"
	}
	return Result{OK: true, Stage: "done", Detail: "Настоящий " + protocol + "-сеанс и передача 64 КБ прошли.", LatencyMS: latency, Bytes: int64(len(body))}
}
