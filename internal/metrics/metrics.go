// Package metrics — сбор метрик ноды через gopsutil/v4.
// Сетевые скорости считаются дельтами между тиками; первый тик после подключения
// отдаёт нули по сети (истории ещё нет) — панель это переживает.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/feauche/nodeservice-agent/internal/proto"
)

const conntrackPath = "/proc/sys/net/netfilter/nf_conntrack_count"
const routePath = "/proc/net/route"

// NetSnap — снимок суммарных сетевых счётчиков в момент времени.
type NetSnap struct {
	At                   time.Time
	RxBytes, TxBytes     uint64
	RxPackets, TxPackets uint64
}

// Rates — скорости между двумя снимками. Сброс счётчика (cur < prev)
// и нулевой интервал дают 0, а не мусорные отрицательные значения.
func Rates(prev, cur NetSnap) (rxBps, txBps, rxPps, txPps float64) {
	sec := cur.At.Sub(prev.At).Seconds()
	if sec <= 0 {
		return 0, 0, 0, 0
	}
	d := func(p, c uint64) float64 {
		if c < p {
			return 0
		}
		return float64(c-p) / sec
	}
	return d(prev.RxBytes, cur.RxBytes),
		d(prev.TxBytes, cur.TxBytes),
		d(prev.RxPackets, cur.RxPackets),
		d(prev.TxPackets, cur.TxPackets)
}

// Collector держит предыдущий сетевой снимок для дельт.
type Collector struct {
	mu   sync.Mutex
	prev *NetSnap
}

func NewCollector() *Collector { return &Collector{} }

// Collect собирает метрики. Ошибка не фатальна: возвращаются метрики,
// которые удалось получить, плюс объединённая ошибка для лога.
func (c *Collector) Collect(ctx context.Context) (*proto.Metrics, error) {
	m := &proto.Metrics{ConntrackCount: conntrackCount(), XrayRunning: xrayRunning("/proc")}
	var probs []error

	if pct, err := cpu.PercentWithContext(ctx, 0, false); err != nil {
		probs = append(probs, fmt.Errorf("cpu: %w", err))
	} else if len(pct) > 0 {
		m.CPUPct = clamp(pct[0], 0, 100)
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err != nil {
		probs = append(probs, fmt.Errorf("память: %w", err))
	} else {
		m.MemUsedMb = int64(vm.Used / 1024 / 1024)
		m.MemTotalMb = int64(vm.Total / 1024 / 1024)
	}

	if du, err := disk.UsageWithContext(ctx, "/"); err != nil {
		probs = append(probs, fmt.Errorf("диск: %w", err))
	} else {
		m.DiskUsedMb = int64(du.Used / 1024 / 1024)
		m.DiskTotalMb = int64(du.Total / 1024 / 1024)
	}

	if la, err := load.AvgWithContext(ctx); err != nil {
		probs = append(probs, fmt.Errorf("load: %w", err))
	} else {
		m.Load1 = clamp(la.Load1, 0, 1e6)
	}

	if up, err := host.UptimeWithContext(ctx); err != nil {
		probs = append(probs, fmt.Errorf("uptime: %w", err))
	} else {
		m.UptimeSec = int64(up)
	}

	if counters, err := net.IOCountersWithContext(ctx, true); err != nil {
		probs = append(probs, fmt.Errorf("сеть: %w", err))
	} else if len(counters) > 0 {
		routes, _ := os.ReadFile(routePath)
		counter := externalCounter(counters, string(routes))
		cur := NetSnap{
			At:        time.Now(),
			RxBytes:   counter.BytesRecv,
			TxBytes:   counter.BytesSent,
			RxPackets: counter.PacketsRecv,
			TxPackets: counter.PacketsSent,
		}
		c.mu.Lock()
		if c.prev != nil {
			m.NetRxBps, m.NetTxBps, m.NetRxPps, m.NetTxPps = Rates(*c.prev, cur)
		}
		c.prev = &cur
		c.mu.Unlock()
	}

	return m, errors.Join(probs...)
}

// externalCounter считает трафик физических входов сервера один раз. Сначала берём интерфейсы,
// через которые ядро держит default route: это надёжно для eth/enp, bond и сетевых мостов провайдера.
// Если таблица маршрутов недоступна, исключаем заведомо внутренние loopback, Docker/veth и туннели.
func externalCounter(counters []net.IOCountersStat, routes string) net.IOCountersStat {
	defaults := defaultInterfaces(routes)
	selected := make([]net.IOCountersStat, 0, len(counters))
	if len(defaults) > 0 {
		for _, counter := range counters {
			// Full-tunnel VPN/WARP can also install a default route. Counting it together with the
			// physical NIC duplicates the same bytes; counting only it describes the tunnel, not the VPS.
			if defaults[counter.Name] && !virtualInterface(counter.Name) {
				selected = append(selected, counter)
			}
		}
	}
	if len(selected) == 0 {
		for _, counter := range counters {
			if !virtualInterface(counter.Name) {
				selected = append(selected, counter)
			}
		}
	}
	var total net.IOCountersStat
	for _, counter := range selected {
		total.BytesRecv += counter.BytesRecv
		total.BytesSent += counter.BytesSent
		total.PacketsRecv += counter.PacketsRecv
		total.PacketsSent += counter.PacketsSent
	}
	return total
}

func defaultInterfaces(routes string) map[string]bool {
	out := make(map[string]bool)
	for n, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if n == 0 || len(fields) < 4 || fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 64)
		if err == nil && flags&1 != 0 { // RTF_UP
			out[fields[0]] = true
		}
	}
	return out
}

func virtualInterface(name string) bool {
	n := strings.ToLower(name)
	for _, prefix := range []string{
		"lo", "docker", "veth", "br-", "virbr", "cni", "flannel", "kube", "tun", "tap",
		"wg", "tailscale", "ifb", "dummy", "ip6tnl", "sit", "gre", "gretap",
	} {
		if n == prefix || strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// xrayRunning ищет процесс xray по /proc — так видно и процесс внутри контейнера ноды
// (remnanode), потому что контейнеры делят ядро с хостом; comm и cmdline читаются без прав.
// Имя бинаря у сборок разное (xray, xray-core, Xray-linux-64), поэтому смотрим и comm, и
// argv0 из cmdline: имя файла начинается с «xray» без учёта регистра.
// Не смогли прочитать /proc (не linux) — nil, панель считает «неизвестно».
func xrayRunning(procRoot string) *bool {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	found := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := procRoot + "/" + e.Name()
		if comm, err := os.ReadFile(dir + "/comm"); err == nil && looksLikeXray(strings.TrimSpace(string(comm))) {
			found = true
			break
		}
		if cmd, err := os.ReadFile(dir + "/cmdline"); err == nil {
			argv0, _, _ := strings.Cut(string(cmd), "\x00")
			if looksLikeXray(argv0) {
				found = true
				break
			}
		}
	}
	return &found
}

// looksLikeXray: имя файла (без пути) начинается с «xray» без учёта регистра.
func looksLikeXray(name string) bool {
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return strings.HasPrefix(strings.ToLower(name), "xray")
}

// conntrackCount читает счётчик conntrack; недоступен (не linux, нет модуля) — null.
func conntrackCount() *int64 {
	raw, err := os.ReadFile(conntrackPath)
	if err != nil {
		return nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || n < 0 {
		return nil
	}
	return &n
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
