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

	"github.com/lumaxdev/nodeservice-agent/internal/proto"
)

const conntrackPath = "/proc/sys/net/netfilter/nf_conntrack_count"

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
	m := &proto.Metrics{ConntrackCount: conntrackCount()}
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

	if counters, err := net.IOCountersWithContext(ctx, false); err != nil {
		probs = append(probs, fmt.Errorf("сеть: %w", err))
	} else if len(counters) > 0 {
		cur := NetSnap{
			At:        time.Now(),
			RxBytes:   counters[0].BytesRecv,
			TxBytes:   counters[0].BytesSent,
			RxPackets: counters[0].PacketsRecv,
			TxPackets: counters[0].PacketsSent,
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
