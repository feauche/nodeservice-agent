package metrics

import (
	"os"
	"testing"
	"time"
)

func TestRates(t *testing.T) {
	t0 := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name                       string
		prev, cur                  NetSnap
		rxBps, txBps, rxPps, txPps float64
	}{
		{
			name:  "обычная дельта за 2 секунды",
			prev:  NetSnap{At: t0, RxBytes: 1000, TxBytes: 500, RxPackets: 10, TxPackets: 5},
			cur:   NetSnap{At: t0.Add(2 * time.Second), RxBytes: 3000, TxBytes: 1500, RxPackets: 30, TxPackets: 15},
			rxBps: 1000, txBps: 500, rxPps: 10, txPps: 5,
		},
		{
			name:  "сброс счётчика — нули, не отрицательное",
			prev:  NetSnap{At: t0, RxBytes: 5000, TxBytes: 5000, RxPackets: 50, TxPackets: 50},
			cur:   NetSnap{At: t0.Add(time.Second), RxBytes: 100, TxBytes: 6000, RxPackets: 1, TxPackets: 60},
			rxBps: 0, txBps: 1000, rxPps: 0, txPps: 10,
		},
		{
			name: "нулевой интервал — нули",
			prev: NetSnap{At: t0, RxBytes: 1, TxBytes: 1, RxPackets: 1, TxPackets: 1},
			cur:  NetSnap{At: t0, RxBytes: 100, TxBytes: 100, RxPackets: 100, TxPackets: 100},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rxB, txB, rxP, txP := Rates(tc.prev, tc.cur)
			if rxB != tc.rxBps || txB != tc.txBps || rxP != tc.rxPps || txP != tc.txPps {
				t.Fatalf("получил %v/%v/%v/%v, ждал %v/%v/%v/%v",
					rxB, txB, rxP, txP, tc.rxBps, tc.txBps, tc.rxPps, tc.txPps)
			}
		})
	}
}

func TestCollectSmoke(t *testing.T) {
	// Дымовой тест на реальной машине: значения осмысленные, второй тик даёт сетевые дельты >= 0.
	c := NewCollector()
	m1, _ := c.Collect(t.Context())
	if m1.MemTotalMb <= 0 || m1.DiskTotalMb <= 0 {
		t.Fatalf("память/диск не собрались: %+v", m1)
	}
	if m1.NetRxBps != 0 || m1.NetTxBps != 0 {
		t.Fatalf("первый тик обязан отдать нулевые сетевые скорости, получил %+v", m1)
	}
	time.Sleep(30 * time.Millisecond)
	m2, _ := c.Collect(t.Context())
	if m2.NetRxBps < 0 || m2.NetTxPps < 0 {
		t.Fatalf("отрицательные скорости: %+v", m2)
	}
	if m2.CPUPct < 0 || m2.CPUPct > 100 {
		t.Fatalf("cpuPct вне 0..100: %v", m2.CPUPct)
	}
}

func TestXrayRunning(t *testing.T) {
	root := t.TempDir()
	mk := func(pid, comm string) {
		if err := os.MkdirAll(root+"/"+pid, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(root+"/"+pid+"/comm", []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("1", "systemd")
	mk("42", "sshd")
	if got := xrayRunning(root); got == nil || *got {
		t.Fatalf("без xray ожидали false, получили %v", got)
	}
	mk("777", "xray")
	if got := xrayRunning(root); got == nil || !*got {
		t.Fatalf("с xray ожидали true, получили %v", got)
	}
	if got := xrayRunning(root + "/nope"); got != nil {
		t.Fatalf("нет /proc — ожидали nil, получили %v", got)
	}
}
