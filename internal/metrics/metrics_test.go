package metrics

import (
	"os"
	"testing"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"
)

func TestExternalCounterUsesDefaultRouteWithoutVirtualDoubleCount(t *testing.T) {
	counters := []psnet.IOCountersStat{
		{Name: "eth0", BytesRecv: 100, BytesSent: 200, PacketsRecv: 10, PacketsSent: 20},
		{Name: "docker0", BytesRecv: 90, BytesSent: 80, PacketsRecv: 9, PacketsSent: 8},
		{Name: "veth123", BytesRecv: 70, BytesSent: 60, PacketsRecv: 7, PacketsSent: 6},
		{Name: "lo", BytesRecv: 50, BytesSent: 50, PacketsRecv: 5, PacketsSent: 5},
	}
	routes := "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 01010101 0003 0 0 100 00000000\n"
	got := externalCounter(counters, routes)
	if got.BytesRecv != 100 || got.BytesSent != 200 || got.PacketsRecv != 10 || got.PacketsSent != 20 {
		t.Fatalf("externalCounter() = %+v, want only eth0", got)
	}
}

func TestExternalCounterFallbackExcludesInternalInterfaces(t *testing.T) {
	counters := []psnet.IOCountersStat{
		{Name: "ens3", BytesRecv: 100, BytesSent: 200},
		{Name: "eth1", BytesRecv: 30, BytesSent: 40},
		{Name: "docker0", BytesRecv: 900, BytesSent: 800},
		{Name: "wg0", BytesRecv: 700, BytesSent: 600},
	}
	got := externalCounter(counters, "")
	if got.BytesRecv != 130 || got.BytesSent != 240 {
		t.Fatalf("externalCounter() = %+v, want physical interfaces once", got)
	}
}

func TestExternalCounterIgnoresTunnelDefaultRoute(t *testing.T) {
	counters := []psnet.IOCountersStat{
		{Name: "ens3", BytesRecv: 100, BytesSent: 200},
		{Name: "wg0", BytesRecv: 90, BytesSent: 180},
	}
	routes := "Iface Destination Gateway Flags RefCnt Use Metric Mask\nwg0 00000000 00000000 0001 0 0 10 00000000\n"
	got := externalCounter(counters, routes)
	if got.BytesRecv != 100 || got.BytesSent != 200 {
		t.Fatalf("externalCounter() = %+v, want physical fallback without wg0", got)
	}
}

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
	// другое имя бинаря: comm обрезан/иной, но argv0 говорит xray
	if err := os.RemoveAll(root + "/777"); err != nil {
		t.Fatal(err)
	}
	mk("778", "node")
	if err := os.WriteFile(root+"/778/cmdline", []byte("/usr/local/bin/Xray-linux-64\x00run\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := xrayRunning(root); got == nil || !*got {
		t.Fatalf("Xray-linux-64 в cmdline ожидали true, получили %v", got)
	}
	for _, c := range []struct {
		in   string
		want bool
	}{{"xray", true}, {"/usr/bin/xray-core", true}, {"Xray-linux-64", true}, {"node", false}, {"proxray", false}} {
		if got := looksLikeXray(c.in); got != c.want {
			t.Fatalf("looksLikeXray(%q) = %v, ожидали %v", c.in, got, c.want)
		}
	}
	if got := xrayRunning(root + "/nope"); got != nil {
		t.Fatalf("нет /proc — ожидали nil, получили %v", got)
	}
}
