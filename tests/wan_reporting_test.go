package framework_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

// Synthetic observations verify projection, not controller UI compatibility.
func TestDualWANReportsKeepUnknownAndDisconnectedDistinct(t *testing.T) {
	t.Parallel()
	id := identity()
	id.Model = "UXGPRO"
	link, connected := true, false
	bytes := uint64(12345)
	rate, latency := 12.5, 0.0
	bindings := []domain.Binding{{Port: 1, Interface: "wan-a", Role: "wan"}, {Port: 3, Interface: "wan-b", Role: "wan2"}}
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{
		{Name: "wan-a", Up: &link, Addresses: []string{"192.0.2.2/24"}, Counters: domain.Counters{RXBytes: &bytes}, Rates: domain.Rates{RXBytesPerSecond: &rate}},
		{Name: "wan-b", Addresses: []string{"198.51.100.2/24", "2001:db8::2/64"}},
	}, Gateways: []domain.GatewayMonitor{{Role: "wan", Connected: &connected, LatencyMS: &latency}},
		WANHistory: []domain.WANHistory{{Role: "wan", OfflineSeconds: 45}}}
	b, err := unifi.Render(id, bindings, "", snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	a := root["wan1"].(map[string]any)
	second := root["wan2"].(map[string]any)
	if a["ifname"] != "eth0" || a["up"] != true || a["isWanConnected"] != false || a["rx_bytes"] != float64(bytes) || a["latency"] != float64(0) || second["ifname"] != "eth2" {
		t.Fatal("incorrect mapped WAN measurements")
	}
	for _, key := range []string{"up", "isWanUp", "isWanConnected", "latency", "rx_bytes", "tx_bytes", "type", "enable", "uptime"} {
		if _, ok := second[key]; ok {
			t.Fatalf("unknown WAN field %s fabricated", key)
		}
	}
	if len(root["wans"].([]any)) != 2 || len(root["uplink_table"].([]any)) != 2 {
		t.Fatal("dual WAN inventory missing")
	}
	if _, exists := root["uplink"]; exists {
		t.Fatal("uplink reported without a configured uplink_interface")
	}
	health := root["uptime_stats"].(map[string]any)
	firstHealth := health["WAN"].(map[string]any)
	if firstHealth["uptime"] != float64(0) || firstHealth["downtime"] != float64(45) || firstHealth["alerting_monitors"].([]any)[0].(map[string]any)["latency_average"] != float64(0) {
		t.Fatal("disconnected monitor did not report measured controller health")
	}
	if _, exists := health["WAN2"]; exists {
		t.Fatal("unknown WAN monitor health fabricated")
	}
	networks := root["network_table"].([]any)
	firstNetwork := networks[0].(map[string]any)
	if firstNetwork["networkgroup"] != "WAN" || firstNetwork["stats"].(map[string]any)["rx_bytes"] != float64(bytes) {
		t.Fatal("WAN network statistics were not reported")
	}
	if _, ok := networks[1].(map[string]any)["stats"]; ok {
		t.Fatal("unknown WAN network statistics were fabricated")
	}
	ports := root["port_table"].([]any)
	interfaces := root["if_table"].([]any)
	// The UXG controller joins incoming ports to interface measurements by name.
	for i, raw := range ports {
		port := raw.(map[string]any)
		iface := interfaces[i].(map[string]any)
		if port["name"] != iface["name"] || port["name"] != port["ifname"] {
			t.Fatal("port name cannot join interface measurements and assigned interface")
		}
	}
	measured, unmeasured := ports[0].(map[string]any), ports[1].(map[string]any)
	if measured["rx_rate"] != float64(100) || firstNetwork["stats"].(map[string]any)["rx_rate"] != float64(100) {
		t.Fatal("UXG WAN throughput requires port_table rx_rate in bits per second")
	}
	_, unmeasuredRX := unmeasured["rx_rate"]
	_, unmeasuredTX := measured["tx_rate"]
	if unmeasuredRX || unmeasuredTX {
		t.Fatal("unknown WAN bit rate fabricated")
	}
	if len(ports) != 2 || ports[0].(map[string]any)["port_idx"] != float64(1) || ports[1].(map[string]any)["port_idx"] != float64(3) || ports[0].(map[string]any)["rx_bytes"] != float64(bytes) {
		t.Fatal("gateway port inventory did not reflect configured bindings and measured counters")
	}
	if _, ok := ports[1].(map[string]any)["up"]; ok {
		t.Fatal("unknown port link state fabricated")
	}
}

func TestConfiguredLANVLANIsReportedAsGatewayUplink(t *testing.T) {
	t.Parallel()
	id := identity()
	bindings := []domain.Binding{
		{Port: 1, Interface: "vtnet0", Role: "lan"},
		{Port: 5, Interface: "wan-a", Role: "wan"},
		{Port: 6, Interface: "wan-b", Role: "wan2"},
	}
	snap := domain.Snapshot{
		SourceID:   id.ID,
		ObservedAt: time.Now(),
		Interfaces: []domain.Interface{
			{Name: "vtnet0"},
			{Name: "vlan0.99", Addresses: []string{"192.0.2.99/24"}},
			{Name: "wan-a"},
			{Name: "wan-b"},
		},
		VLANs: []domain.VLAN{{Interface: "vlan0.99", Parent: "vtnet0", Tag: 99}},
	}
	payload, err := unifi.Render(id, bindings, "vlan0.99", snap, domain.Adoption{}, "", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	if got := root["uplink"]; got != "eth0.99" {
		t.Errorf("Render uplink = %v, want eth0.99", got)
	}
	if got := root["ip"]; got != id.ManagementIP {
		t.Errorf("Render ip = %v, want configured management IP %s", got, id.ManagementIP)
	}
}

func TestWANMonitorHealthProjectsCurrentProbeResults(t *testing.T) {
	t.Parallel()
	for _, connected := range []bool{true, false} {
		id := identity()
		loss, latency := 2.5, 7.0
		snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "uplink"}}, Gateways: []domain.GatewayMonitor{{Role: "wan", Connected: &connected, LossPercent: &loss, LatencyMS: &latency}},
			WANHistory: []domain.WANHistory{{Role: "wan", StreakSeconds: 120.6, OfflineSeconds: 30.2}}}
		b, err := unifi.Render(id, []domain.Binding{{Port: 1, Interface: "uplink", Role: "wan"}}, "", snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second, 0)
		if err != nil {
			t.Fatal(err)
		}
		var root map[string]any
		if err := json.Unmarshal(b, &root); err != nil {
			t.Fatal(err)
		}
		health := root["uptime_stats"].(map[string]any)["WAN"].(map[string]any)
		want, uptime := 0.0, 0.0
		if connected {
			want, uptime = 98, 120
		}
		probe := health["alerting_monitors"].([]any)[0].(map[string]any)
		if health["uptime"] != uptime || health["downtime"] != float64(30) || health["availability"] != want || probe["availability"] != want || probe["latency_average"] != latency {
			t.Fatal("current WAN probe health was not projected correctly")
		}
	}
}

func TestNetworkTableReportsCARPAddressFirst(t *testing.T) {
	t.Parallel()
	id := identity()
	bindings := []domain.Binding{{Port: 1, Interface: "lan-a", Role: "lan"}}
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(),
		Interfaces: []domain.Interface{{Name: "lan-a", Addresses: []string{"2001:db8::4/64", "192.0.2.4/24", "192.0.2.1/24"}}},
		CARP:       []domain.CARPObservation{{Interface: "lan-a", Address: "192.0.2.1", State: "MASTER"}, {Interface: "other", Address: "192.0.2.4", State: "MASTER"}}}
	b, err := unifi.Render(id, bindings, "", snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Networks []struct {
			Address   string   `json:"address"`
			Addresses []string `json:"addresses"`
		} `json:"network_table"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	got := root.Networks[0]
	if got.Address != "192.0.2.1/24" || len(got.Addresses) != 3 || got.Addresses[0] != "192.0.2.1/24" || got.Addresses[1] != "2001:db8::4/64" {
		t.Fatalf("network row = %+v", got)
	}
}

func TestWANStreakCountsOnlyMeasuredContinuousUptime(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tracker := usecase.WANTracker{MaxGap: time.Minute}
	sample := func(offset time.Duration, connected bool) domain.WANHistory {
		snap := tracker.Apply(domain.Snapshot{ObservedAt: start.Add(offset), Gateways: []domain.GatewayMonitor{{Role: "wan", Name: "probe", Connected: &connected}}})
		return snap.WANHistory[0]
	}
	steps := []struct {
		offset           time.Duration
		connected        bool
		streak, downtime float64
	}{
		{0, true, 0, 0},
		{10 * time.Second, true, 10, 0},
		{20 * time.Second, true, 20, 0},
		{30 * time.Second, false, 0, 0},
		{40 * time.Second, false, 0, 10},
		{50 * time.Second, true, 0, 20},
		{60 * time.Second, true, 10, 20},
		{200 * time.Second, true, 10, 20},
	}
	for _, step := range steps {
		got := sample(step.offset, step.connected)
		if got.StreakSeconds != step.streak || got.OfflineSeconds != step.downtime {
			t.Fatalf("at %s streak=%v downtime=%v, want %v and %v", step.offset, got.StreakSeconds, got.OfflineSeconds, step.streak, step.downtime)
		}
	}
}

func TestConnectedWANReportsPositiveUptimeAtStreakStart(t *testing.T) {
	t.Parallel()
	id := identity()
	connected := true
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "uplink"}}, Gateways: []domain.GatewayMonitor{{Role: "wan", Connected: &connected}},
		WANHistory: []domain.WANHistory{{Role: "wan", OfflineSeconds: 12}}}
	b, err := unifi.Render(id, []domain.Binding{{Port: 1, Interface: "uplink", Role: "wan"}}, "", snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Health map[string]map[string]any `json:"uptime_stats"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root.Health["WAN"]["uptime"] != float64(1) || root.Health["WAN"]["downtime"] != float64(12) {
		t.Fatalf("uptime_stats = %v", root.Health["WAN"])
	}
}
