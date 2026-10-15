package framework_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/filestate"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/opnsense"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

// API samples in this file are synthetic cases based on documented endpoint shapes.
func TestApplianceTelemetryAndWANProjection(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("telemetry method = %q, want GET", r.Method)
		}
		var body string
		switch r.URL.Path {
		case "/api/diagnostics/interface/getInterfaceConfig":
			body = interfaceJSON
		case "/api/interfaces/overview/interfaces_info":
			body = `{"rows":[{"description":"Internet","config":{"if":"igc0","enable":"1","ipaddr":"dhcp"}},{"description":"Internal","config":{"if":"igc1","enable":"0","ipaddr":"198.51.100.1"},"ipv4":[{"ipaddr":"198.51.100.254","vhid":"10","status":"MASTER"}],"ipv6":[{"ipaddr":"2001:db8::ff/64","vhid":"10","status":"BACKUP"}]}]}`
		case "/api/diagnostics/system/system_information":
			body = `{"name":"edge.example.net","versions":["OPNsense 26.1-amd64","FreeBSD 14.3"]}`
		case "/api/diagnostics/system/system_time":
			body = `{"uptime":"2 jours, 03:04:05","loadavg":"0.10, 0.20, 0.30"}`
		case "/api/diagnostics/system/system_resources":
			body = `{"memory":{"total":"1048576","used":262144}}`
		case "/api/diagnostics/system/system_temperature":
			body = `[{"device":"dev.cpu.0.temperature","type":"cpu","temperature":"42.5"}]`
		case "/api/diagnostics/cpu_usage/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			body = ": heartbeat\n\ndata: {\"total\":12.5,\"user\":10,\"sys\":2.5}\n\n"
		case "/api/routes/gateway/status":
			body = `{"status":"ok","items":[{"name":"WAN_GW","status":"none","delay":"7.4 ms","loss":"0.0 %"}]}`
		default:
			t.Errorf("unexpected endpoint %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	source := &opnsense.Source{Client: client, ID: "edge", System: true, CPU: true, Temperature: true, GatewayMonitors: map[string]string{"wan": "WAN_GW"}}
	snap, err := source.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Warnings) != 0 || snap.System.UptimeSeconds == nil || *snap.System.UptimeSeconds != 183845 || snap.System.CPUPercent == nil || *snap.System.CPUPercent != 12.5 || len(snap.System.Temperatures) != 1 {
		t.Fatalf("appliance telemetry = %+v, warnings %v", snap.System, snap.Warnings)
	}
	if len(snap.Gateways) != 1 || snap.Gateways[0].Connected == nil || !*snap.Gateways[0].Connected || snap.Gateways[0].LossPercent == nil || *snap.Gateways[0].LossPercent != 0 {
		t.Fatalf("WAN metrics = %+v", snap.Gateways)
	}
	if snap.Interfaces[0].IPv4Mode != "dhcp" || snap.Interfaces[0].AdminEnabled == nil || !*snap.Interfaces[0].AdminEnabled || snap.Interfaces[1].IPv4Mode != "static" || snap.Interfaces[1].AdminEnabled == nil || *snap.Interfaces[1].AdminEnabled {
		t.Fatal("interface assignments did not retain observed address modes and administrative state")
	}
	if len(snap.CARP) != 2 || snap.CARP[0].State != "MASTER" || snap.CARP[1].State != "BACKUP" || snap.CARP[1].Address != "2001:db8::ff" || snap.CARP[0].VHID == nil || *snap.CARP[0].VHID != 10 {
		t.Fatal("per-VIP CARP observations were lost or collapsed into a global role")
	}
	b, err := unifi.Render(identity(), bindings(), "", snap, domain.Adoption{}, "", time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["uptime"] != float64(183845) || payload["version"] != "5.1.26.33914" {
		t.Errorf("wire identity/uptime = %v/%v", payload["version"], payload["uptime"])
	}
	usage := payload["system-stats"].(map[string]any)
	if usage["cpu"] != "12.5" || usage["mem"] != "25.0" {
		t.Errorf("system stats = %v", usage)
	}
	rows := payload["if_table"].([]any)
	wan := rows[1].(map[string]any)
	if wan["isWanConnected"] != true || wan["latency"] != float64(7) {
		t.Errorf("WAN wire row = %v", wan)
	}
	if _, ok := rows[0].(map[string]any)["isWanConnected"]; ok {
		t.Error("LAN gained WAN health")
	}
	configWAN := payload["config_network_wan"].(map[string]any)
	if configWAN["type"] != "dhcp" || configWAN["ifname"] != "eth1" || payload["wans"].([]any)[0].(map[string]any)["enabled"] != true {
		t.Fatal("WAN assignment did not use observed mode and administrative state")
	}
	assignments := payload["ethernet_overrides"].([]any)
	if assignments[1].(map[string]any)["networkgroup"] != "WAN" || assignments[1].(map[string]any)["ifname"] != "eth1" {
		t.Fatal("WAN port assignment was not reported")
	}
}

func TestOptionalTelemetryFailureClearsMeasurements(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/diagnostics/interface/getInterfaceConfig" {
			_, _ = io.WriteString(w, interfaceJSON)
			return
		}
		http.Error(w, "not authorized", http.StatusForbidden)
	}))
	defer srv.Close()
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	source := &opnsense.Source{Client: client, ID: "edge", System: true, CPU: true, Temperature: true, GatewayMonitors: map[string]string{"wan": "WAN_GW"}}
	snap, err := source.Collect(t.Context())
	if err != nil || len(snap.Interfaces) != 2 || len(snap.Warnings) != 7 {
		t.Fatalf("partial collection = %+v, %v", snap, err)
	}
	if snap.System.CPUPercent != nil || snap.System.UptimeSeconds != nil || len(snap.Gateways) > 0 {
		t.Error("failed endpoints produced measurements")
	}
	b, err := unifi.Render(identity(), bindings(), "", snap, domain.Adoption{}, "", time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "isWanConnected") || strings.Contains(string(b), "system-stats") {
		t.Error("failed telemetry was represented as healthy")
	}
}

func TestRatesWindowsResetRebootAndOwnership(t *testing.T) {
	t.Parallel()
	var tracker usecase.RateTracker
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rx, tx, uptime := uint64(100), uint64(200), int64(100)
	sample := func(at time.Time) domain.Snapshot {
		return domain.Snapshot{SourceID: "edge", ObservedAt: at, System: domain.System{UptimeSeconds: &uptime}, Interfaces: []domain.Interface{{Name: "igc0", Counters: domain.Counters{RXBytes: &rx, TXBytes: &tx}}}}
	}
	first := tracker.Apply(sample(now))
	if first.Interfaces[0].Rates.RXBytesPerSecond != nil {
		t.Error("first sample produced a rate")
	}
	rx, tx, uptime = 150, 200, 105
	second := tracker.Apply(sample(now.Add(5 * time.Second)))
	if second.Interfaces[0].Rates.RXBytesPerSecond == nil || *second.Interfaces[0].Rates.RXBytesPerSecond != 10 || *second.Interfaces[0].Rates.TXBytesPerSecond != 0 {
		t.Fatalf("rates = %+v", second.Interfaces[0].Rates)
	}
	rx = 1
	reset := tracker.Apply(sample(now.Add(10 * time.Second)))
	if reset.Interfaces[0].Rates.RXBytesPerSecond != nil {
		t.Error("counter reset became a rate")
	}
	rx, uptime = 1000, 1
	reboot := tracker.Apply(sample(now.Add(15 * time.Second)))
	if reboot.Interfaces[0].Rates.TXBytesPerSecond != nil {
		t.Error("appliance reboot retained rate window")
	}
	tracker.Clear()
	if got := tracker.Apply(sample(now.Add(20 * time.Second))); got.Interfaces[0].Rates.RXBytesPerSecond != nil {
		t.Error("collection gap retained rate window")
	}
}

func TestCPUStreamBoundsAndCancellation(t *testing.T) {
	t.Parallel()
	for _, payload := range []string{"data: {\"total\":101}\n\n", "data: {\"total\":\"NaN\"}\n\n", "data: {}\n\n", "data: {\"total\":0}", strings.Repeat("x", 70<<10)} {
		t.Run(payload[:min(len(payload), 24)], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, payload)
			}))
			defer srv.Close()
			client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.CPUUsage(t.Context()); err == nil {
				t.Error("invalid/incomplete CPU event accepted")
			}
		})
	}
	started, finished := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(finished)
	}))
	defer srv.Close()
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := client.CPUUsage(ctx); result <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("CPU stream did not start")
	}
	cancel()
	if err := <-result; err == nil {
		t.Error("CPU stream ignored cancellation")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("CPU stream request did not close")
	}
}

func TestStatusFreshnessAndSecretFreeOutput(t *testing.T) {
	t.Parallel()
	now := time.Now()
	path := filepath.Join(t.TempDir(), "status.json")
	cycle := usecase.CycleResult{SourceID: "edge", AttemptedAt: now, LastCollectionAt: now, LastInformAt: now, Adopted: true, NextDelay: 10 * time.Second, Provisioning: "awaiting_local_review", ProvisioningVersion: "pending", Commands: domain.CommandStatus{Name: "wg-genkeypair", Pending: true}}
	if err := filestate.WriteJSON(path, cycle); err != nil {
		t.Fatal(err)
	}
	fresh, err := filestate.ReadStatus(path, "edge", now.Add(time.Second))
	if err != nil || fresh.Stale || !fresh.Available {
		t.Fatalf("fresh status = %+v, %v", fresh, err)
	}
	stale, err := filestate.ReadStatus(path, "edge", now.Add(time.Minute))
	if err != nil || !stale.Stale {
		t.Fatalf("stale status = %+v, %v", stale, err)
	}
	b, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"auth_key", "private_key", "request_id", "system_cfg"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("status exposes secret field %q", secret)
		}
	}
	pub := &countingPublisher{}
	worker := &usecase.Worker{ID: "edge", Source: failedSource{}, Publisher: pub, Store: &memoryStore{value: domain.Adoption{MAC: identity().MAC, AuthKey: "0123456789abcdef0123456789abcdef"}}, Timeout: time.Second}
	worker.RestoreStatus(cycle)
	result, err := worker.Cycle(t.Context())
	if err == nil || !result.Adopted || !result.LastInformAt.Equal(cycle.LastInformAt) || !result.LastCollectionAt.Equal(cycle.LastCollectionAt) || pub.calls != 0 {
		t.Errorf("restart/failure lost lifecycle history: %+v, %v", result, err)
	}
}

// API responses are synthetic and follow the documented endpoint shapes.
func TestCountersRefreshBetweenFullCollections(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	hits := map[string]int{}
	failStats := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits[r.URL.Path]++
		switch r.URL.Path {
		case "/api/diagnostics/interface/getInterfaceConfig":
			_, _ = io.WriteString(w, interfaceJSON)
		case "/api/diagnostics/interface/getInterfaceStatistics":
			if failStats {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = fmt.Fprintf(w, `{"statistics":{"[igc0]":{"name":"igc0","received-bytes":%d,"sent-bytes":%d}}}`, 1000*hits[r.URL.Path], 10*hits[r.URL.Path])
		case "/api/interfaces/overview/interfaces_info":
			_, _ = io.WriteString(w, `{"rows":[{"description":"Internet","config":{"if":"igc0","enable":"1","ipaddr":"dhcp"}}]}`)
		case "/api/routes/gateway/status":
			_, _ = io.WriteString(w, `{"status":"ok","items":[{"name":"WAN_GW","status":"none","delay":"7.4 ms","loss":"0.0 %"}]}`)
		default:
			t.Errorf("unexpected endpoint %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	source := &opnsense.Source{Client: client, ID: "edge", Statistics: true, GatewayMonitors: map[string]string{"wan": "WAN_GW"}, FullInterval: time.Minute, Now: func() time.Time { return now }}
	collect := func(at time.Duration) domain.Snapshot {
		t.Helper()
		now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(at)
		snap, err := source.Collect(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return snap
	}
	count := func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits["/api/"+path]
	}
	collect(0)
	fast := collect(10 * time.Second)
	if count("diagnostics/interface/getInterfaceConfig") != 1 || count("interfaces/overview/interfaces_info") != 1 || count("diagnostics/interface/getInterfaceStatistics") != 2 || count("routes/gateway/status") != 2 {
		t.Fatalf("fast cycle requests = %v", hits)
	}
	if fast.ObservedAt != now || *fast.Interfaces[0].Counters.RXBytes != 2000 || fast.Interfaces[0].IPv4Mode != "dhcp" || len(fast.Gateways) != 1 {
		t.Fatalf("fast snapshot = %+v", fast)
	}
	collect(61 * time.Second)
	if count("diagnostics/interface/getInterfaceConfig") != 2 {
		t.Fatal("full collection did not resume after its interval")
	}
	mu.Lock()
	failStats = true
	mu.Unlock()
	if _, err := source.Collect(t.Context()); err == nil {
		t.Fatal("failed counter refresh was reported as success")
	}
	mu.Lock()
	failStats = false
	mu.Unlock()
	collect(65 * time.Second)
	if count("diagnostics/interface/getInterfaceConfig") != 3 {
		t.Fatal("failed counter refresh did not force a full collection")
	}
}

func TestMinimumInformIntervalIsAdvertised(t *testing.T) {
	t.Parallel()
	id := identity()
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "uplink"}}}
	b, err := unifi.Render(id, []domain.Binding{{Port: 1, Interface: "uplink", Role: "lan"}}, "", snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root["inform_min_interval"] != float64(2) {
		t.Fatalf("inform_min_interval = %v", root["inform_min_interval"])
	}
}
