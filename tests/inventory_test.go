package framework_test

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jamesbraid/unifi-emu/discovery"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/opnsense"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

// Fixtures here are synthetic documented API shapes, not appliance captures.
func TestInventoryClientAssociationAndFlowProjection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	expiry := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("collection mutated the appliance")
		}
		var body string
		switch r.URL.Path {
		case "/api/diagnostics/interface/getInterfaceConfig":
			body = strings.TrimSuffix(interfaceJSON, "}") + `,"vlan10":{"device":"vlan10","status":"active","ipv4":[{"ipaddr":"198.51.100.1","subnetbits":24}],"ipv6":[{"ipaddr":"2001:db8::1","subnetbits":64}]}}`
		case "/api/diagnostics/interface/get_arp":
			body = `[{"ip":"198.51.100.10","mac":"02:00:00:00:00:10","intf":"vlan10"},{"ip":"198.51.100.99","mac":"(incomplete)","intf":"vlan10"},{"ip":"192.0.2.1","mac":"02:00:00:00:00:20","intf":"igc0"}]`
		case "/api/diagnostics/interface/get_ndp":
			body = `[{"ip":"2001:db8::10","mac":"02:00:00:00:00:10","intf":"vlan10"}]`
		case "/api/interfaces/vlan_settings/searchItem":
			body = `{"total":1,"rows":[{"uuid":"vlan-test"}]}`
		case "/api/interfaces/vlan_settings/getItem/vlan-test":
			body = `{"vlan":{"if":{"igc1":{"selected":1,"value":"LAN"}},"tag":"10","vlanif":"vlan10","descr":"Clients"}}`
		case "/api/kea/leases4/search":
			body = `{"total":2,"rows":[{"address":"198.51.100.10","hwaddr":"02:00:00:00:00:10","if":"vlan10","hostname":"client.example.net","expire":"` + expiry + `","state":0,"lease_type":"static"},{"address":"198.51.100.11","hwaddr":"02:00:00:00:00:11","if":"vlan10","expire":` + expiry + `,"state":0}]}`
		case "/api/kea/leases6/search":
			body = `{"total":1,"rows":[{"address":"2001:db8::10","hwaddr":"02:00:00:00:00:10","if":"vlan10","expire":` + expiry + `,"state":0}]}`
		default:
			if strings.HasPrefix(r.URL.Path, "/api/diagnostics/networkinsight/top/FlowSourceAddrDetails/") {
				if r.URL.Query().Get("filter_field") != "if" || r.URL.Query().Get("filter_value") != "vlan10" {
					t.Error("flow query lost its observation-point filter")
				}
				body = `[{"src_addr":"198.51.100.10","dst_addr":"203.0.113.5","total":"1500.25"},{"src_addr":"203.0.113.5","dst_addr":"198.51.100.10","total":3000.75}]`
			} else {
				t.Errorf("unexpected inventory endpoint %s", r.URL)
				http.NotFound(w, r)
				return
			}
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	source := &opnsense.Source{Client: client, ID: "edge", Neighbors: true, VLANs: true, DHCPBackends: []string{"kea4", "kea6"}, Now: func() time.Time { return now }, Accounting: opnsense.AccountingOptions{Enabled: true, Interfaces: []string{"vlan10"}, Window: 5 * time.Minute, MaxRows: 100}}
	snap, err := source.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Warnings) != 0 || !snap.NeighborsComplete || !snap.LeasesComplete || len(snap.VLANs) != 1 {
		t.Fatalf("inventory warning/completeness = %+v", snap)
	}
	tracker := usecase.ClientTracker{}
	snap = tracker.Apply(snap, bindings())
	var observed, leased *domain.Client
	for i := range snap.Clients {
		row := &snap.Clients[i]
		if row.MAC == "02:00:00:00:00:10" {
			observed = row
		}
		if row.MAC == "02:00:00:00:00:11" {
			leased = row
		}
	}
	if observed == nil || observed.Presence != "observed" || len(observed.Addresses) != 2 || observed.Hostname != "client.example.net" || observed.Addresses[0].Port != 1 || observed.Addresses[0].VLAN != 10 {
		t.Fatalf("merged client = %+v", observed)
	}
	if leased == nil || leased.Presence != "lease_only" {
		t.Fatalf("lease incorrectly marked observed = %+v", leased)
	}
	if len(observed.Traffic) != 1 || observed.Traffic[0].RXBytes == nil || *observed.Traffic[0].RXBytes != 3001 || *observed.Traffic[0].TXBytes != 1500 || observed.Traffic[0].To.Sub(observed.Traffic[0].From) != 5*time.Minute {
		t.Fatalf("client window totals = %+v", observed.Traffic)
	}
	b, err := unifi.Render(identity(), bindings(), "", snap, domain.Adoption{}, "", time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Networks []struct {
			Name   string           `json:"name"`
			Hosts  []map[string]any `json:"host_table"`
			Leases *int             `json:"active_dhcp_lease_count"`
		} `json:"network_table"`
		Leases []map[string]any `json:"ipv4_active_leases"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	var hosts []map[string]any
	for _, row := range root.Networks {
		if row.Name == "eth0.10" {
			hosts = row.Hosts
		}
		if row.Name == "eth1" && len(row.Hosts) != 0 {
			t.Error("upstream WAN neighbor was reported as a LAN client")
		}
	}
	if len(hosts) != 1 || hosts[0]["mac"] != "02:00:00:00:00:10" || hosts[0]["rx_bytes-r"] != float64(10) || hosts[0]["tx_bytes-r"] != float64(5) || len(root.Leases) != 2 {
		t.Fatalf("client wire projection = %+v, leases %+v", hosts, root.Leases)
	}
	if _, exists := hosts[0]["rx_bytes"]; exists {
		t.Error("rolling window was reported as a lifetime counter")
	}
	counted := 0
	for _, row := range root.Networks {
		if row.Leases == nil {
			t.Fatalf("network %s omitted its lease count", row.Name)
		}
		counted += *row.Leases
	}
	if counted != len(root.Leases) {
		t.Fatalf("network lease counts total %d, reported %d leases", counted, len(root.Leases))
	}
	for _, lease := range root.Leases {
		if _, ok := lease["leaseExpiry"].(float64); !ok {
			t.Fatalf("lease %v omitted leaseExpiry", lease)
		}
	}
}

func TestClientLifecyclePartialFailureAndResolution(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tracker := usecase.ClientTracker{TTL: 5 * time.Minute}
	first := domain.Snapshot{SourceID: "edge", ObservedAt: now, NeighborsComplete: true, LeasesComplete: true, Neighbors: []domain.Neighbor{{IP: "192.0.2.10", Interface: "igc1", Incomplete: true}}}
	initial := tracker.Apply(first, bindings())
	if len(initial.Clients) != 1 || !initial.Clients[0].Incomplete {
		t.Fatal("incomplete neighbor was lost")
	}
	first.ObservedAt = now.Add(time.Minute)
	first.Neighbors[0].MAC = "02:00:00:00:00:10"
	first.Neighbors[0].Incomplete = false
	resolved := tracker.Apply(first, bindings())
	if len(resolved.Clients) != 1 || resolved.Clients[0].Incomplete || !resolved.Clients[0].FirstSeen.Equal(now) {
		t.Fatalf("resolution duplicated/lost history: %+v", resolved.Clients)
	}
	partial := tracker.Apply(domain.Snapshot{SourceID: "edge", ObservedAt: now.Add(2 * time.Minute)}, bindings())
	if partial.Clients[0].Presence != "unknown" {
		t.Error("failed inventory was treated as disappearance")
	}
	absent := tracker.Apply(domain.Snapshot{SourceID: "edge", ObservedAt: now.Add(3 * time.Minute), NeighborsComplete: true, LeasesComplete: true}, bindings())
	if absent.Clients[0].Presence != "absent" || !absent.Clients[0].LastSeen.Equal(now.Add(time.Minute)) {
		t.Error("missing client changed last-seen time")
	}
	expired := tracker.Apply(domain.Snapshot{SourceID: "edge", ObservedAt: now.Add(7 * time.Minute), NeighborsComplete: true, LeasesComplete: true}, bindings())
	if len(expired.Clients) != 0 {
		t.Error("expired client history retained indefinitely")
	}
}

func TestFlowTruncationAndDnsmasqReaders(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/dnsmasq/leases/search" {
			_, _ = io.WriteString(w, `{"total":"1","rows":[{"address":"192.0.2.10","hwaddr":"02:00:00:00:00:10","if":"igc1","hostname":"client","expire":1800000000,"lease_type":"static"}]}`)
			return
		}
		_, _ = io.WriteString(w, `[{"src_addr":"192.0.2.10","dst_addr":"203.0.113.5","total":100}]`)
	}))
	defer srv.Close()
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	leases, err := client.Leases(t.Context(), "dnsmasq")
	if err != nil || len(leases) != 1 || !leases[0].Reserved {
		t.Fatalf("Dnsmasq reader = %+v, %v", leases, err)
	}
	if _, err := client.FlowTraffic(t.Context(), opnsense.AccountingOptions{Interfaces: []string{"igc1"}, Window: time.Minute, MaxRows: 1}, time.Now()); err == nil {
		t.Error("truncated top-host query accepted")
	}
}

func TestDiscoveryPacketAndWANHistory(t *testing.T) {
	t.Parallel()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	uptime := int64(123)
	now := time.Now()
	discoverer := &unifi.Discoverer{Identity: identity(), Targets: []string{listener.LocalAddr().String()}, Interval: time.Minute}
	if err := discoverer.Send(t.Context(), domain.Snapshot{ObservedAt: now, System: domain.System{UptimeSeconds: &uptime}}); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2048)
	n, _, err := listener.ReadFromUDP(data)
	if err != nil {
		t.Fatal(err)
	}
	announcement, err := discovery.Parse(data[:n])
	if err != nil || announcement.Platform != "UXG" || announcement.Uptime != 123 || announcement.MAC.String() != identity().MAC {
		t.Fatalf("discovery = %+v, %v", announcement, err)
	}
	var tracker usecase.WANTracker
	up, down := true, false
	sample := func(at time.Time, connected *bool) domain.Snapshot {
		return domain.Snapshot{ObservedAt: at, Gateways: []domain.GatewayMonitor{{Name: "WAN_GW", Role: "wan", Connected: connected}}}
	}
	tracker.Apply(sample(now, &up))
	tracker.Apply(sample(now.Add(10*time.Second), &down))
	tracked := tracker.Apply(sample(now.Add(20*time.Second), &down))
	if tracked.WANHistory[0].OnlineSeconds != 10 || tracked.WANHistory[0].OfflineSeconds != 10 || tracked.WANHistory[0].Outages != 1 {
		t.Errorf("WAN transition history = %+v", tracked.WANHistory)
	}
	tracked = tracker.Apply(sample(now.Add(2*time.Minute), &up))
	if tracked.WANHistory[0].UnknownSeconds != 100 {
		t.Error("collection gap became known availability")
	}
}

func TestOwnAddressesAndAmbiguousTrafficAttribution(t *testing.T) {
	t.Parallel()
	now := time.Now()
	bytes := uint64(100)
	snap := domain.Snapshot{SourceID: "edge", ObservedAt: now, NeighborsComplete: true, LeasesComplete: true,
		Interfaces: []domain.Interface{{Name: "igc1", Addresses: []string{"192.0.2.1/24"}}},
		Neighbors:  []domain.Neighbor{{IP: "192.0.2.1", MAC: "02:00:00:00:00:01", Interface: "igc1"}, {IP: "192.0.2.10", MAC: "02:00:00:00:00:10", Interface: "igc1"}},
		Leases:     []domain.Lease{{IP: "192.0.2.10", MAC: "02:00:00:00:00:11", Interface: "igc1"}},
		Traffic:    []domain.ClientTraffic{{IP: "192.0.2.10", Interface: "igc1", From: now.Add(-time.Minute), To: now, TXBytes: &bytes}}}
	tracker := usecase.ClientTracker{}
	result := tracker.Apply(snap, bindings())
	if len(result.Clients) != 2 {
		t.Fatalf("own address became a client: %+v", result.Clients)
	}
	for _, client := range result.Clients {
		if len(client.Traffic) != 0 {
			t.Error("ambiguous ownership duplicated client traffic")
		}
	}
}

func TestDirectVLANBindingsOverrideParentRoles(t *testing.T) {
	t.Parallel()
	snap := domain.Snapshot{SourceID: "edge", ObservedAt: time.Now(), NeighborsComplete: true, LeasesComplete: true,
		Interfaces: []domain.Interface{{Name: "igc1"}, {Name: "vlan100"}, {Name: "vlan200"}},
		VLANs:      []domain.VLAN{{Interface: "vlan100", Parent: "igc1", Tag: 100}, {Interface: "vlan200", Parent: "igc1", Tag: 200}},
		Neighbors:  []domain.Neighbor{{IP: "198.51.100.10", MAC: "02:00:00:00:00:10", Interface: "vlan100"}, {IP: "192.0.2.10", MAC: "02:00:00:00:00:20", Interface: "vlan200"}}}
	mapping := []domain.Binding{{Port: 1, Interface: "igc1", Role: "lan"}, {Port: 2, Interface: "vlan200", Role: "wan"}, {Port: 3, Interface: "vlan100", Role: "lan2"}}
	tracker := usecase.ClientTracker{}
	snap = tracker.Apply(snap, mapping)
	for _, client := range snap.Clients {
		a := client.Addresses[0]
		if a.Interface == "vlan100" && (a.Port != 3 || a.Role != "lan2" || a.VLAN != 100) {
			t.Errorf("direct LAN VLAN binding = %+v", a)
		}
		if a.Interface == "vlan200" && (a.Port != 2 || a.Role != "wan" || a.VLAN != 200) {
			t.Errorf("direct WAN VLAN binding = %+v", a)
		}
	}
	id := identity()
	id.Model = "UXGPRO"
	b, err := unifi.Render(id, mapping, "", snap, domain.Adoption{}, "", time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Networks []struct {
			Name  string           `json:"name"`
			Hosts []map[string]any `json:"host_table"`
		} `json:"network_table"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	for _, network := range root.Networks {
		if network.Name == "eth2" && len(network.Hosts) != 1 {
			t.Error("direct LAN VLAN did not report its client")
		}
		if network.Name == "eth1" && len(network.Hosts) != 0 {
			t.Error("WAN VLAN inherited its parent's LAN client role")
		}
	}
}
