package framework_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// Synthetic projection test; controller retention is a separate live check.
func TestGatewayProfileMapsWANAndLANWithoutClaimingWriteCapabilities(t *testing.T) {
	t.Parallel()
	id := identity()
	id.Model = "UXGPRO"
	up := true
	rx, tx := uint64(1234), uint64(5678)
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{
		{Name: "igc0", Up: &up, Addresses: []string{"192.0.2.2/24"}, Counters: domain.Counters{RXBytes: &rx, TXBytes: &tx}},
		{Name: "igc1", Addresses: []string{"198.51.100.1/24"}},
	}}
	bindings := []domain.Binding{{Port: 1, Interface: "igc0", Role: "wan"}, {Port: 2, Interface: "igc1", Role: "lan"}}
	body, err := unifi.Render(id, bindings, "", snap, domain.Adoption{MAC: id.MAC}, "https://192.0.2.100:8080/inform", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version struct {
			Version int `json:"version"`
		} `json:"udapi_version"`
		Caps       int `json:"udapi_caps"`
		Interfaces []struct {
			Name    string `json:"name"`
			Comment string `json:"comment"`
			RX      uint64 `json:"rx_bytes"`
		} `json:"if_table"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version.Version != 48 || got.Caps != 0 || len(got.Interfaces) != 2 || got.Interfaces[0].Name != "eth0" || got.Interfaces[0].Comment != "WAN" || got.Interfaces[0].RX != rx || got.Interfaces[1].Comment != "LAN" {
		t.Fatal("incorrect gateway schema, capabilities or measured WAN mapping")
	}
}

func TestEnterpriseProfileUsesSixPortsAndEnterpriseSchema(t *testing.T) {
	t.Parallel()
	id := identity()
	id.Model = "UXGENT"
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "wan-a"}, {Name: "wan-b"}}}
	bindings := []domain.Binding{{Port: 1, Interface: "wan-a", Role: "wan"}, {Port: 5, Interface: "wan-b", Role: "wan2"}}
	b, err := unifi.Render(id, bindings, "", snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p["model"] != "UXGENT" || p["num_port"] != float64(6) || p["udapi_version"].(map[string]any)["version"] != "2.0.0" || p["wan2"].(map[string]any)["ifname"] != "eth4" {
		t.Fatal("incorrect Enterprise model or WAN2 mapping")
	}
	if _, ok := p["usg2_caps"]; ok {
		t.Fatal("profile alone advertised unimplemented managed-shadow support")
	}
}

// Media values follow the 10.6.106 uidb port speeds; the snapshot is synthetic.
func TestPortsReportModelMediaAndEmptyGatewayCapabilities(t *testing.T) {
	t.Parallel()
	id := identity()
	id.Model = "UXGENT"
	bindings := []domain.Binding{{Port: 1, Interface: "lan-a", Role: "lan"}, {Port: 5, Interface: "wan-a", Role: "wan"}, {Port: 6, Interface: "wan-b", Role: "wan2"}}
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "lan-a"}, {Name: "wan-a"}, {Name: "wan-b"}}}
	b, err := unifi.Render(id, bindings, "", snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Ports []struct {
			Index int    `json:"port_idx"`
			Media string `json:"media"`
		} `json:"port_table"`
		Caps map[string]any `json:"gw_caps"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	want := map[int]string{1: "2P5GE", 5: "SFP28", 6: "SFP28"}
	for _, port := range root.Ports {
		if port.Media != want[port.Index] {
			t.Fatalf("port %d media = %q, want %q", port.Index, port.Media, want[port.Index])
		}
	}
	if len(root.Ports) != 3 || root.Caps == nil || len(root.Caps) != 0 {
		t.Fatalf("ports %+v gw_caps %v", root.Ports, root.Caps)
	}
}
