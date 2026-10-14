package framework_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/config"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

func TestCARPHAProjectionDoesNotInventOwnershipOrTransition(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	bindings := []domain.Binding{{Port: 2, Interface: "trunk", Role: "lan"}, {Port: 1, Interface: "wan", Role: "wan"}}
	snap := domain.Snapshot{SourceID: "edge", ObservedAt: now, VLANs: []domain.VLAN{{Interface: "vlan10", Parent: "trunk", Tag: 10}}, CARP: []domain.CARPObservation{{Interface: "vlan10", Address: "198.51.100.1", State: "MASTER"}, {Interface: "wan", Address: "192.0.2.1", State: "BACKUP"}}}
	tracker := usecase.HATracker{Role: "primary", Peer: "other"}
	snap = tracker.Apply(snap, bindings)
	if snap.HA.CARPState != "master" || snap.HA.VIPCount != 1 || snap.HA.ObservedTransitionAt != nil {
		t.Fatal("inside ownership mixed with WAN ownership or transition invented")
	}
	snap.ObservedAt = now.Add(time.Minute)
	snap.CARP[0].State = "BACKUP"
	snap = tracker.Apply(snap, bindings)
	if snap.HA.CARPState != "backup" || snap.HA.ObservedTransitionAt == nil || !snap.HA.ObservedTransitionAt.Equal(snap.ObservedAt) {
		t.Fatal("observed CARP transition lost")
	}
	snap.CARP = append(snap.CARP, domain.CARPObservation{Interface: "vlan10", Address: "198.51.100.2", State: "MASTER"})
	snap = tracker.Apply(snap, bindings)
	if snap.HA.CARPState != "unknown" || snap.HA.Status != "mixed" || snap.HA.ObservedTransitionAt != nil {
		t.Fatal("mixed VIP ownership reported as a global role")
	}
	snap.CARP = nil
	snap = tracker.Apply(snap, bindings)
	if snap.HA.CARPState != "unknown" || snap.HA.Status != "unavailable" {
		t.Fatal("missing observations reused stale ownership")
	}
}

func TestHAConfigurationRequiresReciprocalEnterprisePair(t *testing.T) {
	t.Parallel()
	c, err := config.Load("../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for i := range c.Gateways {
		c.Gateways[i].Identity.Model = "UXGENT"
	}
	c.Gateways[0].HA = &config.HA{Role: "primary", Peer: c.Gateways[1].Identity.ID}
	c.Gateways[1].HA = &config.HA{Role: "shadow", Peer: c.Gateways[0].Identity.ID}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Gateways[1].HA.Role = "primary"
	if err := c.Validate(); err == nil {
		t.Fatal("two configured primaries accepted")
	}
	c.Gateways[1].HA.Role = "shadow"
	c.Gateways[1].Identity.Model = "UXGPRO"
	if err := c.Validate(); err == nil {
		t.Fatal("non-Enterprise shadow accepted")
	}
}

// Synthetic wire case exercises the schema inspected in controller 10.6.106.
func TestEnterpriseHAAdvertisesOnlyExplicitReportingSupport(t *testing.T) {
	t.Parallel()
	id := identity()
	id.Model = "UXGENT"
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "inside"}}, HA: &domain.HAStatus{Role: "shadow", Peer: "peer", CARPState: "backup", Status: "observed"}}
	b, err := unifi.Render(id, []domain.Binding{{Port: 2, Interface: "inside", Role: "lan"}}, snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p["usg2_caps"] != float64(1073741824) || p["vrrp"].(map[string]any)["state"] != "backup" {
		t.Fatal("managed-shadow capability or CARP-derived state missing")
	}
	if _, ok := p["vrrp"].(map[string]any)["lastTransition"]; ok {
		t.Fatal("unknown transition time invented")
	}
	if _, ok := p["shadow_mode_adopt"]; ok {
		t.Fatal("shadow setup success was fabricated")
	}
}
