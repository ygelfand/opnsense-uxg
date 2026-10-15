package framework_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/cymru"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

// TXT records are synthetic and follow the documented Team Cymru field order.
func TestCymruResolverPrefersMostSpecificOrigin(t *testing.T) {
	t.Parallel()
	queries := []string{}
	resolver := cymru.Resolver{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		queries = append(queries, name)
		switch name {
		case "10.2.0.192.origin.asn.cymru.com":
			return []string{"64501 | 192.0.0.0/16 | US | arin | 2001-01-01", "64500 64502 | 192.0.2.0/24 | US | arin | 2001-01-01"}, nil
		case "AS64500.asn.cymru.com":
			return []string{"64500 | US | arin | 2001-01-01 | EXAMPLE-64500 - Example Networks, LLC, US"}, nil
		}
		return nil, errors.New("unexpected query")
	}}
	provider, err := resolver.Lookup(context.Background(), netip.MustParseAddr("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	if provider.ASN != 64500 || provider.Name != "Example Networks, LLC" || provider.Organization != "Example Networks, LLC" || len(queries) != 2 {
		t.Fatalf("provider = %+v, queries = %v", provider, queries)
	}
	if _, err := resolver.Lookup(context.Background(), netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Fatal("unresolvable origin returned a provider")
	}
	if queries[2] != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.origin6.asn.cymru.com" {
		t.Fatalf("IPv6 origin query = %s", queries[2])
	}
}

func TestProviderTrackerCachesLookupsAndPrefersConfiguredNames(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lookups := map[netip.Addr]int{}
	failing := netip.MustParseAddr("198.51.100.7")
	tracker := usecase.ProviderTracker{
		Names:      map[string]string{"wan2": "Configured Provider"},
		RetryAfter: time.Minute,
		Lookup: func(_ context.Context, addr netip.Addr) (domain.Provider, error) {
			lookups[addr]++
			if addr == failing {
				return domain.Provider{}, errors.New("timeout")
			}
			return domain.Provider{Name: "Looked Up", Organization: "Looked Up Org", ASN: 64500}, nil
		},
	}
	bindings := []domain.Binding{{Port: 1, Interface: "lan", Role: "lan"}, {Port: 2, Interface: "wan-a", Role: "wan"}, {Port: 3, Interface: "wan-b", Role: "wan2"}}
	snapshot := func(at time.Time, wanA string) domain.Snapshot {
		return domain.Snapshot{ObservedAt: at, Interfaces: []domain.Interface{
			{Name: "lan", Addresses: []string{"10.0.0.1/24"}},
			{Name: "wan-a", Addresses: []string{"10.1.0.2/24", wanA}},
			{Name: "wan-b", Addresses: []string{"100.64.0.2/10"}},
		}}
	}
	first := tracker.Apply(context.Background(), snapshot(now, "192.0.2.10/24"), bindings)
	second := tracker.Apply(context.Background(), snapshot(now.Add(10*time.Second), "192.0.2.10/24"), bindings)
	want := []domain.Provider{{Role: "wan", Name: "Looked Up", Organization: "Looked Up Org", ASN: 64500}, {Role: "wan2", Name: "Configured Provider", Organization: "Configured Provider"}}
	for _, got := range [][]domain.Provider{first.Providers, second.Providers} {
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("providers = %+v", got)
		}
	}
	if len(lookups) != 1 || lookups[netip.MustParseAddr("192.0.2.10")] != 1 {
		t.Fatalf("lookups = %v", lookups)
	}
	failed := tracker.Apply(context.Background(), snapshot(now.Add(20*time.Second), "198.51.100.7/24"), bindings)
	if len(failed.Providers) != 1 || failed.Providers[0].Role != "wan2" || len(failed.Warnings) != 1 {
		t.Fatalf("failed lookup produced providers %+v warnings %v", failed.Providers, failed.Warnings)
	}
	tracker.Apply(context.Background(), snapshot(now.Add(30*time.Second), "198.51.100.7/24"), bindings)
	if lookups[failing] != 1 {
		t.Fatal("failed lookup retried before its retry interval")
	}
	tracker.Apply(context.Background(), snapshot(now.Add(90*time.Second), "198.51.100.7/24"), bindings)
	tracker.Apply(context.Background(), snapshot(now.Add(100*time.Second), "192.0.2.10/24"), bindings)
	if lookups[failing] != 2 || lookups[netip.MustParseAddr("192.0.2.10")] != 2 {
		t.Fatalf("retry or address change did not refresh lookups: %v", lookups)
	}
}

func TestProvidersRenderAsGeoInfoByWANGroup(t *testing.T) {
	t.Parallel()
	id := identity()
	bindings := []domain.Binding{{Port: 1, Interface: "wan-a", Role: "wan"}}
	snap := domain.Snapshot{SourceID: id.ID, ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "wan-a"}},
		Providers: []domain.Provider{{Role: "wan", Name: "Example Networks", Organization: "Example Networks, LLC", ASN: 64500}, {Role: "wan2", Name: "Unverified", ASN: 64501}}}
	b, err := unifi.Render(id, bindings, "", snap, domain.Adoption{}, "https://192.0.2.100/inform", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		GeoInfo map[string]map[string]any `json:"geo_info"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if wan := root.GeoInfo["WAN"]; wan["isp_name"] != "Example Networks" || wan["isp_organization"] != "Example Networks, LLC" || wan["asn"] != float64(64500) || len(root.GeoInfo) != 1 {
		t.Fatalf("geo_info = %v", root.GeoInfo)
	}
}
