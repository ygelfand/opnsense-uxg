package usecase

import (
	"context"
	"net/netip"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// ProviderTracker names WAN providers from configuration and cached lookups.
type ProviderTracker struct {
	Names      map[string]string
	Lookup     domain.ProviderLookup
	RetryAfter time.Duration
	cache      map[netip.Addr]providerResult
}

type providerResult struct {
	provider domain.Provider
	retryAt  time.Time
}

// Apply attaches providers for bound WAN roles, looking up each public address once.
func (t *ProviderTracker) Apply(ctx context.Context, snap domain.Snapshot, bindings []domain.Binding) domain.Snapshot {
	if len(t.Names) == 0 && t.Lookup == nil {
		return snap
	}
	retry := t.RetryAfter
	if retry <= 0 {
		retry = 15 * time.Minute
	}
	interfaces := make(map[string]domain.Interface, len(snap.Interfaces))
	for _, row := range snap.Interfaces {
		interfaces[row.Name] = row
	}
	seen := map[netip.Addr]bool{}
	providers := []domain.Provider{}
	for _, binding := range bindings {
		if binding.Role != "wan" && binding.Role != "wan2" {
			continue
		}
		provider := domain.Provider{Role: binding.Role}
		if addr, ok := publicAddress(interfaces[binding.Interface]); ok && t.Lookup != nil {
			seen[addr] = true
			cached, exists := t.cache[addr]
			if !exists || !cached.retryAt.IsZero() && !snap.ObservedAt.Before(cached.retryAt) {
				lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				found, err := t.Lookup(lookupCtx, addr)
				cancel()
				cached = providerResult{provider: found}
				if err != nil {
					cached = providerResult{retryAt: snap.ObservedAt.Add(retry)}
					snap.Warnings = append(snap.Warnings, "provider_lookup_failed")
				}
				if t.cache == nil {
					t.cache = map[netip.Addr]providerResult{}
				}
				t.cache[addr] = cached
			}
			provider.Name, provider.ASN = cached.provider.Name, cached.provider.ASN
		}
		if name := t.Names[binding.Role]; name != "" {
			provider.Name = name
		}
		if provider.Name != "" || provider.ASN != 0 {
			providers = append(providers, provider)
		}
	}
	for addr := range t.cache {
		if !seen[addr] {
			delete(t.cache, addr)
		}
	}
	snap.Providers = providers
	return snap
}

func publicAddress(row domain.Interface) (netip.Addr, bool) {
	for _, address := range row.Addresses {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			continue
		}
		addr := prefix.Addr()
		if addr.IsGlobalUnicast() && !addr.IsPrivate() && !sharedAddressSpace.Contains(addr) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}
