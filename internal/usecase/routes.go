// Package usecase coordinates collection, publication, and configuration planning.
package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// RouteRepository collects configured routes and executes explicit additions.
type RouteRepository interface {
	Routes(context.Context) ([]domain.Route, error)
	AddRoute(context.Context, domain.Route) (string, error)
	ReconfigureRoutes(context.Context) error
}

// ApplyOptions binds a reviewed plan to the configured appliance and journal.
type ApplyOptions struct {
	Plan      domain.RoutePlan
	Identity  domain.Identity
	SourceURL string
	Policy    RoutePolicy
	Record    func(domain.RouteApplyResult) error
}

// RoutePolicy authorizes controller routes by destination and explicit gateway map.
type RoutePolicy struct {
	AllowedNetworks []string
	GatewayMap      map[string]string
	ControllerPath  []string
	NetworkField    string
	GatewayField    string
}

// ExtractRoutes selects a locally configured array path from a controller push.
// Field mappings are provided from the operator's gateway capture.
func ExtractRoutes(data []byte, policy RoutePolicy) ([]domain.Route, error) {
	if len(policy.ControllerPath) == 0 {
		return nil, fmt.Errorf("controller route mapping is not configured")
	}
	var current any
	if err := json.Unmarshal(data, &current); err != nil {
		return nil, err
	}
	for _, key := range policy.ControllerPath {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("route path must traverse JSON objects")
		}
		current, ok = obj[key]
		if !ok {
			return nil, fmt.Errorf("controller push is missing configured route path")
		}
	}
	rows, ok := current.([]any)
	if !ok {
		return nil, fmt.Errorf("controller route path must contain an array")
	}
	out := make([]domain.Route, 0, len(rows))
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("controller route must be an object")
		}
		network, nok := row[policy.NetworkField].(string)
		gateway, gok := row[policy.GatewayField].(string)
		if !nok || !gok {
			return nil, fmt.Errorf("controller route fields must be strings")
		}
		mapped, ok := policy.GatewayMap[gateway]
		if !ok {
			return nil, fmt.Errorf("controller route uses an unmapped next hop")
		}
		out = append(out, domain.Route{Network: network, Gateway: mapped, Description: "opnsense-uxg"})
	}
	return out, nil
}

// BuildRoutePlan compares desired routes with current routes and proposes additions.
// A conflicting existing destination requires local resolution.
func BuildRoutePlan(id domain.Identity, version string, desired, current []domain.Route, policy RoutePolicy) (domain.RoutePlan, error) {
	baseline := append([]domain.Route{}, current...)
	sort.Slice(baseline, func(i, j int) bool {
		a, b := baseline[i], baseline[j]
		if a.Network != b.Network {
			return a.Network < b.Network
		}
		if a.Gateway != b.Gateway {
			return a.Gateway < b.Gateway
		}
		if a.Description != b.Description {
			return a.Description < b.Description
		}
		return !a.Disabled && b.Disabled
	})
	b, err := json.Marshal(baseline)
	if err != nil {
		return domain.RoutePlan{}, err
	}
	sum := sha256.Sum256(b)
	plan := domain.RoutePlan{SourceID: id.ID, MAC: id.MAC, CFGVersion: version, Baseline: hex.EncodeToString(sum[:]), Additions: []domain.Route{}}
	seen := map[string]bool{}
	for _, route := range desired {
		if route.Disabled {
			return plan, fmt.Errorf("route additions must be enabled")
		}
		p, err := netip.ParsePrefix(route.Network)
		if err != nil || p != p.Masked() || p.Bits() == 0 {
			return plan, fmt.Errorf("route destination must be a canonical non-default prefix")
		}
		allowed := false
		for _, network := range policy.AllowedNetworks {
			a, err := netip.ParsePrefix(network)
			if err == nil && a.Addr().BitLen() == p.Addr().BitLen() && a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
				allowed = true
			}
		}
		if !allowed {
			return plan, fmt.Errorf("route destination is outside local allowlist")
		}
		gatewayAllowed := false
		for _, gateway := range policy.GatewayMap {
			if route.Gateway != "" && gateway == route.Gateway {
				gatewayAllowed = true
			}
		}
		if !gatewayAllowed {
			return plan, fmt.Errorf("route gateway is outside local allowlist")
		}
		if seen[route.Network] {
			return plan, fmt.Errorf("duplicate desired route destination")
		}
		seen[route.Network] = true
		exists := false
		for _, old := range current {
			prefix, err := netip.ParsePrefix(old.Network)
			if err != nil {
				return plan, fmt.Errorf("invalid existing route prefix")
			}
			if prefix.Masked() != p {
				continue
			}
			if old.Gateway != route.Gateway || old.Disabled {
				return plan, fmt.Errorf("desired route conflicts with existing destination")
			}
			exists = true
		}
		if !exists {
			plan.Additions = append(plan.Additions, route)
		}
	}
	sort.Slice(plan.Additions, func(i, j int) bool { return plan.Additions[i].Network < plan.Additions[j].Network })
	return plan, nil
}

// ApplyRoutePlan checks fresh state before adding, reconfiguring, and reading back
// routes. The caller retains progress when a write partially succeeds.
func ApplyRoutePlan(ctx context.Context, repo RouteRepository, options ApplyOptions) (domain.RouteApplyResult, error) {
	plan, id, sourceURL, policy := options.Plan, options.Identity, options.SourceURL, options.Policy
	r := domain.RouteApplyResult{SourceID: id.ID, AddedUUIDs: []string{}}
	if plan.SourceID != id.ID || plan.MAC != id.MAC || plan.SourceURL != sourceURL {
		return r, fmt.Errorf("route plan belongs to another appliance or virtual identity")
	}
	current, err := repo.Routes(ctx)
	if err != nil {
		return r, err
	}
	fresh, err := BuildRoutePlan(id, plan.CFGVersion, plan.Additions, current, policy)
	if err != nil {
		return r, err
	}
	if fresh.Baseline != plan.Baseline || len(fresh.Additions) != len(plan.Additions) {
		return r, fmt.Errorf("route inventory changed; generate and review a fresh plan")
	}
	record := func(stage string) error {
		r.Stage = stage
		if options.Record != nil {
			return options.Record(r)
		}
		return nil
	}
	for _, route := range fresh.Additions {
		r.InFlightNetwork = route.Network
		if err := record("adding"); err != nil {
			return r, fmt.Errorf("write apply journal: %w", err)
		}
		uuid, err := repo.AddRoute(ctx, route)
		if err != nil {
			return r, err
		}
		r.AddedUUIDs = append(r.AddedUUIDs, uuid)
		r.InFlightNetwork = ""
		if err := record("saved"); err != nil {
			return r, fmt.Errorf("write apply journal: %w", err)
		}
	}
	if len(r.AddedUUIDs) > 0 {
		if err := record("reconfiguring"); err != nil {
			return r, fmt.Errorf("write apply journal: %w", err)
		}
		if err := repo.ReconfigureRoutes(ctx); err != nil {
			return r, err
		}
		r.Reconfigured = true
	}
	if err := record("verifying"); err != nil {
		return r, fmt.Errorf("write apply journal: %w", err)
	}
	updated, err := repo.Routes(ctx)
	if err != nil {
		return r, err
	}
	verification, err := BuildRoutePlan(id, plan.CFGVersion, plan.Additions, updated, policy)
	if err != nil {
		return r, err
	}
	if len(verification.Additions) > 0 {
		return r, fmt.Errorf("route readback did not match plan")
	}
	r.Verified = true
	return r, record("verified")
}
