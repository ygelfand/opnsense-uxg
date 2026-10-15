package opnsense

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/browningluke/opnsense-go/pkg/diagnostics"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// Source reads interface configuration and optional measured counters.
type Source struct {
	Assignments     bool
	Client          *Client
	ID              string
	Statistics      bool
	Now             func() time.Time
	System          bool
	CPU             bool
	Temperature     bool
	GatewayMonitors map[string]string
	Timeout         time.Duration
	Neighbors       bool
	DHCPBackends    []string
	VLANs           bool
	Accounting      AccountingOptions
	FullInterval    time.Duration
	full            domain.Snapshot
	fullAt          time.Time
	accountingMu    sync.Mutex
	accountingTo    time.Time
	accountingData  []domain.ClientTraffic
}

// AccountingOptions selects exporter observation points and the query window.
type AccountingOptions struct {
	Enabled    bool
	Interfaces []string
	Window     time.Duration
	MaxRows    int
}

var _ domain.Source = (*Source)(nil)

// Collect returns interfaces sorted by device name and a completion timestamp.
func (s *Source) Collect(ctx context.Context) (domain.Snapshot, error) {
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if s.Statistics && s.FullInterval > 0 && !s.fullAt.IsZero() && now().Sub(s.fullAt) < s.FullInterval {
		snap, err := s.collectCounters(ctx, now)
		if err != nil {
			s.fullAt = time.Time{}
		}
		return snap, err
	}
	var raw map[string]diagnostics.Interface
	if err := s.Client.request(ctx, httpGET, "/diagnostics/interface/getInterfaceConfig", nil, &raw); err != nil {
		return domain.Snapshot{}, err
	}
	if len(raw) == 0 {
		return domain.Snapshot{}, fmt.Errorf("source %q returned no interfaces", s.ID)
	}
	stats := map[string]domain.Counters{}
	if s.Statistics {
		var err error
		if stats, err = s.counters(ctx); err != nil {
			return domain.Snapshot{}, err
		}
	}
	snap := domain.Snapshot{SourceID: s.ID, Interfaces: make([]domain.Interface, 0, len(raw))}
	for name, v := range raw {
		if v.Device == "" && v.Status == "" && v.Media == "" && v.MacAddr == "" && len(v.Ipv4) == 0 && len(v.Ipv6) == 0 {
			return domain.Snapshot{}, fmt.Errorf("interface config row %q has no recognized observations", name)
		}
		row := domain.Interface{Name: name, MAC: v.MacAddr, Addresses: []string{}, Counters: stats[name]}
		switch strings.ToLower(v.Status) {
		case "active", "up":
			up := true
			row.Up = &up
		case "no carrier", "down", "inactive":
			up := false
			row.Up = &up
		}
		row.SpeedMbps, row.Duplex = media(v.Media)
		for _, a := range v.Ipv4 {
			ip, err := netip.ParseAddr(a.IpAddr)
			if err != nil || !ip.Is4() || a.SubnetBits < 0 || a.SubnetBits > 32 {
				return domain.Snapshot{}, fmt.Errorf("invalid IPv4 observation on %q", name)
			}
			row.Addresses = append(row.Addresses, netip.PrefixFrom(ip, int(a.SubnetBits)).String())
		}
		for _, a := range v.Ipv6 {
			ip, err := netip.ParseAddr(a.IpAddr)
			if err != nil || !ip.Is6() || a.SubnetBits < 0 || a.SubnetBits > 128 {
				return domain.Snapshot{}, fmt.Errorf("invalid IPv6 observation on %q", name)
			}
			row.Addresses = append(row.Addresses, netip.PrefixFrom(ip, int(a.SubnetBits)).String())
		}
		snap.Interfaces = append(snap.Interfaces, row)
	}
	sort.Slice(snap.Interfaces, func(i, j int) bool { return snap.Interfaces[i].Name < snap.Interfaces[j].Name })
	if s.Assignments || len(s.GatewayMonitors) > 0 {
		s.collectInterfaceAssignments(ctx, &snap)
	}
	s.collectTelemetry(ctx, &snap)
	snap.ObservedAt = now()
	s.collectInventory(ctx, &snap)
	s.full, s.fullAt = snap, snap.ObservedAt
	s.full.Interfaces, s.full.Warnings = append([]domain.Interface{}, snap.Interfaces...), nil
	return snap, nil
}

func (s *Source) collectCounters(ctx context.Context, now func() time.Time) (domain.Snapshot, error) {
	stats, err := s.counters(ctx)
	if err != nil {
		return domain.Snapshot{}, err
	}
	snap := s.full
	snap.Interfaces = append([]domain.Interface{}, s.full.Interfaces...)
	for i := range snap.Interfaces {
		snap.Interfaces[i].Counters = stats[snap.Interfaces[i].Name]
	}
	snap.Warnings, snap.Gateways = nil, nil
	if len(s.GatewayMonitors) > 0 {
		gateways, err := s.gatewayStatus(ctx)
		if err != nil {
			snap.Warnings = append(snap.Warnings, "gateway_status_unavailable")
		} else {
			snap.Gateways = gateways
		}
	}
	snap.ObservedAt = now()
	return snap, nil
}

func (s *Source) counters(ctx context.Context) (map[string]domain.Counters, error) {
	var response struct {
		Statistics map[string]statRow `json:"statistics"`
	}
	if err := s.Client.request(ctx, httpGET, "/diagnostics/interface/getInterfaceStatistics", nil, &response); err != nil {
		return nil, err
	}
	if response.Statistics == nil {
		return nil, fmt.Errorf("interface statistics response omitted its table")
	}
	stats := map[string]domain.Counters{}
	for _, row := range response.Statistics {
		if row.Name == "" {
			return nil, fmt.Errorf("interface statistics row omitted its name")
		}
		old := stats[row.Name]
		stats[row.Name] = domain.Counters{RXBytes: counterMax(old.RXBytes, row.RXBytes), TXBytes: counterMax(old.TXBytes, row.TXBytes), RXPackets: counterMax(old.RXPackets, row.RXPackets), TXPackets: counterMax(old.TXPackets, row.TXPackets)}
	}
	return stats, nil
}

// counterMax coalesces netstat rows for multiple addresses of the same interface.
func counterMax(a, b *uint64) *uint64 {
	if a == nil {
		return b
	}
	if b == nil || *a >= *b {
		return a
	}
	return b
}

const httpGET = "GET"

// statRow follows the diagnostics interface-statistics endpoint's netstat fields.
type statRow struct {
	Name      string  `json:"name"`
	RXBytes   *uint64 `json:"received-bytes"`
	TXBytes   *uint64 `json:"sent-bytes"`
	RXPackets *uint64 `json:"received-packets"`
	TXPackets *uint64 `json:"sent-packets"`
}

func media(text string) (*int, string) {
	text = strings.ToLower(text)
	duplex := ""
	if strings.Contains(text, "full-duplex") {
		duplex = "full"
	}
	if strings.Contains(text, "half-duplex") {
		duplex = "half"
	}
	m := regexp.MustCompile(`(?:^|[^0-9.])([0-9]+(?:\.[0-9]+)?)([gm]?)base`).FindStringSubmatch(text)
	if len(m) == 0 {
		return nil, duplex
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return nil, duplex
	}
	if m[2] == "g" {
		v *= 1000
	}
	speed := int(v)
	if speed <= 0 {
		return nil, duplex
	}
	return &speed, duplex
}
