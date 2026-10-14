package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/browningluke/opnsense-go/pkg/api"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

func (s *Source) collectInventory(ctx context.Context, snap *domain.Snapshot) {
	snap.NeighborsComplete = !s.Neighbors
	if s.Neighbors {
		arp, err := s.Client.sdk.Diagnostics().InterfaceGetARP(ctx, nil)
		arpOK := err == nil && arp != nil
		if !arpOK {
			snap.Warnings = append(snap.Warnings, "arp_unavailable")
		} else {
			for _, row := range *arp {
				snap.Neighbors = append(snap.Neighbors, neighbor(row.IP, row.MAC, row.Interface, row.Hostname, row.Manufacturer))
			}
		}
		ndp, err := s.Client.sdk.Diagnostics().InterfaceGetNDP(ctx)
		ndpOK := err == nil && ndp != nil
		if !ndpOK {
			snap.Warnings = append(snap.Warnings, "ndp_unavailable")
		} else {
			for _, row := range *ndp {
				snap.Neighbors = append(snap.Neighbors, neighbor(row.IP, row.MAC, row.Interface, "", row.Manufacturer))
			}
		}
		snap.NeighborsComplete = arpOK && ndpOK
	}
	if s.VLANs {
		vlans, err := s.Client.VLANs(ctx)
		if err != nil {
			snap.Warnings = append(snap.Warnings, "vlans_unavailable")
		} else {
			snap.VLANs = vlans
		}
	}
	snap.LeasesComplete = true
	for _, backend := range s.DHCPBackends {
		leases, err := s.Client.Leases(ctx, backend)
		if err != nil {
			snap.LeasesComplete = false
			snap.Warnings = append(snap.Warnings, backend+"_leases_unavailable")
		} else {
			snap.Leases = append(snap.Leases, leases...)
		}
	}
	if s.Accounting.Enabled {
		err := validateObservationPoints(s.Accounting.Interfaces, snap.Interfaces, snap.VLANs)
		if err != nil {
			snap.Warnings = append(snap.Warnings, "flow_accounting_unavailable")
		} else {
			from, to := accountingWindow(s.Accounting, snap.ObservedAt)
			s.accountingMu.Lock()
			if !to.Equal(s.accountingTo) {
				traffic, queryErr := s.Client.FlowTraffic(ctx, s.Accounting, to)
				if queryErr != nil {
					snap.Warnings = append(snap.Warnings, "flow_accounting_unavailable")
				} else {
					s.accountingTo = to
					s.accountingData = append([]domain.ClientTraffic{}, traffic...)
					snap.TrafficFresh = true
				}
			}
			snap.Traffic = append([]domain.ClientTraffic{}, s.accountingData...)
			s.accountingMu.Unlock()
			for i := range snap.Traffic {
				snap.Traffic[i].From = from
				snap.Traffic[i].To = to
			}
		}
	}
}

func accountingWindow(cfg AccountingOptions, now time.Time) (time.Time, time.Time) {
	window := cfg.Window
	if window <= 0 {
		window = 5 * time.Minute
	}
	to := now.UTC().Truncate(window)
	return to.Add(-window), to
}

func neighbor(ip, mac, iface, hostname, manufacturer string) domain.Neighbor {
	row := domain.Neighbor{IP: ip, Interface: iface, Hostname: hostname, Manufacturer: manufacturer}
	parsed, err := net.ParseMAC(mac)
	if err == nil && len(parsed) == 6 && parsed[0]&1 == 0 && parsed.String() != "00:00:00:00:00:00" {
		row.MAC = parsed.String()
	} else {
		row.Incomplete = true
	}
	return row
}

// Leases returns a complete DHCP table from one explicitly selected backend.
func (c *Client) Leases(ctx context.Context, backend string) ([]domain.Lease, error) {
	all, page := "-1", "1"
	rows := []domain.Lease{}
	var count *api.Int64
	switch backend {
	case "kea4", "kea6":
		search := c.sdk.Kea().LeasesSearchV4
		if backend == "kea6" {
			search = c.sdk.Kea().LeasesSearchV6
		}
		result, err := search(ctx, &all, &page)
		if err != nil {
			return nil, err
		}
		if result == nil || result.Rows == nil {
			return nil, fmt.Errorf("lease response omitted rows")
		}
		count = result.Total
		for _, row := range result.Rows {
			lease := leaseRow(row.Address, row.MAC, row.Interface, row.Hostname, backend, row.Expires, row.LeaseType)
			if row.State != nil {
				active := *row.State == 0
				lease.Active = &active
			}
			rows = append(rows, lease)
		}
	case "dnsmasq":
		result, err := c.sdk.Dnsmasq().LeasesSearch(ctx, &all, &page)
		if err != nil {
			return nil, err
		}
		if result == nil || result.Rows == nil {
			return nil, fmt.Errorf("lease response omitted rows")
		}
		count = result.Total
		for _, row := range result.Rows {
			rows = append(rows, leaseRow(row.Address, row.MAC, row.Interface, row.Hostname, backend, row.Expires, row.LeaseType))
		}
	default:
		return nil, fmt.Errorf("unsupported DHCP backend")
	}
	if count == nil || int64(*count) != int64(len(rows)) {
		return nil, fmt.Errorf("lease inventory is incomplete")
	}
	return rows, nil
}

func leaseRow(ip, mac, iface, hostname, backend string, expires *api.Int64, kind string) domain.Lease {
	if hostname == "*" {
		hostname = ""
	}
	lease := domain.Lease{IP: ip, MAC: neighbor(ip, mac, iface, "", "").MAC, Interface: iface, Hostname: hostname, Backend: backend, Reserved: kind == "static"}
	if expires != nil && *expires > 0 {
		value := time.Unix(int64(*expires), 0).UTC()
		lease.ExpiresAt = &value
	}
	return lease
}

// VLANs reads UUIDs then typed configuration to preserve actual parent identities.
func (c *Client) VLANs(ctx context.Context) ([]domain.VLAN, error) {
	var result struct {
		Total *int `json:"total"`
		Rows  []struct {
			UUID string `json:"uuid"`
		} `json:"rows"`
	}
	if err := c.request(ctx, httpGET, "/interfaces/vlan_settings/searchItem?rowCount=-1", nil, &result); err != nil {
		return nil, err
	}
	if result.Total == nil || result.Rows == nil || len(result.Rows) != *result.Total || len(result.Rows) > 4094 {
		return nil, fmt.Errorf("VLAN inventory is incomplete")
	}
	vlans := make([]domain.VLAN, 0, len(result.Rows))
	for _, row := range result.Rows {
		if !safeID(row.UUID) {
			return nil, fmt.Errorf("invalid VLAN UUID")
		}
		v, err := c.sdk.Interfaces().GetVlan(ctx, row.UUID)
		if err != nil {
			return nil, err
		}
		tag, err := strconv.Atoi(v.Tag)
		if err != nil || tag < 1 || tag > 4094 || v.Device == "" || string(v.Parent) == "" {
			return nil, fmt.Errorf("invalid VLAN configuration")
		}
		vlans = append(vlans, domain.VLAN{UUID: row.UUID, Interface: v.Device, Parent: string(v.Parent), Tag: tag, Name: v.Description})
	}
	return vlans, nil
}

func safeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
		if !valid {
			return false
		}
	}
	return true
}

func queryEscape(value string) string { return url.QueryEscape(value) }

type flowTotals struct {
	rx float64
	tx float64
}

// FlowTraffic queries one observation point per interface, retaining window totals.
func (c *Client) FlowTraffic(ctx context.Context, cfg AccountingOptions, now time.Time) ([]domain.ClientTraffic, error) {
	from, to := accountingWindow(cfg, now)
	out := []domain.ClientTraffic{}
	for _, iface := range cfg.Interfaces {
		path := "/diagnostics/networkinsight/top/FlowSourceAddrDetails/" + strconv.FormatInt(from.Unix(), 10) + "/" + strconv.FormatInt(to.Unix(), 10) + "/src_addr,dst_addr/octets/" + strconv.Itoa(cfg.MaxRows) + "/?filter_field=if&filter_value=" + queryEscape(iface)
		var rows []struct {
			Source      string          `json:"src_addr"`
			Destination string          `json:"dst_addr"`
			Octets      json.RawMessage `json:"total"`
		}
		if err := c.request(ctx, httpGET, path, nil, &rows); err != nil {
			return nil, err
		}
		if rows == nil || len(rows) >= cfg.MaxRows {
			return nil, fmt.Errorf("flow query is unavailable or truncated")
		}
		traffic := map[string]*flowTotals{}
		add := func(ip string, value float64, rx bool) error {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return fmt.Errorf("flow query returned invalid address")
			}
			ip = addr.String()
			v := traffic[ip]
			if v == nil {
				v = &flowTotals{}
				traffic[ip] = v
			}
			counter := &v.tx
			if rx {
				counter = &v.rx
			}
			if value < 0 || math.IsInf(*counter+value, 0) || *counter+value >= math.Ldexp(1, 64) {
				return fmt.Errorf("flow counter overflow")
			}
			*counter += value
			return nil
		}
		for _, row := range rows {
			value, err := parseFlowOctets(row.Octets)
			if err != nil {
				return nil, err
			}
			if err := add(row.Source, value, false); err != nil {
				return nil, err
			}
			if err := add(row.Destination, value, true); err != nil {
				return nil, err
			}
		}
		for ip, totals := range traffic {
			rx, err := roundedFlowOctets(totals.rx)
			if err != nil {
				return nil, err
			}
			tx, err := roundedFlowOctets(totals.tx)
			if err != nil {
				return nil, err
			}
			out = append(out, domain.ClientTraffic{
				IP: ip, Interface: iface, From: from, To: to,
				Attribution: "current_ip_association", RXBytes: &rx, TXBytes: &tx,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		return a.IP < b.IP
	})
	return out, nil
}

func parseFlowOctets(raw json.RawMessage) (float64, error) {
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		var text string
		if string(raw) == "null" || json.Unmarshal(raw, &text) != nil {
			return 0, fmt.Errorf("flow query omitted octets")
		}
		number = json.Number(text)
	}
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, fmt.Errorf("flow query returned invalid octets")
	}
	return value, nil
}

func roundedFlowOctets(value float64) (uint64, error) {
	rounded := math.Round(value)
	if math.IsNaN(rounded) || math.IsInf(rounded, 0) || rounded < 0 || rounded >= math.Ldexp(1, 64) {
		return 0, fmt.Errorf("flow counter overflow")
	}
	return uint64(rounded), nil
}

func validateObservationPoints(points []string, interfaces []domain.Interface, vlans []domain.VLAN) error {
	known, selected := map[string]bool{}, map[string]bool{}
	for _, iface := range interfaces {
		known[iface.Name] = true
	}
	parents := map[string]string{}
	for _, vlan := range vlans {
		parents[vlan.Interface] = vlan.Parent
	}
	for _, point := range points {
		if !known[point] || selected[point] {
			return fmt.Errorf("invalid or duplicate flow observation point")
		}
		selected[point] = true
	}
	for _, point := range points {
		parent := parents[point]
		for depth := 0; depth < 16 && parent != ""; depth++ {
			if selected[parent] {
				return fmt.Errorf("overlapping flow observation points")
			}
			parent = parents[parent]
		}
	}
	return nil
}
