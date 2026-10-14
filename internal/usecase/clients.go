package usecase

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// ClientTracker maintains per-source observation history and expiry.
type ClientTracker struct {
	Entries []domain.Client
	TTL     time.Duration
}

// Apply merges current neighbors and leases with the source's known history.
func (t *ClientTracker) Apply(snap domain.Snapshot, bindings []domain.Binding) domain.Snapshot {
	now := snap.ObservedAt
	ttl := t.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	current := map[string]*domain.Client{}
	old := map[string]domain.Client{}
	for _, row := range t.Entries {
		old[row.Key] = row
	}
	macByIP := map[string]string{}
	for _, row := range snap.Neighbors {
		if row.MAC != "" && validIP(row.IP) {
			ip, _ := netip.ParseAddr(row.IP)
			macByIP[row.Interface+"/"+ip.String()] = CanonicalMAC(row.MAC)
		}
	}
	for _, lease := range snap.Leases {
		if lease.Active != nil && !*lease.Active || lease.ExpiresAt != nil && !lease.ExpiresAt.After(now) {
			continue
		}
		addr, err := netip.ParseAddr(lease.IP)
		if err != nil {
			continue
		}
		association := associateAddress(addr.String(), lease.Interface, snap, bindings)
		key := association.Interface + "/" + addr.String()
		if macByIP[key] == "" {
			macByIP[key] = CanonicalMAC(lease.MAC)
		}
	}
	find := func(ip, mac, iface string) *domain.Client {
		if !validIP(ip) {
			return nil
		}
		addr, _ := netip.ParseAddr(ip)
		ip = addr.String()
		mac = CanonicalMAC(mac)
		if mac == "" {
			mac = macByIP[iface+"/"+ip]
		}
		address := associateAddress(ip, iface, snap, bindings)
		if mac == "" {
			mac = macByIP[address.Interface+"/"+ip]
		}
		key := "mac/" + mac
		if mac == "" {
			key = "ip/" + iface + "/" + ip
		}
		row := current[key]
		if row == nil {
			first := now
			if previous, ok := old[key]; ok {
				first = previous.FirstSeen
			}
			if previous, ok := old["ip/"+address.Interface+"/"+ip]; ok && previous.FirstSeen.Before(first) {
				first = previous.FirstSeen
			}
			row = &domain.Client{Key: key, MAC: mac, FirstSeen: first, LastSeen: now, Presence: "lease_only", Addresses: []domain.ClientAddress{}}
			current[key] = row
		}
		found := false
		for _, a := range row.Addresses {
			if a.IP == ip && a.Interface == address.Interface {
				found = true
			}
		}
		if !found {
			row.Addresses = append(row.Addresses, address)
		}
		return row
	}
	for _, observation := range snap.Neighbors {
		self := false
		ip, err := netip.ParseAddr(observation.IP)
		if err == nil {
			for _, iface := range snap.Interfaces {
				for _, address := range iface.Addresses {
					p, err := netip.ParsePrefix(address)
					if err == nil && p.Addr() == ip.WithZone("") {
						self = true
					}
				}
			}
		}
		if self {
			continue
		}
		row := find(observation.IP, observation.MAC, observation.Interface)
		if row == nil {
			continue
		}
		row.Presence = "observed"
		row.Incomplete = observation.Incomplete || row.MAC == ""
		if observation.Hostname != "" {
			row.Hostname = observation.Hostname
		}
		if observation.Manufacturer != "" {
			row.Manufacturer = observation.Manufacturer
		}
	}
	for _, lease := range snap.Leases {
		if lease.Active != nil && !*lease.Active || lease.ExpiresAt != nil && !lease.ExpiresAt.After(now) {
			continue
		}
		row := find(lease.IP, lease.MAC, lease.Interface)
		if row == nil {
			continue
		}
		row.Leases = append(row.Leases, lease)
		if lease.Hostname != "" {
			row.Hostname = lease.Hostname
		}
	}
	for key, previous := range old {
		if _, seen := current[key]; seen {
			continue
		}
		if now.Sub(previous.LastSeen) > ttl {
			continue
		}
		resolved := false
		if previous.MAC == "" {
			for _, address := range previous.Addresses {
				if macByIP[address.Interface+"/"+address.IP] != "" {
					resolved = true
				}
			}
		}
		if resolved {
			continue
		}
		previous.Presence = "unknown"
		if snap.NeighborsComplete && snap.LeasesComplete {
			previous.Presence = "absent"
		}
		previous.Traffic = nil
		current[key] = &previous
	}
	clients := make([]domain.Client, 0, len(current))
	owners := map[string]map[string]bool{}
	trafficByIP := map[string]domain.ClientTraffic{}
	points := map[string]bool{}
	for _, traffic := range snap.Traffic {
		key := traffic.Interface + "/" + traffic.IP
		trafficByIP[key] = traffic
		points[traffic.Interface] = true
	}
	for _, row := range current {
		if row.MAC == "" || (row.Presence != "observed" && row.Presence != "lease_only") {
			continue
		}
		for _, address := range row.Addresses {
			for point := range points {
				if !observationPoint(point, address.Interface, snap.VLANs) {
					continue
				}
				key := point + "/" + strings.Split(address.IP, "%")[0]
				if owners[key] == nil {
					owners[key] = map[string]bool{}
				}
				owners[key][row.Key+"/"+address.Interface] = true
			}
		}
	}
	for _, row := range current {
		attached := map[string]bool{}
		if row.MAC != "" && (row.Presence == "observed" || row.Presence == "lease_only") {
			for _, address := range row.Addresses {
				for point := range points {
					key := point + "/" + strings.Split(address.IP, "%")[0]
					if attached[key] || len(owners[key]) != 1 || !observationPoint(point, address.Interface, snap.VLANs) {
						continue
					}
					if traffic, ok := trafficByIP[key]; ok {
						row.Traffic = append(row.Traffic, traffic)
						attached[key] = true
					}
				}
			}
		}
		sort.Slice(row.Traffic, func(i, j int) bool {
			a, b := row.Traffic[i], row.Traffic[j]
			if a.Interface != b.Interface {
				return a.Interface < b.Interface
			}
			return a.IP < b.IP
		})
		sort.Slice(row.Addresses, func(i, j int) bool {
			a, b := row.Addresses[i], row.Addresses[j]
			if a.Interface != b.Interface {
				return a.Interface < b.Interface
			}
			return a.IP < b.IP
		})
		clients = append(clients, *row)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Key < clients[j].Key })
	if len(clients) > 16384 {
		clients = clients[:16384]
		snap.Warnings = append(snap.Warnings, "client_history_limit")
	}
	t.Entries = clients
	snap.Clients = clients
	return snap
}

func observationPoint(point, iface string, vlans []domain.VLAN) bool {
	for depth := 0; depth < 16; depth++ {
		if point == iface {
			return true
		}
		found := false
		for _, vlan := range vlans {
			if vlan.Interface == iface {
				iface = vlan.Parent
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return false
}

func validIP(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && !addr.IsMulticast() && !addr.IsUnspecified()
}

func associateAddress(ip, iface string, snap domain.Snapshot, bindings []domain.Binding) domain.ClientAddress {
	address := domain.ClientAddress{IP: ip, Interface: iface}
	if iface == "" {
		addr, _ := netip.ParseAddr(ip)
		for _, row := range snap.Interfaces {
			for _, cidr := range row.Addresses {
				p, err := netip.ParsePrefix(cidr)
				if err == nil && p.Contains(addr.WithZone("")) {
					if address.Interface != "" && address.Interface != row.Name {
						address.Interface = ""
						return address
					}
					address.Interface = row.Name
				}
			}
		}
	}
	parent := address.Interface
	for _, vlan := range snap.VLANs {
		if vlan.Interface == address.Interface {
			address.VLAN, address.Network = vlan.Tag, vlan.Name
			break
		}
	}
	visited := map[string]bool{}
	for depth := 0; depth < 16; depth++ {
		if visited[parent] {
			return address
		}
		visited[parent] = true
		for _, binding := range bindings {
			if binding.Interface == parent {
				address.Port, address.Role = binding.Port, binding.Role
				return address
			}
		}
		found := false
		for _, vlan := range snap.VLANs {
			if vlan.Interface == parent {
				if address.VLAN == 0 {
					address.VLAN, address.Network = vlan.Tag, vlan.Name
				}
				parent = vlan.Parent
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return address
}

// CanonicalMAC normalizes a complete unicast Ethernet address.
func CanonicalMAC(value string) string {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return ""
	}
	return mac.String()
}
