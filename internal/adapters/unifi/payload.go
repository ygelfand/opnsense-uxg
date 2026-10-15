package unifi

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jamesbraid/unifi-emu/inform"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

const gatewayFirmwareVersion = "5.1.26.33914"

type interfaceRow struct {
	Name          string `json:"name"`
	Comment       string `json:"comment"`
	MAC           string `json:"mac,omitempty"`
	IP            string `json:"ip,omitempty"`
	Netmask       string `json:"netmask,omitempty"`
	NumPort       int    `json:"num_port"`
	PhysicalPorts []int  `json:"physical_ports"`
	Up            *bool  `json:"up,omitempty"`
	Speed         *int   `json:"speed,omitempty"`
	RXRate        *int64 `json:"rx_bytes-r,omitempty"`
	TXRate        *int64 `json:"tx_bytes-r,omitempty"`
	WANConnected  *bool  `json:"isWanConnected,omitempty"`
	WANUp         *bool  `json:"isWanUp,omitempty"`
	Latency       *int   `json:"latency,omitempty"`
	domain.Counters
}

type networkRow struct {
	Name             string        `json:"name"`
	IfName           string        `json:"ifname,omitempty"`
	NetworkGroup     string        `json:"networkgroup,omitempty"`
	PortIdx          int           `json:"port_idx,omitempty"`
	Stats            *networkStats `json:"stats,omitempty"`
	Address          string        `json:"address,omitempty"`
	Addresses        []string      `json:"addresses"`
	MAC              string        `json:"mac,omitempty"`
	Up               *bool         `json:"up,omitempty"`
	Speed            string        `json:"speed,omitempty"`
	Duplex           string        `json:"duplex,omitempty"`
	WANConnected     *bool         `json:"isWanConnected,omitempty"`
	WANUp            *bool         `json:"isWanUp,omitempty"`
	Latency          *int          `json:"latency,omitempty"`
	HostTable        []hostRow     `json:"host_table,omitempty"`
	ActiveDHCPLeases *int          `json:"active_dhcp_lease_count,omitempty"`
}

type networkStats struct {
	domain.Counters
	RXRate    *int64 `json:"rx_bytes-r,omitempty"`
	TXRate    *int64 `json:"tx_bytes-r,omitempty"`
	RXBitRate *int64 `json:"rx_rate,omitempty"`
	TXBitRate *int64 `json:"tx_rate,omitempty"`
}

type hostRow struct {
	MAC      string   `json:"mac"`
	IP       string   `json:"ip,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	VLAN     int      `json:"vlan,omitempty"`
	Static   bool     `json:"static,omitempty"`
	RXRate   *int64   `json:"rx_bytes-r,omitempty"`
	TXRate   *int64   `json:"tx_bytes-r,omitempty"`
	IPv6     []string `json:"ipv6,omitempty"`
}

// Render projects mapped observed interfaces into the captured UXG table shapes.
// Missing mapped interfaces fail the cycle so a disappearing NIC stays visible.
func Render(id domain.Identity, bindings []domain.Binding, uplinkInterface string, snap domain.Snapshot, adoption domain.Adoption, informURL string, uptime, minInterval time.Duration) ([]byte, error) {
	if snap.SourceID != id.ID {
		return nil, fmt.Errorf("snapshot belongs to another source")
	}
	interfaces := make(map[string]domain.Interface, len(snap.Interfaces))
	for _, row := range snap.Interfaces {
		interfaces[row.Name] = row
	}
	ordered := append([]domain.Binding{}, bindings...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Port < ordered[j].Port })
	ifs := make([]interfaceRow, 0, len(ordered))
	ports := make([]map[string]any, 0, len(ordered))
	assignments := make([]map[string]any, 0, len(ordered))
	nets := make([]networkRow, 0, len(ordered))
	monitors := make(map[string]domain.GatewayMonitor, len(snap.Gateways))
	for _, monitor := range snap.Gateways {
		monitors[monitor.Role] = monitor
	}
	wanStatus := map[string]string{}
	for _, binding := range ordered {
		observed, ok := interfaces[binding.Interface]
		if !ok {
			return nil, fmt.Errorf("mapped interface %q missing", binding.Interface)
		}
		name := "eth" + strconv.Itoa(binding.Port-1)
		row := interfaceRow{Name: name, Comment: strings.ToUpper(binding.Role), MAC: observed.MAC, NumPort: 1, PhysicalPorts: []int{binding.Port}, Up: observed.Up, Speed: observed.SpeedMbps, Counters: observed.Counters}
		row.RXRate, row.TXRate = wireRate(observed.Rates.RXBytesPerSecond), wireRate(observed.Rates.TXBytesPerSecond)
		network := networkRow{Name: name, IfName: name, NetworkGroup: strings.ToUpper(binding.Role), PortIdx: binding.Port, Addresses: gatewayAddressesFirst(binding.Interface, observed.Addresses, snap.CARP), MAC: observed.MAC, Up: observed.Up, Duplex: observed.Duplex}
		network.Stats = measuredNetworkStats(observed)
		if monitor, ok := monitors[binding.Role]; ok {
			row.WANUp, row.WANConnected = observed.Up, monitor.Connected
			network.WANUp, network.WANConnected = observed.Up, monitor.Connected
			if monitor.LatencyMS != nil {
				value := int(*monitor.LatencyMS + 0.5)
				row.Latency, network.Latency = &value, &value
			}
			if monitor.Connected != nil {
				status := "offline"
				if *monitor.Connected {
					status = "online"
				}
				wanStatus[strings.ToUpper(binding.Role)] = status
			}
		}
		if observed.SpeedMbps != nil {
			network.Speed = strconv.Itoa(*observed.SpeedMbps)
		}
		for _, addr := range observed.Addresses {
			p, err := netip.ParsePrefix(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid observed address on %q", binding.Interface)
			}
			if p.Addr().Is4() && row.IP == "" {
				row.IP = p.Addr().String()
				row.Netmask = net.IP(net.CIDRMask(p.Bits(), 32)).String()
			}
		}
		for _, addr := range network.Addresses {
			if p, err := netip.ParsePrefix(addr); err == nil && p.Addr().Is4() {
				network.Address = addr
				break
			}
		}
		ifs, nets = append(ifs, row), append(nets, network)
		port := map[string]any{"port_idx": binding.Port, "name": name, "ifname": name, "networkgroup": strings.ToUpper(binding.Role), "network_name": strings.ToUpper(binding.Role), "type": "wire"}
		if media := portMedia(id.Model, binding.Port); media != "" {
			port["media"] = media
		}
		if observed.MAC != "" {
			port["mac"] = observed.MAC
		}
		if observed.Up != nil {
			port["up"] = *observed.Up
		}
		if observed.SpeedMbps != nil {
			port["speed"] = *observed.SpeedMbps
		}
		if observed.Duplex != "" {
			port["full_duplex"] = observed.Duplex == "full"
		}
		if observed.Counters.RXBytes != nil {
			port["rx_bytes"] = *observed.Counters.RXBytes
		}
		if observed.Counters.TXBytes != nil {
			port["tx_bytes"] = *observed.Counters.TXBytes
		}
		if observed.Counters.RXPackets != nil {
			port["rx_packets"] = *observed.Counters.RXPackets
		}
		if observed.Counters.TXPackets != nil {
			port["tx_packets"] = *observed.Counters.TXPackets
		}
		if row.RXRate != nil {
			port["rx_bytes-r"] = *row.RXRate
		}
		if row.TXRate != nil {
			port["tx_bytes-r"] = *row.TXRate
		}
		if rate := bitRate(observed.Rates.RXBytesPerSecond); rate != nil {
			port["rx_rate"] = *rate
		}
		if rate := bitRate(observed.Rates.TXBytesPerSecond); rate != nil {
			port["tx_rate"] = *rate
		}
		ports = append(ports, port)
		assignment := map[string]any{"ifname": name, "port_idx": binding.Port, "networkgroup": strings.ToUpper(binding.Role), "role": binding.Role}
		if observed.AdminEnabled != nil {
			assignment["enable"] = *observed.AdminEnabled
			port["enable"] = *observed.AdminEnabled
		}
		assignments = append(assignments, assignment)
	}
	nets = clientNetworks(nets, snap, ordered)
	leases, leaseIPs := []map[string]any{}, []netip.Addr{}
	for _, client := range snap.Clients {
		if client.MAC == "" {
			continue
		}
		for _, lease := range client.Leases {
			ip, err := netip.ParseAddr(lease.IP)
			if err != nil || !ip.Is4() {
				continue
			}
			row := map[string]any{"mac": client.MAC, "ip": ip.String(), "hostname": lease.Hostname, "static": lease.Reserved}
			if lease.ExpiresAt != nil {
				row["leaseExpiry"] = lease.ExpiresAt.Unix()
			}
			leases, leaseIPs = append(leases, row), append(leaseIPs, ip)
		}
	}
	if snap.LeasesComplete {
		for i := range nets {
			count := 0
			for _, ip := range leaseIPs {
				for _, address := range nets[i].Addresses {
					if prefix, err := netip.ParsePrefix(address); err == nil && prefix.Masked().Contains(ip) {
						count++
						break
					}
				}
			}
			nets[i].ActiveDHCPLeases = &count
		}
	}
	adopted := adoption.AuthKey != ""
	state := 1
	if adopted {
		state = 2
	}
	count, display := 2, "UniFi Gateway Lite"
	if id.Model == "UXGPRO" {
		count, display = 4, "UniFi Next-Generation Gateway Pro"
	}
	if id.Model == "UXGENT" {
		count, display = 6, "Gateway Enterprise"
	}
	mac, err := net.ParseMAC(id.MAC)
	if err != nil {
		return nil, err
	}
	cfgVersion := adoption.CFGVersion
	if cfgVersion == "" {
		cfgVersion = "0"
	}
	key := adoption.AuthKey
	if key == "" {
		key = inform.DefaultKey
	}
	root := map[string]any{
		"mac": mac.String(), "serial": strings.ToUpper(strings.ReplaceAll(mac.String(), ":", "")),
		"hostname": id.Hostname, "model": id.Model, "model_display": display,
		"type": "uxg", "version": gatewayFirmwareVersion, "ip": id.ManagementIP,
		"default": !adopted, "adopted": adopted, "state": state, "num_port": count,
		"cfgversion": cfgVersion, "inform_url": informURL,
		"x_authkey": key, "_default_key": key == inform.DefaultKey,
		"uptime": max(1, int(uptime.Seconds())), "time": snap.ObservedAt.Unix(), "time_ms": snap.ObservedAt.UnixMilli(),
		"if_table": ifs, "network_table": nets, "port_table": ports,
		"ethernet_overrides": assignments, "config_port_table": assignments,
		"udapi_version": map[string]any{"version": 48},
		"udapi_caps":    0,
		"gw_caps":       map[string]any{},
	}
	if uplinkInterface != "" {
		uplink, role := logicalInterfaceRole(uplinkInterface, bindings, snap.VLANs)
		if uplink == "" || role != "lan" && role != "lan2" {
			return nil, fmt.Errorf("uplink interface %q is not mapped to a bound LAN interface", uplinkInterface)
		}
		root["uplink"] = uplink
	}
	if snap.System.UptimeSeconds != nil {
		root["uptime"] = *snap.System.UptimeSeconds
	}
	if minInterval > 0 {
		root["inform_min_interval"] = int(minInterval / time.Second)
	}
	if id.Model == "UXGENT" {
		root["udapi_version"] = map[string]any{"version": "2.0.0"}
	}
	caps := 0
	if minInterval > 0 {
		caps |= 16
	}
	if id.Model == "UXGENT" && snap.HA != nil {
		caps |= 1073741824
		vrrp := map[string]any{"state": snap.HA.CARPState}
		if snap.HA.ObservedTransitionAt != nil {
			vrrp["lastTransition"] = snap.HA.ObservedTransitionAt.UnixMilli()
		}
		root["vrrp"] = vrrp
	}
	if caps != 0 {
		root["usg2_caps"] = caps
	}
	addSystemStats(root, snap.System)
	if snap.LeasesComplete && len(snap.Leases) > 0 {
		root["ipv4_active_leases"] = leases
	}
	if len(wanStatus) > 0 {
		root["last_wan_status"] = wanStatus
	}
	addWANReports(root, ordered, snap)
	return json.Marshal(root)
}

func measuredNetworkStats(observed domain.Interface) *networkStats {
	stats := networkStats{Counters: observed.Counters, RXRate: wireRate(observed.Rates.RXBytesPerSecond), TXRate: wireRate(observed.Rates.TXBytesPerSecond), RXBitRate: bitRate(observed.Rates.RXBytesPerSecond), TXBitRate: bitRate(observed.Rates.TXBytesPerSecond)}
	if stats.RXBytes == nil && stats.TXBytes == nil && stats.RXPackets == nil && stats.TXPackets == nil && stats.RXRate == nil && stats.TXRate == nil {
		return nil
	}
	return &stats
}

func clientNetworks(rows []networkRow, snap domain.Snapshot, bindings []domain.Binding) []networkRow {
	indices := map[string]int{}
	for i, row := range rows {
		indices[row.Name] = i
	}
	for _, vlan := range snap.VLANs {
		name := logicalInterface(vlan.Interface, bindings, snap.VLANs)
		if name == "" {
			continue
		}
		if _, exists := indices[name]; exists {
			continue
		}
		row := networkRow{Name: name, Addresses: []string{}}
		for _, iface := range snap.Interfaces {
			if iface.Name == vlan.Interface {
				row.Addresses = gatewayAddressesFirst(iface.Name, iface.Addresses, snap.CARP)
				row.MAC, row.Up, row.Duplex = iface.MAC, iface.Up, iface.Duplex
				if len(row.Addresses) > 0 {
					row.Address = row.Addresses[0]
				}
			}
		}
		indices[name] = len(rows)
		rows = append(rows, row)
	}
	for _, client := range snap.Clients {
		if client.Presence != "observed" || client.Incomplete || client.MAC == "" {
			continue
		}
		seen := map[string]int{}
		for _, address := range client.Addresses {
			if address.Port == 0 || (address.Role != "lan" && address.Role != "lan2") {
				continue
			}
			name := logicalInterface(address.Interface, bindings, snap.VLANs)
			if name == "" {
				continue
			}
			index, ok := indices[name]
			if !ok {
				row := networkRow{Name: name, Addresses: []string{}}
				for _, iface := range snap.Interfaces {
					if iface.Name == address.Interface {
						row.Addresses = gatewayAddressesFirst(iface.Name, iface.Addresses, snap.CARP)
						row.MAC, row.Up = iface.MAC, iface.Up
						if len(row.Addresses) > 0 {
							row.Address = row.Addresses[0]
						}
					}
				}
				index = len(rows)
				indices[name] = index
				rows = append(rows, row)
			}
			if existing, ok := seen[name]; ok {
				host := &rows[index].HostTable[existing]
				ip, err := netip.ParseAddr(address.IP)
				if err == nil {
					if ip.Is4() && host.IP == "" {
						host.IP = ip.String()
					}
					if ip.Is6() {
						host.IPv6 = append(host.IPv6, ip.String())
					}
				}
				continue
			}
			seen[name] = len(rows[index].HostTable)
			host := hostRow{MAC: client.MAC, Hostname: client.Hostname, VLAN: address.VLAN}
			ip, err := netip.ParseAddr(address.IP)
			if err == nil {
				if ip.Is4() {
					host.IP = ip.String()
				} else {
					host.IPv6 = []string{ip.String()}
				}
			}
			for _, lease := range client.Leases {
				if lease.IP == address.IP && lease.Reserved {
					host.Static = true
				}
			}
			for _, traffic := range client.Traffic {
				if traffic.IP != strings.Split(address.IP, "%")[0] {
					continue
				}
				seconds := traffic.To.Sub(traffic.From).Seconds()
				if seconds <= 0 {
					continue
				}
				if traffic.RXBytes != nil {
					v := float64(*traffic.RXBytes) / seconds
					host.RXRate = wireRate(&v)
				}
				if traffic.TXBytes != nil {
					v := float64(*traffic.TXBytes) / seconds
					host.TXRate = wireRate(&v)
				}
			}
			rows[index].HostTable = append(rows[index].HostTable, host)
		}
	}
	return rows
}

func logicalInterface(iface string, bindings []domain.Binding, vlans []domain.VLAN) string {
	name, _ := logicalInterfaceRole(iface, bindings, vlans)
	return name
}

func logicalInterfaceRole(iface string, bindings []domain.Binding, vlans []domain.VLAN) (string, string) {
	var tags []int
	visited := map[string]bool{}
	for depth := 0; depth < 16; depth++ {
		if visited[iface] {
			return "", ""
		}
		visited[iface] = true
		for _, binding := range bindings {
			if binding.Interface == iface {
				name := "eth" + strconv.Itoa(binding.Port-1)
				for i := len(tags) - 1; i >= 0; i-- {
					name += "." + strconv.Itoa(tags[i])
				}
				return name, binding.Role
			}
		}
		found := false
		for _, vlan := range vlans {
			if vlan.Interface == iface {
				tags = append(tags, vlan.Tag)
				iface = vlan.Parent
				found = true
				break
			}
		}
		if !found {
			return "", ""
		}
	}
	return "", ""
}

func wireRate(value *float64) *int64 {
	if value == nil || math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value >= float64(math.MaxInt64) {
		return nil
	}
	v := int64(*value)
	return &v
}

func gatewayAddressesFirst(iface string, addresses []string, carp []domain.CARPObservation) []string {
	out := append([]string{}, addresses...)
	vips := map[netip.Addr]bool{}
	for _, observation := range carp {
		if addr, err := netip.ParseAddr(observation.Address); err == nil && observation.Interface == iface {
			vips[addr] = true
		}
	}
	isVIP := func(address string) bool {
		prefix, err := netip.ParsePrefix(address)
		return err == nil && vips[prefix.Addr()]
	}
	sort.SliceStable(out, func(i, j int) bool { return isVIP(out[i]) && !isVIP(out[j]) })
	return out
}

// portMedia follows the 10.6.106 uidb link speeds for each model's physical ports.
func portMedia(model string, port int) string {
	media := map[string][]string{
		"UXG":    {"GE", "GE"},
		"UXGPRO": {"GE", "GE", "SFP+", "SFP+"},
		"UXGENT": {"2P5GE", "2P5GE", "SFP+", "SFP+", "SFP28", "SFP28"},
	}[model]
	if port < 1 || port > len(media) {
		return ""
	}
	return media[port-1]
}

func bitRate(bytesPerSecond *float64) *int64 {
	if bytesPerSecond == nil {
		return nil
	}
	bits := *bytesPerSecond * 8
	return wireRate(&bits)
}

func addSystemStats(root map[string]any, system domain.System) {
	stats, usage := map[string]any{}, map[string]any{}
	if system.UptimeSeconds != nil {
		stats["uptime"], usage["uptime"] = *system.UptimeSeconds, strconv.FormatInt(*system.UptimeSeconds, 10)
	}
	if len(system.LoadAverage) == 3 {
		stats["loadavg_1"], stats["loadavg_5"], stats["loadavg_15"] = system.LoadAverage[0], system.LoadAverage[1], system.LoadAverage[2]
	}
	if system.CPUPercent != nil {
		usage["cpu"] = strconv.FormatFloat(*system.CPUPercent, 'f', 1, 64)
		stats["cpu"] = *system.CPUPercent
	}
	if system.MemoryTotalBytes != nil && system.MemoryUsedBytes != nil && *system.MemoryTotalBytes > 0 {
		stats["mem_total"], stats["mem_used"] = *system.MemoryTotalBytes, *system.MemoryUsedBytes
		percent := 100 * float64(*system.MemoryUsedBytes) / float64(*system.MemoryTotalBytes)
		usage["mem"], stats["mem"] = strconv.FormatFloat(percent, 'f', 1, 64), strconv.FormatFloat(percent, 'f', 1, 64)
	}
	if len(stats) > 0 {
		root["sys_stats"] = stats
	}
	if len(usage) > 0 {
		root["system-stats"] = usage
	}
}
