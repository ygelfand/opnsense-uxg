package unifi

import (
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// addWANReports supplies dedicated gateway blocks in addition to interface rows.
// Field names follow the gateway reference; values come only from observations.
func addWANReports(root map[string]any, bindings []domain.Binding, snap domain.Snapshot) {
	wans := []map[string]any{}
	uplinks := []map[string]any{}
	health := map[string]any{}
	for _, binding := range bindings {
		if binding.Role != "wan" && binding.Role != "wan2" {
			continue
		}
		var observed domain.Interface
		for _, iface := range snap.Interfaces {
			if iface.Name == binding.Interface {
				observed = iface
				break
			}
		}
		name := "eth" + strconv.Itoa(binding.Port-1)
		group := strings.ToUpper(binding.Role)
		row := map[string]any{"name": group, "ifname": name, "uplink_ifname": name, "port_idx": binding.Port, "networkgroup": group, "role": binding.Role}
		inventory := map[string]any{"interface": name, "port": binding.Port}
		inventory["type"] = group
		if observed.AdminEnabled != nil {
			inventory["enabled"], row["enable"] = *observed.AdminEnabled, *observed.AdminEnabled
		}
		if observed.IPv4Mode != "" {
			row["type"] = observed.IPv4Mode
			config := map[string]any{"type": observed.IPv4Mode, "name": group, "ifname": name, "port_idx": binding.Port, "networkgroup": group, "uplink_ifname": name}
			key := "config_network_wan"
			if binding.Role == "wan2" {
				key = "config_network_wan2"
			}
			root[key] = config
		}
		if observed.MAC != "" {
			row["mac"], inventory["mac"] = observed.MAC, observed.MAC
		}
		if observed.Up != nil {
			row["up"], row["isWanUp"], inventory["plugged"] = *observed.Up, *observed.Up, *observed.Up
		}
		if observed.SpeedMbps != nil {
			row["speed"] = *observed.SpeedMbps
		}
		if observed.Duplex != "" {
			row["full_duplex"] = observed.Duplex == "full"
		}
		ipv6 := []string{}
		for _, address := range observed.Addresses {
			prefix, err := netip.ParsePrefix(address)
			if err != nil {
				continue
			}
			if prefix.Addr().Is4() {
				if _, exists := row["ip"]; !exists {
					row["ip"], inventory["ipv4"] = prefix.Addr().String(), prefix.Addr().String()
					row["address"] = address
					row["netmask"] = net.IP(net.CIDRMask(prefix.Bits(), 32)).String()
				}
			} else {
				ipv6 = append(ipv6, prefix.Addr().String())
			}
		}
		if len(ipv6) > 0 {
			row["ipv6"], inventory["ipv6"] = ipv6, ipv6
		}
		configKey := "config_network_wan"
		if binding.Role == "wan2" {
			configKey = "config_network_wan2"
		}
		if config, ok := root[configKey].(map[string]any); ok {
			for _, field := range []string{"ip", "netmask"} {
				if value, exists := row[field]; exists {
					config[field] = value
				}
			}
		}
		if observed.Counters.RXBytes != nil {
			row["rx_bytes"] = *observed.Counters.RXBytes
		}
		if observed.Counters.TXBytes != nil {
			row["tx_bytes"] = *observed.Counters.TXBytes
		}
		if observed.Counters.RXPackets != nil {
			row["rx_packets"] = *observed.Counters.RXPackets
		}
		if observed.Counters.TXPackets != nil {
			row["tx_packets"] = *observed.Counters.TXPackets
		}
		if rate := wireRate(observed.Rates.RXBytesPerSecond); rate != nil {
			row["rx_bytes-r"] = *rate
		}
		if rate := wireRate(observed.Rates.TXBytesPerSecond); rate != nil {
			row["tx_bytes-r"] = *rate
		}
		for _, monitor := range snap.Gateways {
			if monitor.Role != binding.Role {
				continue
			}
			if monitor.Connected != nil {
				row["isWanConnected"] = *monitor.Connected
				// UniFi uses uptime > 0 as current reachability, not elapsed seconds.
				// Project the current monitor result; this is not historical ISP uptime.
				availability := 0.0
				if *monitor.Connected {
					availability = 100
					if monitor.LossPercent != nil && !math.IsNaN(*monitor.LossPercent) && !math.IsInf(*monitor.LossPercent, 0) && *monitor.LossPercent >= 0 && *monitor.LossPercent <= 100 {
						availability -= *monitor.LossPercent
					}
				}
				result := map[string]any{"uptime": availability, "availability": availability}
				probe := map[string]any{"availability": availability}
				if monitor.LatencyMS != nil {
					probe["latency_average"] = int(*monitor.LatencyMS + 0.5)
				}
				result["alerting_monitors"] = []map[string]any{probe}
				health[group] = result
			}
			if monitor.LatencyMS != nil {
				row["latency"] = int(*monitor.LatencyMS + 0.5)
			}
		}
		key := "wan1"
		if binding.Role == "wan2" {
			key = "wan2"
		}
		root[key] = row
		link := make(map[string]any, len(row)+1)
		for k, v := range row {
			link[k] = v
		}
		link["name"], link["type"] = name, "wire"
		uplinks = append(uplinks, link)
		wans = append(wans, inventory)
	}
	if len(wans) > 0 {
		root["wans"], root["uplink_table"] = wans, uplinks
	}
	if len(health) > 0 {
		root["uptime_stats"] = health
	}
}
