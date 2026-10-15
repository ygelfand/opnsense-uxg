package unifiapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

func desiredNetwork(binding domain.Binding, iface domain.Interface) (map[string]any, error) {
	name := iface.Description
	if name == "" {
		name = strings.ToUpper(binding.Role)
	}
	n := map[string]any{"name": name, "purpose": "wan", "wan_networkgroup": strings.ToUpper(binding.Role), "wan_type": iface.IPv4Mode}
	switch iface.IPv4Mode {
	case "dhcp":
	case "static":
		found := false
		for _, address := range iface.Addresses {
			p, err := netip.ParsePrefix(address)
			if err == nil && p.Addr().Is4() {
				n["wan_ip"], n["wan_netmask"] = p.Addr().String(), net.IP(net.CIDRMask(p.Bits(), 32)).String()
				found = true
				break
			}
		}
		gateway, err := netip.ParseAddr(iface.GatewayIP)
		if !found || err != nil || !gateway.Is4() {
			return nil, fmt.Errorf("static WAN inventory requires a measured IPv4 prefix and gateway")
		}
		n["wan_gateway"] = gateway.String()
	default:
		return nil, fmt.Errorf("WAN address mode %q cannot be mirrored yet", iface.IPv4Mode)
	}
	return n, nil
}

func controllerVLANTag(network map[string]any) (int, bool) {
	value, ok := network["vlan"].(float64)
	if !ok || value < 1 || value > 4094 || value != float64(int(value)) {
		return 0, false
	}
	return int(value), true
}

func desiredVLANFields(vlan domain.VLAN, snap domain.Snapshot) (map[string]any, string, error) {
	if vlan.Tag < 1 || vlan.Tag > 4094 {
		return nil, "", fmt.Errorf("invalid OPNsense VLAN tag %d", vlan.Tag)
	}
	var iface domain.Interface
	for _, observed := range snap.Interfaces {
		if observed.Name == vlan.Interface {
			iface = observed
			break
		}
	}
	if iface.Name == "" {
		return nil, "", fmt.Errorf("OPNsense VLAN %d interface %q was not observed", vlan.Tag, vlan.Interface)
	}
	prefixes := make([]netip.Prefix, 0, len(iface.Addresses))
	for _, address := range iface.Addresses {
		prefix, err := netip.ParsePrefix(address)
		if err == nil && prefix.Addr().Is4() {
			prefixes = append(prefixes, prefix)
		}
	}
	if len(prefixes) == 0 {
		return nil, "", fmt.Errorf("OPNsense VLAN %d has no observed IPv4 subnet", vlan.Tag)
	}
	var gateway netip.Addr
	activeCARPs := map[netip.Addr]struct{}{}
	observedCARP := false
	for _, observation := range snap.CARP {
		if observation.Interface != vlan.Interface {
			continue
		}
		observedCARP = true
		if !strings.EqualFold(observation.State, "MASTER") {
			continue
		}
		address, err := netip.ParseAddr(observation.Address)
		if err != nil || !address.Is4() {
			continue
		}
		for _, prefix := range prefixes {
			if prefix.Contains(address) {
				activeCARPs[address] = struct{}{}
				gateway = address
				break
			}
		}
	}
	if len(activeCARPs) > 1 {
		return nil, "", fmt.Errorf("OPNsense VLAN %d has multiple active CARP addresses", vlan.Tag)
	}
	if !gateway.IsValid() {
		if observedCARP {
			return nil, "", fmt.Errorf("OPNsense VLAN %d has no active CARP gateway address", vlan.Tag)
		}
		gateway = prefixes[0].Addr()
	}
	var subnet netip.Prefix
	for _, prefix := range prefixes {
		if prefix.Contains(gateway) {
			subnet = netip.PrefixFrom(gateway, prefix.Bits())
			break
		}
	}
	if !subnet.IsValid() {
		return nil, "", fmt.Errorf("OPNsense VLAN %d gateway is outside its observed subnet", vlan.Tag)
	}
	name := strings.TrimSpace(vlan.Name)
	if name == "" {
		name = fmt.Sprintf("VLAN %d", vlan.Tag)
	}
	return map[string]any{
		"purpose":       "corporate",
		"gateway_type":  "default",
		"vlan_enabled":  true,
		"ip_subnet":     subnet.String(),
		"dhcpd_enabled": false,
	}, name, nil
}

var controllerDefaultWANName = regexp.MustCompile(`^Internet [0-9]+$`)

// controllerDefaultWAN matches the WAN records UniFi 10.6.106 creates when a gateway is adopted into a site without WANs.
func controllerDefaultWAN(current, wanted map[string]any) bool {
	name, _ := current["name"].(string)
	if current["purpose"] != "wan" || !controllerDefaultWANName.MatchString(name) {
		return false
	}
	for k, v := range wanted {
		if k != "name" && !reflect.DeepEqual(current[k], v) {
			return false
		}
	}
	return true
}

func matchesFields(current, wanted map[string]any) bool {
	for k, v := range wanted {
		if !reflect.DeepEqual(current[k], v) {
			return false
		}
	}
	return true
}

// Sync creates or reconciles bridge-owned WAN and VLAN definitions and assignments.
func (c *Client) Sync(ctx context.Context, snap domain.Snapshot) (domain.InventorySync, error) {
	if snap.SourceID != c.Identity.ID || c.Load == nil || c.Save == nil {
		return domain.InventorySync{}, fmt.Errorf("invalid controller inventory source or ownership storage")
	}
	if time.Now().Before(c.nextSync) {
		return domain.InventorySync{Status: c.last.Status}, nil
	}
	d, site, err := c.findDevice(ctx)
	if err != nil {
		return domain.InventorySync{}, err
	}
	state, err := c.Load()
	if err != nil {
		return domain.InventorySync{}, err
	}
	if state.URL != "" && (state.URL != c.URL || state.Site != site || !strings.EqualFold(state.MAC, c.Identity.MAC)) {
		return domain.InventorySync{}, fmt.Errorf("controller inventory ownership belongs to a different target")
	}
	state.URL, state.Site, state.MAC = c.URL, site, c.Identity.MAC
	if state.Networks == nil {
		state.Networks = map[string]OwnedNetwork{}
	}
	var response struct {
		Data []map[string]any `json:"data"`
	}
	if err := c.request(ctx, http.MethodGet, sitePath(site)+"/rest/networkconf", nil, &response); err != nil {
		return domain.InventorySync{}, err
	}
	desired := map[string]map[string]any{}
	desiredVLANs := map[int]map[string]any{}
	newVLANNames := map[int]string{}
	assignments := []map[string]any{}
	explicitPorts := map[string]bool{}
	for _, binding := range c.Bindings {
		if c.SyncWANs {
			ifname := "eth" + strconv.Itoa(binding.Port-1)
			assignments = append(assignments, map[string]any{"ifname": ifname, "networkgroup": strings.ToUpper(binding.Role)})
			explicitPorts[ifname] = true
		}
		if !c.SyncWANs || binding.Role != "wan" && binding.Role != "wan2" {
			continue
		}
		var iface domain.Interface
		for _, i := range snap.Interfaces {
			if i.Name == binding.Interface {
				iface = i
				break
			}
		}
		fields, err := desiredNetwork(binding, iface)
		if err != nil {
			return domain.InventorySync{}, err
		}
		desired[strings.ToUpper(binding.Role)] = fields
	}
	if c.SyncVLANs {
		for _, vlan := range snap.VLANs {
			if vlan.Tag == c.NativeVLAN {
				continue
			}
			if _, duplicate := desiredVLANs[vlan.Tag]; duplicate {
				return domain.InventorySync{}, fmt.Errorf("duplicate OPNsense VLAN tag %d", vlan.Tag)
			}
			fields, name, err := desiredVLANFields(vlan, snap)
			if err != nil {
				return domain.InventorySync{}, err
			}
			desiredVLANs[vlan.Tag], newVLANNames[vlan.Tag] = fields, name
		}
	}
	for _, port := range c.DisabledPorts {
		ifname := "eth" + strconv.Itoa(port-1)
		assignments = append(assignments, map[string]any{"ifname": ifname, "disabled": true})
		explicitPorts[ifname] = true
	}
	// Validate all ownership/conflicts before the first remote mutation.
	existing := map[string]map[string]any{}
	controllerDefaults := map[string]bool{}
	existingVLANs := map[int]map[string]any{}
	for _, network := range response.Data {
		if tag, ok := controllerVLANTag(network); ok {
			if _, needed := desiredVLANs[tag]; needed {
				if existingVLANs[tag] != nil {
					return domain.InventorySync{}, fmt.Errorf("duplicate controller VLAN %d", tag)
				}
				existingVLANs[tag] = network
				role := fmt.Sprintf("VLAN:%d", tag)
				owned, isOwned := state.Networks[role]
				if isOwned {
					if owned.ID != "" && network["_id"] != owned.ID || !matchesFields(network, normalizeVLANFields(owned.Fields)) {
						return domain.InventorySync{}, fmt.Errorf("controller VLAN %d has conflicting operator edits", tag)
					}
				} else if network["purpose"] != "vlan-only" && !matchesFields(network, desiredVLANs[tag]) {
					return domain.InventorySync{}, fmt.Errorf("unmanaged controller VLAN %d conflicts with source inventory", tag)
				}
			}
		}
		role, _ := network["wan_networkgroup"].(string)
		if _, needed := desired[role]; !needed || network["purpose"] != "wan" {
			continue
		}
		if existing[role] != nil {
			return domain.InventorySync{}, fmt.Errorf("duplicate controller WAN group %s", role)
		}
		existing[role] = network
		owned, ok := state.Networks[role]
		if ok {
			if owned.ID != "" && network["_id"] != owned.ID || !matchesFields(network, owned.Fields) {
				return domain.InventorySync{}, fmt.Errorf("controller WAN %s has conflicting operator edits", role)
			}
		} else if controllerDefaultWAN(network, desired[role]) {
			controllerDefaults[role] = true
		} else if !matchesFields(network, desired[role]) {
			return domain.InventorySync{}, fmt.Errorf("unmanaged controller WAN %s conflicts with source inventory", role)
		}
	}
	merged, err := mergeAssignments(d.Assignments, assignments, state.Assignments, explicitPorts)
	if err != nil {
		return domain.InventorySync{}, err
	}
	result := domain.InventorySync{Status: "synced"}
	for tag, fields := range desiredVLANs {
		role := fmt.Sprintf("VLAN:%d", tag)
		current := existingVLANs[tag]
		if current == nil {
			state.Networks[role] = OwnedNetwork{Fields: fields, Pending: true}
			if err := c.Save(state); err != nil {
				return result, err
			}
			create := map[string]any{"name": newVLANNames[tag], "vlan": tag}
			for key, value := range fields {
				create[key] = value
			}
			var created struct {
				Data []map[string]any `json:"data"`
			}
			if err := c.request(ctx, http.MethodPost, sitePath(site)+"/rest/networkconf", create, &created); err != nil {
				return result, err
			}
			if len(created.Data) != 1 {
				return result, fmt.Errorf("controller did not return the created VLAN %d definition", tag)
			}
			id, _ := created.Data[0]["_id"].(string)
			if id == "" {
				return result, fmt.Errorf("created controller VLAN %d has no record ID", tag)
			}
			state.Networks[role] = OwnedNetwork{ID: id, Fields: fields}
			result.VLANsCreated++
		} else {
			id, _ := current["_id"].(string)
			if id == "" {
				return result, fmt.Errorf("controller VLAN %d has no record ID", tag)
			}
			if !matchesFields(current, fields) {
				update := make(map[string]any, len(fields)+1)
				for key, value := range fields {
					update[key] = value
				}
				if current["purpose"] == "vlan-only" {
					update["name"] = newVLANNames[tag]
				}
				if err := c.request(ctx, http.MethodPut, sitePath(site)+"/rest/networkconf/"+url.PathEscape(id), update, nil); err != nil {
					return result, err
				}
				result.VLANsUpdated++
			}
			state.Networks[role] = OwnedNetwork{ID: id, Fields: fields}
		}
		if err := c.Save(state); err != nil {
			return result, err
		}
	}
	loadBalanceDefault := "failover-only"
	for _, network := range response.Data {
		if network["purpose"] == "wan" && network["wan_load_balance_type"] == "weighted" {
			loadBalanceDefault = "weighted"
		}
	}
	for _, binding := range c.Bindings {
		role := strings.ToUpper(binding.Role)
		fields, needed := desired[role]
		if !needed {
			continue
		}
		current := existing[role]
		owned, isOwned := state.Networks[role]
		if current == nil {
			state.Networks[role] = OwnedNetwork{Fields: fields, Pending: true}
			if err := c.Save(state); err != nil {
				return result, err
			}
			var created struct {
				Data []map[string]any `json:"data"`
			}
			create := make(map[string]any, len(fields)+1)
			for k, v := range fields {
				create[k] = v
			}
			create["wan_load_balance_type"] = loadBalanceDefault
			if err := c.request(ctx, http.MethodPost, sitePath(site)+"/rest/networkconf", create, &created); err != nil {
				return result, err
			}
			if len(created.Data) != 1 {
				return result, fmt.Errorf("controller did not return the created WAN definition")
			}
			id, ok := created.Data[0]["_id"].(string)
			if !ok || id == "" {
				return result, fmt.Errorf("created controller WAN has no record ID")
			}
			state.Networks[role] = OwnedNetwork{ID: id, Fields: fields}
			result.Created++
		} else if isOwned || controllerDefaults[role] {
			id, _ := current["_id"].(string)
			if id == "" {
				return result, fmt.Errorf("controller WAN has no record ID")
			}
			missingLoadBalance := current["wan_load_balance_type"] == nil || current["wan_load_balance_type"] == ""
			if !matchesFields(current, fields) || missingLoadBalance {
				update := make(map[string]any, len(fields)+3)
				for k, v := range fields {
					update[k] = v
				}
				if missingLoadBalance {
					update["wan_load_balance_type"] = loadBalanceDefault
				}
				for _, k := range []string{"wan_ip", "wan_netmask", "wan_gateway"} {
					if _, had := owned.Fields[k]; had {
						if _, keep := fields[k]; !keep {
							update[k] = ""
						}
					}
				}
				if err := c.request(ctx, http.MethodPut, sitePath(site)+"/rest/networkconf/"+url.PathEscape(id), update, nil); err != nil {
					return result, err
				}
				result.Updated++
			}
			state.Networks[role] = OwnedNetwork{ID: id, Fields: fields}
		}
		if err := c.Save(state); err != nil {
			return result, err
		}
	}
	if !reflect.DeepEqual(merged, d.Assignments) {
		// Journal the expected assignment before the idempotent write.
		state.Assignments = assignments
		if err := c.Save(state); err != nil {
			return result, err
		}
		if err := c.request(ctx, http.MethodPut, sitePath(site)+"/rest/device/"+url.PathEscape(d.ID), map[string]any{"ethernet_overrides": merged}, nil); err != nil {
			return result, err
		}
		result.AssignmentsUpdated = true
	}
	if result.Created > 0 || result.Updated > 0 || result.VLANsCreated > 0 || result.VLANsUpdated > 0 || result.AssignmentsUpdated {
		var readback struct {
			Data []map[string]any `json:"data"`
		}
		if err := c.request(ctx, http.MethodGet, sitePath(site)+"/rest/networkconf", nil, &readback); err != nil {
			return result, err
		}
		for role, fields := range desired {
			found := false
			for _, n := range readback.Data {
				if n["purpose"] == "wan" && n["wan_networkgroup"] == role && matchesFields(n, fields) {
					found = true
					break
				}
			}
			if !found {
				return result, fmt.Errorf("controller WAN %s failed readback verification", role)
			}
			if _, owned := state.Networks[role]; owned {
				for _, n := range readback.Data {
					if n["purpose"] == "wan" && n["wan_networkgroup"] == role && n["wan_load_balance_type"] != "failover-only" && n["wan_load_balance_type"] != "weighted" {
						return result, fmt.Errorf("controller WAN %s has no valid load-balancing metadata", role)
					}
				}
			}
		}
		for tag, fields := range desiredVLANs {
			found := false
			for _, n := range readback.Data {
				if actualTag, ok := controllerVLANTag(n); ok && actualTag == tag && matchesFields(n, fields) {
					found = true
					break
				}
			}
			if !found {
				return result, fmt.Errorf("controller VLAN %d failed readback verification", tag)
			}
		}
		fresh, _, err := c.findDevice(ctx)
		if err != nil {
			return result, err
		}
		for _, a := range assignments {
			found := false
			for _, actual := range fresh.Assignments {
				if matchesFields(actual, a) {
					found = true
					break
				}
			}
			if !found {
				return result, fmt.Errorf("controller WAN port assignment failed readback verification")
			}
		}
	}
	c.last, c.nextSync = result, time.Now().Add(time.Minute)
	return result, nil
}

func normalizeVLANFields(fields map[string]any) map[string]any {
	if _, legacy := fields["ip"]; !legacy {
		return fields
	}
	normalized := make(map[string]any, len(fields)-1)
	for key, value := range fields {
		if key != "ip" {
			normalized[key] = value
		}
	}
	return normalized
}

func mergeAssignments(existing, desired, previous []map[string]any, explicitPorts map[string]bool) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(existing)+len(desired))
	seen := map[string]bool{}
	for _, entry := range existing {
		name, _ := entry["ifname"].(string)
		wanted := map[string]any(nil)
		for _, d := range desired {
			if d["ifname"] == name {
				wanted = d
				break
			}
		}
		if wanted == nil {
			out = append(out, entry)
			continue
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate virtual WAN port assignment")
		}
		seen[name] = true
		group, _ := entry["networkgroup"].(string)
		if group != "LAN" && group != "" && group != wanted["networkgroup"] {
			owned := false
			for _, p := range previous {
				if matchesFields(entry, p) {
					owned = true
					break
				}
			}
			if !owned && !explicitPorts[name] {
				return nil, fmt.Errorf("virtual WAN port has conflicting operator assignment")
			}
		}
		copy := make(map[string]any, len(entry)+len(wanted))
		for k, v := range entry {
			copy[k] = v
		}
		for k, v := range wanted {
			copy[k] = v
		}
		out = append(out, copy)
	}
	for _, d := range desired {
		name, _ := d["ifname"].(string)
		if !seen[name] {
			out = append(out, d)
		}
	}
	return out, nil
}
