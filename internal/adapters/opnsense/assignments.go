package opnsense

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

func (s *Source) collectInterfaceAssignments(ctx context.Context, snap *domain.Snapshot) {
	result, err := s.Client.sdk.Interfaces().OverviewGet(ctx)
	if err != nil || result == nil {
		snap.Warnings = append(snap.Warnings, "interface_assignments_unavailable")
		return
	}
	for _, assignment := range result.Rows {
		for i := range snap.Interfaces {
			iface := &snap.Interfaces[i]
			if assignment.Config.If == "" || assignment.Config.If != iface.Name {
				continue
			}
			iface.Description = assignment.Description
			for _, address := range assignment.IPv4 {
				if observation, ok := carpObservation(iface.Name, address.IPAddr, address.CarpStatus, address.Vhid); ok {
					iface.CARP = append(iface.CARP, observation)
					snap.CARP = append(snap.CARP, observation)
				}
			}
			for _, address := range assignment.IPv6 {
				if observation, ok := carpObservation(iface.Name, address.IPAddr, address.CarpStatus, address.Vhid); ok {
					iface.CARP = append(iface.CARP, observation)
					snap.CARP = append(snap.CARP, observation)
				}
			}
			for _, router := range assignment.IfctlRouter {
				if ip, err := netip.ParseAddr(router); err == nil && ip.Is4() {
					iface.GatewayIP = ip.String()
					break
				}
			}
			mode := strings.ToLower(assignment.Config.IPAddr)
			switch mode {
			case "dhcp", "pppoe":
				iface.IPv4Mode = mode
			default:
				if ip, err := netip.ParseAddr(mode); err == nil && ip.Is4() {
					iface.IPv4Mode = "static"
				}
			}
			switch assignment.Config.Enable {
			case "1":
				enabled := true
				iface.AdminEnabled = &enabled
			case "0":
				enabled := false
				iface.AdminEnabled = &enabled
			}
		}
	}
}

func carpObservation(iface, address, state, vhid string) (domain.CARPObservation, bool) {
	state = strings.ToUpper(strings.TrimSpace(state))
	if state != "MASTER" && state != "BACKUP" && state != "INIT" {
		return domain.CARPObservation{}, false
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		if prefix, prefixErr := netip.ParsePrefix(address); prefixErr == nil {
			ip, err = prefix.Addr(), nil
		}
	}
	if err != nil {
		return domain.CARPObservation{}, false
	}
	observation := domain.CARPObservation{Interface: iface, Address: ip.String(), State: state}
	if id, err := strconv.Atoi(vhid); err == nil && id >= 1 && id <= 255 {
		observation.VHID = &id
	}
	return observation, true
}
