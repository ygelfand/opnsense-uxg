package unifi

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jamesbraid/unifi-emu/discovery"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// Discoverer sends interval-limited UDP announcements to operator-owned targets.
type Discoverer struct {
	Identity domain.Identity
	Targets  []string
	Interval time.Duration
	last     time.Time
}

// Send announces a virtual gateway identity using the observed appliance uptime.
func (d *Discoverer) Send(ctx context.Context, snap domain.Snapshot) error {
	if !d.last.IsZero() && snap.ObservedAt.Sub(d.last) < d.Interval {
		return nil
	}
	mac, err := net.ParseMAC(d.Identity.MAC)
	if err != nil {
		return err
	}
	announcement := discovery.Announcement{Version: discovery.V2, Command: 6, MAC: mac, SourceMAC: mac, Addresses: []discovery.Address{{MAC: mac, IP: net.ParseIP(d.Identity.ManagementIP)}}, Firmware: gatewayFirmwareVersion, Hostname: d.Identity.Hostname, Platform: d.Identity.Model, Model: d.Identity.Model}
	if snap.System.UptimeSeconds != nil {
		announcement.Uptime = uint32(min(max(*snap.System.UptimeSeconds, 0), 1<<32-1))
	}
	packet, err := announcement.Marshal()
	if err != nil {
		return err
	}
	var failures []error
	for _, target := range d.Targets {
		dialer := net.Dialer{Timeout: time.Second}
		conn, err := dialer.DialContext(ctx, "udp4", target)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		deadline := time.Now().Add(time.Second)
		if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
			deadline = until
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			failures = append(failures, err)
		} else {
			_, err := conn.Write(packet)
			if err != nil {
				failures = append(failures, err)
			}
		}
		if err := conn.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	d.last = snap.ObservedAt
	return errors.Join(failures...)
}
