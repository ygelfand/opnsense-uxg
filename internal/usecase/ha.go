package usecase

import (
	"strings"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// HATracker projects observed inside-VIP ownership without controlling failover.
type HATracker struct {
	Role           string
	Peer           string
	LastKnownState string
	ChangedAt      *time.Time
}

// Apply marks mixed or missing inside-VIP ownership unknown for UniFi reporting.
func (t *HATracker) Apply(snap domain.Snapshot, bindings []domain.Binding) domain.Snapshot {
	if t.Role == "" {
		return snap
	}
	h := domain.HAStatus{Role: t.Role, Peer: t.Peer, CARPState: "unknown", Status: "unavailable"}
	state := ""
	for _, vip := range snap.CARP {
		address := associateAddress(vip.Address, vip.Interface, snap, bindings)
		if address.Role != "lan" && address.Role != "lan2" {
			continue
		}
		h.VIPCount++
		role := strings.ToLower(vip.State)
		if role != "master" && role != "backup" && role != "init" {
			state = "mixed"
			continue
		}
		if state == "" {
			state = role
		} else if state != role {
			state = "mixed"
		}
	}
	if h.VIPCount > 0 {
		if state == "mixed" {
			h.Status = "mixed"
		} else {
			h.CARPState, h.Status = state, "observed"
			if state != "init" {
				if t.LastKnownState != "" && t.LastKnownState != state {
					at := snap.ObservedAt
					t.ChangedAt = &at
				}
				t.LastKnownState = state
			}
			h.ObservedTransitionAt = t.ChangedAt
		}
	}
	snap.HA = &h
	return snap
}
