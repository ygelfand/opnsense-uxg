package usecase

import (
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// RateTracker owns consecutive collection samples for one appliance.
type RateTracker struct{ previous domain.Snapshot }

// Clear starts a new sampling window after collection failure or source reset.
func (r *RateTracker) Clear() { r.previous = domain.Snapshot{} }

// Apply derives rates from cumulative counters and preserves unknown/reset samples.
func (r *RateTracker) Apply(snap domain.Snapshot) domain.Snapshot {
	out := snap
	out.Interfaces = append([]domain.Interface{}, snap.Interfaces...)
	old := r.previous
	seconds := snap.ObservedAt.Sub(old.ObservedAt).Seconds()
	rebooted := old.System.UptimeSeconds != nil && snap.System.UptimeSeconds != nil && *snap.System.UptimeSeconds < *old.System.UptimeSeconds
	previous := make(map[string]domain.Counters, len(old.Interfaces))
	if old.SourceID == snap.SourceID && !old.ObservedAt.IsZero() && seconds > 0 && !rebooted {
		for _, row := range old.Interfaces {
			previous[row.Name] = row.Counters
		}
	}
	for i := range out.Interfaces {
		row := &out.Interfaces[i]
		before := previous[row.Name]
		row.Rates = domain.Rates{RXBytesPerSecond: deltaRate(before.RXBytes, row.Counters.RXBytes, seconds), TXBytesPerSecond: deltaRate(before.TXBytes, row.Counters.TXBytes, seconds)}
	}
	if old.ObservedAt.IsZero() || snap.ObservedAt.After(old.ObservedAt) {
		r.previous = snap
		r.previous.Interfaces = append([]domain.Interface{}, snap.Interfaces...)
		for i := range r.previous.Interfaces {
			c := &r.previous.Interfaces[i].Counters
			c.RXBytes, c.TXBytes, c.RXPackets, c.TXPackets = cloneCounter(c.RXBytes), cloneCounter(c.TXBytes), cloneCounter(c.RXPackets), cloneCounter(c.TXPackets)
		}
		if snap.System.UptimeSeconds != nil {
			value := *snap.System.UptimeSeconds
			r.previous.System.UptimeSeconds = &value
		}
	}
	return out
}

func cloneCounter(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func deltaRate(previous, current *uint64, seconds float64) *float64 {
	if previous == nil || current == nil || seconds <= 0 || *current < *previous {
		return nil
	}
	rate := float64(*current-*previous) / seconds
	return &rate
}
