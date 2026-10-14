package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// CycleResult is the status produced by one gateway worker cycle.
type CycleResult = domain.CycleStatus

// Worker owns one appliance cycle; methods run sequentially per identity.
type Worker struct {
	HA                 HATracker
	ID                 string
	Source             domain.Source
	Bindings           []domain.Binding
	Publisher          domain.Publisher
	Store              domain.StateStore
	Interval           time.Duration
	Timeout            time.Duration
	Plan               func(context.Context, []byte, string) error
	OnReset            func() error
	InvalidatePlans    func() error
	RecordProvisioning func([]byte, string) error
	MonitorOnly        bool
	SyncInventory      func(context.Context, domain.Snapshot) (domain.InventorySync, error)
	Clients            ClientTracker
	WAN                WANTracker
	SaveHistory        func([]domain.Client, []domain.WANHistory) error
	Discover           func(context.Context, domain.Snapshot) error
	interval           time.Duration
	failures           int
	rates              RateTracker
	Now                func() time.Time
	lastCollection     time.Time
	lastInform         time.Time
	pendingVersion     string
	provisioning       string
}

// RestoreStatus retains successful timestamps when the worker process restarts.
func (w *Worker) RestoreStatus(previous CycleResult) {
	if previous.SourceID == w.ID {
		w.lastCollection, w.lastInform = previous.LastCollectionAt, previous.LastInformAt
		if previous.HA != nil && previous.HA.Role == w.HA.Role && previous.HA.Peer == w.HA.Peer && previous.HA.Status == "observed" {
			w.HA.LastKnownState, w.HA.ChangedAt = previous.HA.CARPState, previous.HA.ObservedTransitionAt
		}
	}
}

// Cycle collects before publication, persists adoption, and prepares provisioning.
func (w *Worker) Cycle(ctx context.Context) (CycleResult, error) {
	ctx, cancel := context.WithTimeout(ctx, w.Timeout)
	defer cancel()
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	r := CycleResult{SourceID: w.ID, AttemptedAt: now(), LastCollectionAt: w.lastCollection, LastInformAt: w.lastInform, Provisioning: w.provisioning, ProvisioningVersion: w.pendingVersion, NextDelay: w.nextDelay()}
	state, err := w.Store.Load()
	if err != nil {
		return w.failed(r), fmt.Errorf("load adoption: %w", err)
	}
	r.Adopted = state.AuthKey != ""
	w.pendingVersion, w.provisioning = state.PendingCFGVersion, state.Provisioning
	r.Provisioning, r.ProvisioningVersion = w.provisioning, w.pendingVersion
	snap, err := w.Source.Collect(ctx)
	if err != nil {
		w.rates.Clear()
		return w.failed(r), fmt.Errorf("collect: %w", err)
	}
	if snap.SourceID != w.ID || snap.ObservedAt.IsZero() {
		w.rates.Clear()
		return w.failed(r), fmt.Errorf("source returned invalid snapshot identity or timestamp")
	}
	snap = w.rates.Apply(snap)
	snap = w.Clients.Apply(snap, w.Bindings)
	snap = w.HA.Apply(snap, w.Bindings)
	interval := w.Interval
	if w.interval > 0 {
		interval = w.interval
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	w.WAN.MaxGap = 2 * interval
	snap = w.WAN.Apply(snap)
	w.lastCollection = snap.ObservedAt
	r.ObservedAt, r.LastCollectionAt, r.InterfaceCount = snap.ObservedAt, snap.ObservedAt, len(snap.Interfaces)
	r.System, r.Gateways, r.Warnings = snap.System, snap.Gateways, snap.Warnings
	r.Clients, r.VLANs, r.WANHistory = snap.Clients, snap.VLANs, snap.WANHistory
	r.CARP = snap.CARP
	r.HA = snap.HA
	if w.SaveHistory != nil {
		if err := w.SaveHistory(snap.Clients, snap.WANHistory); err != nil {
			return w.failed(r), fmt.Errorf("persist observation history: %w", err)
		}
	}
	if w.Discover != nil {
		if err := w.Discover(ctx, snap); err != nil {
			snap.Warnings = append(snap.Warnings, "discovery_failed")
		}
	}
	r.Warnings = snap.Warnings
	ex, err := w.Publisher.Publish(ctx, snap, state)
	r.HTTPStatus, r.ResponseType = ex.HTTPStatus, ex.ResponseType
	r.Cipher, r.CipherFallback, r.Commands = ex.Cipher, ex.CipherFallback, ex.CommandStatus
	if err != nil {
		return w.failed(r), fmt.Errorf("publish: %w", err)
	}
	if ex.HTTPStatus == 404 && state.AuthKey == "" {
		w.failures = 0
		r.NextDelay = w.nextDelay()
		return r, nil
	}
	if ex.HTTPStatus != 200 {
		return w.failed(r), fmt.Errorf("controller returned HTTP %d", ex.HTTPStatus)
	}
	if err := w.Store.Save(ex.Adoption); err != nil {
		return w.failed(r), fmt.Errorf("persist adoption: %w", err)
	}
	w.failures = 0
	w.lastInform = now()
	r.LastInformAt = w.lastInform
	if ex.Interval > 0 {
		w.interval = max(5*time.Second, min(time.Minute, ex.Interval))
	}
	r.Adopted, r.IgnoredCommand = ex.Adoption.AuthKey != "", ex.IgnoredCommand
	if r.Adopted && !ex.ResetRequested && w.SyncInventory != nil {
		result, syncErr := w.SyncInventory(ctx, snap)
		if syncErr != nil {
			result.Status = "failed"
			result.Error = syncErr.Error()
			r.Warnings = append(r.Warnings, "controller_inventory_sync_failed")
		}
		r.Inventory = &result
	}
	r.Reset = ex.ResetRequested
	if ex.ResetRequested {
		w.rates.Clear()
		w.pendingVersion, w.provisioning = "", ""
		r.Provisioning, r.ProvisioningVersion = "", ""
	}
	if ex.ResetRequested && w.OnReset != nil {
		if err := w.OnReset(); err != nil {
			return r, fmt.Errorf("clear pending virtual-device plan: %w", err)
		}
	}
	r.NextDelay = w.nextDelay()
	if len(ex.SystemConfig) > 0 {
		if w.MonitorOnly && (w.RecordProvisioning == nil || ex.RequestedCFGVersion == "") {
			return w.failed(r), fmt.Errorf("monitoring acceptance requires durable configuration storage and a version")
		}
		if w.InvalidatePlans != nil {
			if err := w.InvalidatePlans(); err != nil {
				return r, fmt.Errorf("invalidate previous provisioning plans: %w", err)
			}
		}
		w.pendingVersion = ex.RequestedCFGVersion
		r.ProvisioningVersion = w.pendingVersion
		if w.RecordProvisioning != nil {
			if err := w.RecordProvisioning(ex.SystemConfig, ex.RequestedCFGVersion); err != nil {
				return w.failed(r), fmt.Errorf("record pending provisioning: %w", err)
			}
		}
		r.Provisioning = "unsupported"
		if w.MonitorOnly {
			ex.Adoption.CFGVersion = ex.RequestedCFGVersion
			w.pendingVersion = ""
			r.ProvisioningVersion = ""
			r.Provisioning = "monitoring"
		} else if w.Plan != nil {
			if err := w.Plan(ctx, ex.SystemConfig, ex.RequestedCFGVersion); err != nil {
				r.Provisioning = "plan_rejected"
				w.provisioning = r.Provisioning
				ex.Adoption.PendingCFGVersion, ex.Adoption.Provisioning = w.pendingVersion, w.provisioning
				if saveErr := w.Store.Save(ex.Adoption); saveErr != nil {
					return r, fmt.Errorf("persist provisioning status: %w", saveErr)
				}
				return r, fmt.Errorf("plan provisioning: %w", err)
			}
			r.Provisioning = "awaiting_local_review"
		}
		w.provisioning = r.Provisioning
		ex.Adoption.PendingCFGVersion, ex.Adoption.Provisioning = w.pendingVersion, w.provisioning
		if err := w.Store.Save(ex.Adoption); err != nil {
			return w.failed(r), fmt.Errorf("persist provisioning status: %w", err)
		}
	}
	return r, nil
}

func (w *Worker) failed(r CycleResult) CycleResult {
	w.failures = min(w.failures+1, 6)
	r.NextDelay = w.nextDelay()
	r.ConsecutiveFailures = w.failures
	return r
}

func (w *Worker) nextDelay() time.Duration {
	interval := w.Interval
	if w.interval > 0 {
		interval = w.interval
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return min(5*time.Minute, interval*time.Duration(1<<w.failures))
}
