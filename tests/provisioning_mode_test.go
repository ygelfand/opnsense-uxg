package framework_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

type configurationPublisher struct{}

func (configurationPublisher) Publish(_ context.Context, _ domain.Snapshot, state domain.Adoption) (domain.Exchange, error) {
	return domain.Exchange{Adoption: state, HTTPStatus: 200, SystemConfig: []byte(`{"udapi":{"interfaces":[]}}`), RequestedCFGVersion: "new-version"}, nil
}

func TestMonitoringAcknowledgesOnlyDurablyStoredVirtualConfiguration(t *testing.T) {
	t.Parallel()
	for _, fail := range []bool{false, true} {
		store := &memoryStore{value: domain.Adoption{MAC: identity().MAC, CFGVersion: "old-version", AuthKey: "0123456789abcdef0123456789abcdef"}}
		recorded := false
		worker := &usecase.Worker{ID: "edge", Source: healthySource{}, Publisher: configurationPublisher{}, Store: store, Timeout: time.Second, MonitorOnly: true}
		worker.RecordProvisioning = func(data []byte, version string) error {
			if store.value.CFGVersion != "old-version" || version != "new-version" || len(data) == 0 {
				t.Fatal("acknowledged before storing the virtual configuration")
			}
			if fail {
				return errors.New("disk full")
			}
			recorded = true
			return nil
		}
		worker.Plan = func(context.Context, []byte, string) error {
			t.Fatal("monitoring mode called configuration sync")
			return nil
		}
		result, err := worker.Cycle(t.Context())
		if fail {
			if err == nil || store.value.CFGVersion != "old-version" {
				t.Fatal("failed persistence was acknowledged")
			}
		} else if err != nil || !recorded || store.value.CFGVersion != "new-version" || store.value.PendingCFGVersion != "" || result.Provisioning != "monitoring" {
			t.Fatalf("virtual configuration not accepted: %v", err)
		}
	}
}
