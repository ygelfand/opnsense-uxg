package framework_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

type configurationRepo struct {
	objects      []domain.ConfigObject
	writes       int
	failAt       int
	reconfigured []string
}

func (r *configurationRepo) Configuration(_ context.Context, kinds []string) ([]domain.ConfigObject, error) {
	return append([]domain.ConfigObject{}, r.objects...), nil
}
func (r *configurationRepo) CreateConfiguration(_ context.Context, object domain.ConfigObject) (string, error) {
	r.writes++
	if r.writes == r.failAt {
		return "", errors.New("write failed")
	}
	r.objects = append(r.objects, object)
	return "test-uuid", nil
}
func (r *configurationRepo) ReconfigureConfiguration(_ context.Context, kind string) error {
	r.reconfigured = append(r.reconfigured, kind)
	return nil
}

func configurationPolicy() usecase.ConfigurationPolicy {
	return usecase.ConfigurationPolicy{AllowedParents: []string{"igc1"}, AllowedTags: []int{10}, AllowedSubnets: map[string]string{"subnet-test": "198.51.100.0/24"}, AliasPrefix: "uxg_", AllowedNetworks: []string{"198.51.100.0/24"}}
}

func desiredConfiguration() []domain.ConfigObject {
	return []domain.ConfigObject{
		{Kind: "vlan", Fields: map[string]string{"parent": "igc1", "tag": "10", "description": "Clients"}},
		{Kind: "reservation", Fields: map[string]string{"subnet": "subnet-test", "ip": "198.51.100.10", "mac": "02:00:00:00:00:10", "hostname": "client"}},
		{Kind: "alias", Fields: map[string]string{"name": "uxg_clients", "type": "host", "content": "198.51.100.10\n198.51.100.11"}},
	}
}

func TestConfigurationPlanningApplyAndPolicy(t *testing.T) {
	t.Parallel()
	plan, err := usecase.BuildConfigurationPlan(identity(), "https://192.0.2.10", "pending", desiredConfiguration(), nil, configurationPolicy())
	if err != nil || len(plan.Additions) != 3 {
		t.Fatalf("configuration plan = %+v, %v", plan, err)
	}
	repo := &configurationRepo{}
	var recorded []string
	result, err := usecase.ApplyConfigurationPlan(t.Context(), repo, plan, identity(), plan.SourceURL, configurationPolicy(), func(r domain.ConfigurationApplyResult) error { recorded = append(recorded, r.Stage); return nil })
	if err != nil || !result.Verified || repo.writes != 3 || len(repo.reconfigured) != 3 || len(recorded) < 6 {
		t.Fatalf("apply result = %+v, %v, writes %d", result, err, repo.writes)
	}
	if _, err := usecase.ApplyConfigurationPlan(t.Context(), repo, plan, identity(), plan.SourceURL, configurationPolicy(), nil); err == nil || repo.writes != 3 {
		t.Error("changed inventory was written twice")
	}
	for _, object := range []domain.ConfigObject{
		{Kind: "vlan", Fields: map[string]string{"parent": "igc0", "tag": "10"}},
		{Kind: "vlan", Fields: map[string]string{"parent": "igc1", "tag": "20"}},
		{Kind: "reservation", Fields: map[string]string{"subnet": "subnet-test", "ip": "203.0.113.10", "mac": "02:00:00:00:00:10"}},
		{Kind: "alias", Fields: map[string]string{"name": "existing_alias", "type": "host", "content": "198.51.100.10"}},
		{Kind: "alias", Fields: map[string]string{"name": "uxg_remote", "type": "urltable", "content": "https://example.net"}},
	} {
		if _, err := usecase.BuildConfigurationPlan(identity(), plan.SourceURL, "", []domain.ConfigObject{object}, nil, configurationPolicy()); err == nil {
			t.Errorf("unauthorized object accepted: %+v", object)
		}
	}
	noOp, err := usecase.BuildConfigurationPlan(identity(), plan.SourceURL, "", desiredConfiguration(), repo.objects, configurationPolicy())
	if err != nil || len(noOp.Additions) != 0 {
		t.Errorf("existing desired state was not a no-op: %+v, %v", noOp, err)
	}
}

func TestConfigurationExtractionAndJournalFailure(t *testing.T) {
	t.Parallel()
	extractors := []usecase.ConfigurationExtractor{{Kind: "vlan", Path: []string{"udapi", "interfaces"}, Fields: map[string]string{"parent": "port", "tag": "vid"}, Values: map[string]map[string]string{"parent": {"eth0": "igc1"}}}}
	objects, err := usecase.ExtractConfiguration([]byte(`{"udapi":{"interfaces":[{"port":"eth0","vid":10}]}}`), extractors)
	if err != nil || len(objects) != 1 || objects[0].Fields["parent"] != "igc1" || objects[0].Fields["tag"] != "10" {
		t.Fatalf("controller projection = %+v, %v", objects, err)
	}
	plan, err := usecase.BuildConfigurationPlan(identity(), "https://192.0.2.10", "", objects, nil, configurationPolicy())
	if err != nil {
		t.Fatal(err)
	}
	repo := &configurationRepo{}
	if _, err := usecase.ApplyConfigurationPlan(t.Context(), repo, plan, identity(), plan.SourceURL, configurationPolicy(), func(domain.ConfigurationApplyResult) error { return errors.New("disk full") }); err == nil || repo.writes != 0 {
		t.Error("failed journal permitted mutation")
	}
	plan.Kinds = nil
	if _, err := usecase.ApplyConfigurationPlan(t.Context(), repo, plan, identity(), plan.SourceURL, configurationPolicy(), nil); err == nil {
		t.Error("forged inventory scope accepted")
	}
	if _, err := usecase.ExtractConfiguration([]byte(`{"udapi":{}}`), extractors); err == nil {
		t.Error("missing configuration treated as an empty desired state")
	}
	if !reflect.DeepEqual(objects[0].Fields, map[string]string{"parent": "igc1", "tag": "10"}) {
		t.Error("planning mutated input fields")
	}
}

type provisioningPublisher struct{}

func (provisioningPublisher) Publish(_ context.Context, _ domain.Snapshot, state domain.Adoption) (domain.Exchange, error) {
	return domain.Exchange{HTTPStatus: 200, Adoption: state, SystemConfig: []byte(`{"udapi":{}}`), RequestedCFGVersion: "pending-new"}, nil
}

func TestNewProvisioningInvalidatesOldPlansBeforeRejection(t *testing.T) {
	t.Parallel()
	invalidated := false
	store := &memoryStore{value: domain.Adoption{MAC: identity().MAC, CFGVersion: "applied"}}
	worker := &usecase.Worker{ID: "edge", Source: healthySource{}, Publisher: provisioningPublisher{}, Store: store, Timeout: time.Minute,
		InvalidatePlans: func() error { invalidated = true; return nil },
		Plan: func(context.Context, []byte, string) error {
			if !invalidated {
				t.Error("planner ran before invalidation")
			}
			return errors.New("unsupported new configuration")
		}}
	result, err := worker.Cycle(t.Context())
	if err == nil || !invalidated || result.Provisioning != "plan_rejected" || store.value.PendingCFGVersion != "pending-new" || store.value.CFGVersion != "applied" {
		t.Fatalf("new provisioning was mishandled: %+v, %v", result, err)
	}
}
