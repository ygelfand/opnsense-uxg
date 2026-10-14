package framework_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

type routeRepo struct {
	routes []domain.Route
	writes int
	failAt int
}

func (r *routeRepo) Routes(context.Context) ([]domain.Route, error) {
	return append([]domain.Route{}, r.routes...), nil
}
func (r *routeRepo) AddRoute(_ context.Context, route domain.Route) (string, error) {
	r.writes++
	if r.writes == r.failAt {
		return "", errors.New("write unavailable")
	}
	r.routes = append(r.routes, route)
	return "test-uuid", nil
}
func (*routeRepo) ReconfigureRoutes(context.Context) error { return nil }

func TestApplyJournalsBeforeWritesAndRetainsPartialResults(t *testing.T) {
	t.Parallel()
	desired := []domain.Route{{Network: "198.51.100.0/25", Gateway: "WAN_GW"}, {Network: "198.51.100.128/25", Gateway: "WAN_GW"}}
	plan, err := usecase.BuildRoutePlan(identity(), "pending", desired, nil, policy())
	if err != nil {
		t.Fatal(err)
	}
	plan.SourceURL = "https://192.0.2.10"
	repo := &routeRepo{failAt: 2}
	var records []domain.RouteApplyResult
	opts := usecase.ApplyOptions{Plan: plan, Identity: identity(), SourceURL: plan.SourceURL, Policy: policy(), Record: func(r domain.RouteApplyResult) error {
		if r.Stage == "adding" && repo.writes >= len(records)+1 {
			t.Error("journal ran after mutation")
		}
		r.AddedUUIDs = append([]string{}, r.AddedUUIDs...)
		records = append(records, r)
		return nil
	}}
	result, err := usecase.ApplyRoutePlan(t.Context(), repo, opts)
	if err == nil || len(result.AddedUUIDs) != 1 || result.InFlightNetwork != desired[1].Network || result.Verified {
		t.Fatalf("partial apply result = %+v, %v", result, err)
	}
	if len(records) != 3 || records[0].InFlightNetwork != desired[0].Network || len(records[1].AddedUUIDs) != 1 {
		t.Fatalf("journal records = %+v", records)
	}
	repo = &routeRepo{}
	opts.Record = func(domain.RouteApplyResult) error { return errors.New("disk full") }
	if _, err := usecase.ApplyRoutePlan(t.Context(), repo, opts); err == nil || repo.writes != 0 {
		t.Fatalf("failed journal allowed writes = %d, error %v", repo.writes, err)
	}
}
