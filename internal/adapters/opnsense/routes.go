package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/browningluke/opnsense-go/pkg/api"
	sdkroutes "github.com/browningluke/opnsense-go/pkg/routes"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// Routes retrieves the complete configured static-route inventory for planning.
func (c *Client) Routes(ctx context.Context) ([]domain.Route, error) {
	var result struct {
		Total *int `json:"total"`
		Rows  []struct {
			Network     string          `json:"network"`
			Gateway     string          `json:"gateway"`
			Description string          `json:"descr"`
			Disabled    json.RawMessage `json:"disabled"`
			Enabled     json.RawMessage `json:"enabled"`
		} `json:"rows"`
	}
	if err := c.request(ctx, httpGET, "/routes/routes/searchroute?rowCount=-1", nil, &result); err != nil {
		return nil, err
	}
	if result.Total == nil || result.Rows == nil || len(result.Rows) != *result.Total {
		return nil, fmt.Errorf("route inventory is incomplete")
	}
	routes := make([]domain.Route, 0, len(result.Rows))
	for _, row := range result.Rows {
		disabled, err := routeDisabled(row.Disabled, row.Enabled)
		if err != nil {
			return nil, err
		}
		routes = append(routes, domain.Route{Network: row.Network, Gateway: row.Gateway, Description: row.Description, Disabled: disabled})
	}
	return routes, nil
}

func routeDisabled(disabled, enabled json.RawMessage) (bool, error) {
	parse := func(raw json.RawMessage) (bool, bool) {
		switch string(raw) {
		case `"1"`, "1", "true":
			return true, true
		case `"0"`, "0", "false":
			return false, true
		default:
			return false, false
		}
	}
	if d, ok := parse(disabled); ok {
		if e, known := parse(enabled); known && d == e {
			return false, fmt.Errorf("contradictory route enabled state")
		}
		return d, nil
	}
	if e, ok := parse(enabled); ok {
		return !e, nil
	}
	return false, fmt.Errorf("route inventory omitted enabled state")
}

// AddRoute saves a static route and returns the appliance-generated UUID.
func (c *Client) AddRoute(ctx context.Context, route domain.Route) (string, error) {
	resource := sdkroutes.Route{Enabled: "1", Disabled: "0", Description: route.Description, Gateway: api.SelectedMap(route.Gateway), Network: route.Network}
	var response struct {
		Result string `json:"result"`
		UUID   string `json:"uuid"`
	}
	if err := c.request(ctx, http.MethodPost, sdkroutes.RouteOpts.AddEndpoint, map[string]sdkroutes.Route{"route": resource}, &response); err != nil {
		return "", fmt.Errorf("route addition failed; inspect appliance before retry: %w", err)
	}
	if response.Result != "saved" || response.UUID == "" {
		return "", fmt.Errorf("OPNsense rejected route addition")
	}
	return response.UUID, nil
}

// ReconfigureRoutes activates the appliance's saved static-route configuration.
func (c *Client) ReconfigureRoutes(ctx context.Context) error {
	var response struct {
		Status string `json:"status"`
	}
	if err := c.request(ctx, http.MethodPost, sdkroutes.RouteOpts.ReconfigureEndpoint, struct{}{}, &response); err != nil {
		return err
	}
	if response.Status != "ok" {
		return fmt.Errorf("route reconfiguration failed")
	}
	return nil
}
