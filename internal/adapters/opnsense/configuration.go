package opnsense

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/browningluke/opnsense-go/pkg/api"
	"github.com/browningluke/opnsense-go/pkg/firewall"
	"github.com/browningluke/opnsense-go/pkg/interfaces"
	"github.com/browningluke/opnsense-go/pkg/kea"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

var featureEndpoints = map[string]struct{ search, add, reconfigure, monad string }{
	"vlan":        {search: "/interfaces/vlan_settings/searchItem", add: interfaces.VlanOpts.AddEndpoint, reconfigure: interfaces.VlanOpts.ReconfigureEndpoint, monad: "vlan"},
	"reservation": {search: "/kea/dhcpv4/search_reservation", add: kea.ReservationV4Opts.AddEndpoint, reconfigure: kea.ReservationV4Opts.ReconfigureEndpoint, monad: "reservation"},
	"alias":       {search: "/firewall/alias/searchItem", add: firewall.AliasOpts.AddEndpoint, reconfigure: firewall.AliasOpts.ReconfigureEndpoint, monad: "alias"},
}

// Configuration collects typed inventories for local reconciliation.
func (c *Client) Configuration(ctx context.Context, kinds []string) ([]domain.ConfigObject, error) {
	objects := []domain.ConfigObject{}
	for _, kind := range kinds {
		endpoints, ok := featureEndpoints[kind]
		if !ok {
			return nil, fmt.Errorf("unsupported configuration feature")
		}
		var response struct {
			Total *api.Int64 `json:"total"`
			Rows  []struct {
				UUID string `json:"uuid"`
			} `json:"rows"`
		}
		if err := c.request(ctx, httpGET, endpoints.search+"?rowCount=-1", nil, &response); err != nil {
			return nil, err
		}
		if response.Total == nil || response.Rows == nil || int64(*response.Total) != int64(len(response.Rows)) || len(response.Rows) > 10000 {
			return nil, fmt.Errorf("configuration inventory is incomplete")
		}
		for _, row := range response.Rows {
			if !safeID(row.UUID) {
				return nil, fmt.Errorf("invalid configuration UUID")
			}
			object := domain.ConfigObject{Kind: kind, Fields: map[string]string{}}
			switch kind {
			case "vlan":
				v, err := c.sdk.Interfaces().GetVlan(ctx, row.UUID)
				if err != nil {
					return nil, err
				}
				object.Key = string(v.Parent) + "/" + v.Tag
				object.Fields = map[string]string{"parent": string(v.Parent), "tag": v.Tag, "description": v.Description}
			case "reservation":
				v, err := c.sdk.Kea().GetReservationV4(ctx, row.UUID)
				if err != nil {
					return nil, err
				}
				mac := neighbor(v.IpAddress, v.HwAddress, "", "", "").MAC
				object.Key = string(v.Subnet) + "/" + mac
				object.Fields = map[string]string{"subnet": string(v.Subnet), "mac": mac, "ip": v.IpAddress, "hostname": v.Hostname, "description": v.Description}
			case "alias":
				v, err := c.sdk.Firewall().GetAlias(ctx, row.UUID)
				if err != nil {
					return nil, err
				}
				values := append([]string{}, v.Content...)
				sort.Strings(values)
				object.Key = v.Name
				object.Disabled = v.Enabled != "1"
				object.Fields = map[string]string{"name": v.Name, "type": string(v.Type), "content": strings.Join(values, "\n"), "description": v.Description}
			}
			objects = append(objects, object)
		}
	}
	return objects, nil
}

// CreateConfiguration saves one object for an explicit reconfigure step.
func (c *Client) CreateConfiguration(ctx context.Context, object domain.ConfigObject) (string, error) {
	endpoints, ok := featureEndpoints[object.Kind]
	if !ok {
		return "", fmt.Errorf("unsupported configuration feature")
	}
	f := object.Fields
	var resource any
	switch object.Kind {
	case "vlan":
		resource = interfaces.Vlan{Parent: api.SelectedMap(f["parent"]), Tag: f["tag"], Description: f["description"]}
	case "reservation":
		resource = kea.ReservationV4{Subnet: api.SelectedMap(f["subnet"]), HwAddress: f["mac"], IpAddress: f["ip"], Hostname: f["hostname"], Description: f["description"]}
	case "alias":
		resource = firewall.Alias{Enabled: "1", Name: f["name"], Type: api.SelectedMap(f["type"]), Content: api.SelectedMapListNL(strings.Split(f["content"], "\n")), Description: f["description"]}
	}
	var response struct {
		Result string `json:"result"`
		UUID   string `json:"uuid"`
	}
	if err := c.request(ctx, http.MethodPost, endpoints.add, map[string]any{endpoints.monad: resource}, &response); err != nil {
		return "", err
	}
	if response.Result != "saved" || response.UUID == "" {
		return "", fmt.Errorf("OPNsense rejected configuration addition")
	}
	return response.UUID, nil
}

// ReconfigureConfiguration activates saved changes for one feature.
func (c *Client) ReconfigureConfiguration(ctx context.Context, kind string) error {
	endpoints, ok := featureEndpoints[kind]
	if !ok {
		return fmt.Errorf("unsupported configuration feature")
	}
	var response struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if err := c.request(ctx, http.MethodPost, endpoints.reconfigure, struct{}{}, &response); err != nil {
		return err
	}
	if response.Status != "ok" && response.Result != "ok" {
		return fmt.Errorf("configuration reconfigure failed")
	}
	return nil
}
