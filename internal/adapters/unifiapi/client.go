// Package unifiapi mirrors source inventory into controller-owned definitions.
package unifiapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/transport"
)

var errorCodePattern = regexp.MustCompile(`^api\.err\.[A-Za-z0-9_.]+$`)

// OwnedNetwork tracks only controller fields managed by this bridge.
type OwnedNetwork struct {
	ID      string         `json:"id"`
	Fields  map[string]any `json:"fields"`
	Pending bool           `json:"pending,omitempty"`
}

// State binds controller inventory ownership to one adopted virtual identity.
type State struct {
	URL         string                  `json:"url"`
	Site        string                  `json:"site"`
	MAC         string                  `json:"mac"`
	Networks    map[string]OwnedNetwork `json:"networks"`
	Assignments []map[string]any        `json:"assignments,omitempty"`
}

// Client owns a single gateway's inventory sync; methods run sequentially.
type Client struct {
	PeerMAC       string
	URL           string
	Key           string
	Site          string
	Prefix        string
	HTTP          *http.Client
	Identity      domain.Identity
	Bindings      []domain.Binding
	DisabledPorts []int
	SyncWANs      bool
	SyncVLANs     bool
	NativeVLAN    int
	Load          func() (State, error)
	Save          func(State) error
	resolvedSite  string
	nextSync      time.Time
	last          domain.InventorySync
}

type device struct {
	Mode        string           `json:"device_mode_override"`
	Type        string           `json:"type"`
	ID          string           `json:"_id"`
	MAC         string           `json:"mac"`
	Model       string           `json:"model"`
	Adopted     bool             `json:"adopted"`
	Assignments []map[string]any `json:"ethernet_overrides"`
}

func (c *Client) request(ctx context.Context, method, path string, value, output any) error {
	var body []byte
	var err error
	if value != nil {
		body, err = json.Marshal(value)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.URL, "/")+c.Prefix+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.Key)
	req.Header.Set("Accept", "application/json")
	if value != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("controller inventory request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := transport.ReadBody(resp.Body)
	if err != nil {
		return err
	}
	var meta struct {
		Meta struct {
			RC  string `json:"rc"`
			Msg string `json:"msg"`
		} `json:"meta"`
	}
	decodeErr := json.Unmarshal(b, &meta)
	if resp.StatusCode/100 != 2 || meta.Meta.RC != "" && meta.Meta.RC != "ok" {
		if errorCodePattern.MatchString(meta.Meta.Msg) {
			return fmt.Errorf("controller inventory %s returned HTTP %d: %s", method, resp.StatusCode, meta.Meta.Msg)
		}
		return fmt.Errorf("controller inventory %s returned HTTP %d or rejected the request", method, resp.StatusCode)
	}
	if decodeErr != nil {
		return fmt.Errorf("decode controller inventory response: %w", decodeErr)
	}
	if output != nil {
		return json.Unmarshal(b, output)
	}
	return nil
}

func sitePath(site string) string { return "/api/s/" + url.PathEscape(site) }

func (c *Client) findDevice(ctx context.Context) (device, string, error) {
	sites := []string{c.Site}
	if c.resolvedSite != "" {
		sites = []string{c.resolvedSite}
	} else if c.Site == "" {
		var result struct {
			Data []struct {
				Name string `json:"name"`
			} `json:"data"`
		}
		if err := c.request(ctx, http.MethodGet, "/api/self/sites", nil, &result); err != nil {
			return device{}, "", err
		}
		sites = nil
		for _, s := range result.Data {
			if s.Name != "" && s.Name != "." && s.Name != ".." {
				sites = append(sites, s.Name)
			}
		}
	}
	var found device
	var foundSite string
	for _, site := range sites {
		var result struct {
			Data []device `json:"data"`
		}
		if err := c.request(ctx, http.MethodGet, sitePath(site)+"/stat/device", nil, &result); err != nil {
			return device{}, "", err
		}
		for _, d := range result.Data {
			if !strings.EqualFold(d.MAC, c.Identity.MAC) {
				continue
			}
			if foundSite != "" {
				return device{}, "", fmt.Errorf("virtual gateway exists in multiple controller sites")
			}
			if !d.Adopted || d.ID == "" || d.Model != c.Identity.Model {
				return device{}, "", fmt.Errorf("controller device identity or adoption does not match")
			}
			found, foundSite = d, site
		}
		if foundSite == site {
			for _, d := range result.Data {
				if d.Adopted && !strings.EqualFold(d.MAC, c.Identity.MAC) && (d.Type == "uxg" || d.Type == "ugw" || d.Type == "udm") {
					managedPeer := d.Mode == "managed_shadow_gateway" || found.Mode == "managed_shadow_gateway"
					if c.Identity.Model == "UXGENT" && strings.EqualFold(d.MAC, c.PeerMAC) && d.Model == c.Identity.Model && managedPeer {
						continue
					}
					return device{}, "", fmt.Errorf("controller site contains another adopted gateway")
				}
			}
		}
	}
	if foundSite == "" {
		return device{}, "", fmt.Errorf("adopted virtual gateway not found on controller")
	}
	c.resolvedSite = foundSite
	return found, foundSite, nil
}
