// Package opnsense collects appliance state and implements reviewed route additions.
package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/browningluke/opnsense-go/pkg/api"
	sdk "github.com/browningluke/opnsense-go/pkg/opnsense"
	"github.com/ygelfand/opnsense-uxg/internal/transport"
)

// Client binds all requests and credentials to one appliance.
type Client struct {
	url    string
	key    string
	secret string
	http   *http.Client
	api    *api.Client
	sdk    sdk.Client
}

// NewClient uses the supplied HTTP client, allowing private CAs and test servers.
func NewClient(url, key, secret string, client *http.Client) (*Client, error) {
	if key == "" || secret == "" || client == nil {
		return nil, fmt.Errorf("OPNsense credentials and HTTP client are required")
	}
	base := strings.TrimRight(url, "/")
	a := api.NewClient(api.Options{Uri: base, APIKey: key, APISecret: secret, HTTPClient: client, MaxResponseBytes: transport.MaxBody, SuppressBodyLogging: true, DisableRetries: true, Logger: log.New(io.Discard, "", 0)})
	return &Client{url: base, key: key, secret: secret, http: client, api: a, sdk: sdk.NewClient(a)}, nil
}

func (c *Client) request(ctx context.Context, method, path string, body any, out any) error {
	u, err := url.Parse(path)
	if err != nil {
		return err
	}
	query := map[string]string{}
	for key, values := range u.Query() {
		if len(values) != 1 {
			return fmt.Errorf("duplicate API query field")
		}
		query[key] = values[0]
	}
	opts := api.RPCOpts{BaseEndpoint: u.Path, Method: method, QueryParameters: query}
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("API body must be an object: %w", err)
		}
		opts.BodyParameters = make(map[string]any, len(fields))
		for key, value := range fields {
			opts.BodyParameters[key] = value
		}
	}
	_, err = api.Call(c.api, ctx, opts, &out)
	return err
}
