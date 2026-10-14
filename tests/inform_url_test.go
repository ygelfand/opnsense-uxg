package framework_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

func TestInformURLResolution(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"https://192.0.2.1:8080/inform", "https://[2001:db8::1]:8080/inform"} {
		got, err := unifi.ResolveInformURL(t.Context(), raw)
		if err != nil || got != raw {
			t.Fatalf("literal URL changed: %q, %v", got, err)
		}
	}
	got, err := unifi.ResolveInformURL(t.Context(), "https://localhost:8080/inform?test=1")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil || net.ParseIP(u.Hostname()) == nil || u.Port() != "8080" || u.Scheme != "https" || u.Path != "/inform" || u.RawQuery != "test=1" {
		t.Fatal("resolution did not preserve URL components")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := unifi.ResolveInformURL(ctx, "https://localhost/inform"); err == nil {
		t.Fatal("cancelled resolution accepted")
	}
}

// Synthetic transport test: the wire URL is numeric but HTTP retains its host.
func TestPublisherSeparatesReportedAndTransportURLs(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host, _, err := net.SplitHostPort(r.Host); err != nil || host != "localhost" {
			t.Error("transport hostname was replaced")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		plain, err := unifi.DecodePacket(body, "")
		if err != nil {
			t.Error(err)
			return
		}
		var payload struct {
			URL string `json:"inform_url"`
		}
		if err := json.Unmarshal(plain, &payload); err != nil {
			t.Error(err)
			return
		}
		u, err := url.Parse(payload.URL)
		if err != nil || net.ParseIP(u.Hostname()) == nil {
			t.Error("reported inform URL was not an IP literal")
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = net.JoinHostPort("localhost", u.Port())
	p := &unifi.Publisher{Identity: identity(), Bindings: bindings(), URL: u.String(), Client: srv.Client(), StartedAt: time.Now()}
	snap, err := (healthySource{}).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ex, err := p.Publish(t.Context(), snap, domain.Adoption{MAC: identity().MAC})
	if err != nil || ex.HTTPStatus != http.StatusNotFound {
		t.Fatalf("publish failed: %v", err)
	}
}
