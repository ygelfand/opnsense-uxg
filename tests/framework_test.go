// These synthetic HTTP/protocol cases verify bridge behavior. They are not
// vendor captures and do not establish real-device/controller compatibility.
package framework_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/filestate"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/opnsense"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/config"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/transport"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

func identity() domain.Identity {
	return domain.Identity{ID: "edge", MAC: "02:00:00:00:00:01", Hostname: "edge", Model: "UXG", ManagementIP: "192.0.2.10"}
}

func bindings() []domain.Binding {
	return []domain.Binding{{Port: 1, Interface: "igc1", Role: "lan"}, {Port: 2, Interface: "igc0", Role: "wan"}}
}

const interfaceJSON = `{"igc0":{"device":"igc0","macaddr":"02:00:00:00:00:10","status":"active","media":"Ethernet autoselect (2500base-T <full-duplex>)","ipv4":[{"ipaddr":"192.0.2.10","subnetbits":24}]},"igc1":{"device":"igc1","macaddr":"02:00:00:00:00:11","status":"no carrier","ipv4":[]}}`

func TestObservedStateAndUnknownMeasurements(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, secret, ok := r.BasicAuth()
		if !ok || key != "test-key" || secret != "test-secret" || r.Method != "GET" {
			t.Errorf("request authentication/method = %v/%q, want test auth/GET", ok, r.Method)
		}
		switch r.URL.Path {
		case "/api/diagnostics/interface/getInterfaceConfig":
			_, _ = io.WriteString(w, interfaceJSON)
		case "/api/diagnostics/interface/getInterfaceStatistics":
			_, _ = io.WriteString(w, `{"statistics":{"wan":{"name":"igc0","received-bytes":0,"sent-bytes":73,"received-packets":0,"sent-packets":2}}}`)
		default:
			t.Errorf("unexpected endpoint %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	source := &opnsense.Source{Client: client, ID: "edge", Statistics: true}
	snap, err := source.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Interfaces) != 2 || snap.Interfaces[0].Counters.RXBytes == nil || *snap.Interfaces[0].Counters.RXBytes != 0 {
		t.Fatalf("measured zero counter lost: %+v", snap)
	}
	b, err := unifi.Render(identity(), bindings(), snap, domain.Adoption{MAC: identity().MAC}, "http://192.0.2.100:8080/inform", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"system-stats", "gw_caps", "internet_health"} {
		if _, ok := payload[field]; ok {
			t.Errorf("unexpected invented telemetry field %q", field)
		}
	}
	var rows []map[string]any
	if err := json.Unmarshal(payload["if_table"], &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0]["name"] != "eth0" || rows[0]["up"] != false || rows[1]["name"] != "eth1" || rows[1]["speed"] != float64(2500) {
		t.Fatalf("mapped rows = %+v", rows)
	}
	if _, ok := rows[0]["rx_bytes"]; ok {
		t.Error("unknown LAN counter became a measurement")
	}
	if rows[1]["rx_bytes"] != float64(0) {
		t.Error("measured WAN zero omitted")
	}
	var ports []map[string]any
	if err := json.Unmarshal(payload["port_table"], &ports); err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0]["up"] != false || ports[1]["rx_bytes"] != float64(0) {
		t.Fatal("gateway port observations did not preserve measured state")
	}
	if _, ok := ports[0]["rx_bytes"]; ok {
		t.Fatal("unknown port counter became a measurement")
	}
	if _, err := unifi.Render(identity(), []domain.Binding{{Port: 1, Interface: "missing", Role: "lan"}}, snap, domain.Adoption{}, "", time.Minute); err == nil {
		t.Error("missing mapped interface accepted")
	}
}

func TestPacketBoundsAndAuthentication(t *testing.T) {
	t.Parallel()
	for _, gcm := range []bool{false, true} {
		packet, err := unifi.EncodePacket(identity().MAC, "", gcm, []byte(`{"_type":"noop"}`))
		if err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint32(packet[4:8]) != 1 || binary.BigEndian.Uint32(packet[32:36]) != 1 {
			t.Error("incorrect TNBU version")
		}
		plain, err := unifi.DecodePacket(packet, "")
		if err != nil || string(plain) != `{"_type":"noop"}` {
			t.Fatalf("decode gcm=%v = %s, %v", gcm, plain, err)
		}
		if gcm {
			packet[8] ^= 1
			if _, err := unifi.DecodePacket(packet, ""); err == nil {
				t.Error("GCM accepted modified authenticated header")
			}
		}
	}
	packet, err := unifi.EncodePacket(identity().MAC, "", true, bytes.Repeat([]byte("x"), transport.MaxBody+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unifi.DecodePacket(packet, ""); err == nil {
		t.Error("unbounded decompression accepted")
	}
	if _, err := unifi.DecodePacket([]byte("TNBU"), ""); err == nil {
		t.Error("short packet accepted")
	}
}

func TestAdoptionRoundTripAndProvisioningHold(t *testing.T) {
	t.Parallel()
	const key = "0123456789abcdef0123456789abcdef"
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		packet, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		auth := ""
		if requestCount > 1 {
			auth = key
		}
		plain, err := unifi.DecodePacket(packet, auth)
		if err != nil {
			t.Error(err)
			http.Error(w, "decode", 400)
			return
		}
		var p struct {
			Default    bool   `json:"default"`
			CFG        string `json:"cfgversion"`
			AuthKey    string `json:"x_authkey"`
			DefaultKey bool   `json:"_default_key"`
		}
		if err := json.Unmarshal(plain, &p); err != nil {
			t.Error(err)
		}
		response := `{"_type":"noop","interval":1}`
		switch requestCount {
		case 1:
			if p.AuthKey != "ba86f2bbe107c7c57eb5f2690775c712" || !p.DefaultKey {
				t.Error("factory inform omitted default authentication fields")
			}
			if !p.Default {
				t.Error("factory inform was already adopted")
			}
			response = `{"_type":"setparam","mgmt_cfg":"authkey=` + key + `\nuse_aes_gcm=true\ncfgversion=adoption"}`
		case 2:
			if p.AuthKey != key || p.DefaultKey {
				t.Error("adopted inform did not carry the rotated authentication fields")
			}
			if p.Default || binary.BigEndian.Uint16(packet[14:16]) != 11 {
				t.Error("adopted request did not switch key/GCM")
			}
			response = `{"_type":"setparam","mgmt_cfg":"cfgversion=provisioning","system_cfg":"{\"udapi\":{}}"}`
		case 3:
			if p.CFG != "adoption" {
				t.Errorf("reported cfgversion = %q, want adoption", p.CFG)
			}
		}
		body, err := unifi.EncodePacket(identity().MAC, auth, requestCount > 1, []byte(response))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	store := &filestate.Store{Path: filepath.Join(t.TempDir(), "adoption.json"), MAC: identity().MAC}
	pub := &unifi.Publisher{Identity: identity(), Bindings: bindings(), URL: srv.URL, Client: srv.Client(), StartedAt: time.Now()}
	w := &usecase.Worker{ID: "edge", Source: healthySource{}, Publisher: pub, Store: store, Interval: 10 * time.Second, Timeout: time.Minute}
	capturePath := filepath.Join(filepath.Dir(store.Path), "pending-system-config.json")
	w.RecordProvisioning = func(data []byte, version string) error {
		if version != "provisioning" {
			t.Error("wrong captured configuration version")
		}
		return filestate.WriteJSON(capturePath, json.RawMessage(data))
	}
	for i := 0; i < 3; i++ {
		r, err := w.Cycle(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && r.Provisioning != "unsupported" {
			t.Errorf("provisioning = %q, want unsupported", r.Provisioning)
		}
		if i == 2 && r.NextDelay != 5*time.Second {
			t.Errorf("delay = %v, want 5s", r.NextDelay)
		}
	}
	a, err := store.Load()
	if err != nil || a.AuthKey != key || !a.UseGCM || a.CFGVersion != "adoption" {
		t.Fatalf("saved adoption = %+v, %v", a, err)
	}
	info, err := os.Stat(store.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state permission = %v, %v", info, err)
	}
	if _, err := (&filestate.Store{Path: store.Path, MAC: "02:00:00:00:00:02"}).Load(); err == nil {
		t.Error("different identity loaded adoption state")
	}
	captured, err := os.ReadFile(capturePath)
	if err != nil || strings.TrimSpace(string(captured)) != "{\n  \"udapi\": {}\n}" {
		t.Fatalf("pending configuration not recorded: %v", err)
	}
	info, err = os.Stat(capturePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pending configuration is not private: %v", err)
	}
}

type healthySource struct{}

func (healthySource) Collect(context.Context) (domain.Snapshot, error) {
	return domain.Snapshot{SourceID: "edge", ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "igc0", Addresses: []string{}}, {Name: "igc1", Addresses: []string{}}}}, nil
}

type failedSource struct{}

func (failedSource) Collect(context.Context) (domain.Snapshot, error) {
	return domain.Snapshot{}, errors.New("offline")
}

type memoryStore struct{ value domain.Adoption }

func (s *memoryStore) Load() (domain.Adoption, error) { return s.value, nil }
func (s *memoryStore) Save(a domain.Adoption) error   { s.value = a; return nil }

type countingPublisher struct{ calls int }

func (p *countingPublisher) Publish(_ context.Context, _ domain.Snapshot, a domain.Adoption) (domain.Exchange, error) {
	p.calls++
	return domain.Exchange{HTTPStatus: 200, Adoption: a}, nil
}

func TestSourceFailureIsolationAndShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		goodPub, badPub := &countingPublisher{}, &countingPublisher{}
		good := &usecase.Worker{ID: "edge", Source: healthySource{}, Publisher: goodPub, Store: &memoryStore{}, Timeout: time.Second, Interval: 5 * time.Second}
		bad := &usecase.Worker{ID: "offline", Source: failedSource{}, Publisher: badPub, Store: &memoryStore{}, Timeout: time.Second, Interval: 5 * time.Second}
		var wg sync.WaitGroup
		wg.Go(func() { usecase.Run(ctx, []*usecase.Worker{good, bad}, func(usecase.CycleResult, error) {}) })
		synctest.Wait()
		time.Sleep(11 * time.Second)
		cancel()
		wg.Wait()
		if goodPub.calls < 3 || badPub.calls != 0 {
			t.Errorf("publications good/bad = %d/%d, want >=3/0", goodPub.calls, badPub.calls)
		}
	})
}

func TestStrictConfigurationAndProcessLock(t *testing.T) {
	t.Parallel()
	c, err := config.Load("../config.example.yaml")
	if err != nil || len(c.Gateways) != 2 {
		t.Fatalf("example config = %+v, %v", c, err)
	}
	c.Gateways[1].Identity.MAC = c.Gateways[0].Identity.MAC
	if err := c.Validate(); err == nil {
		t.Error("duplicate MAC accepted")
	}
	for _, u := range []string{"http://192.0.2.1", "https://key:secret@192.0.2.1", "https://192.0.2.1/api", "https://192.0.2.1?token=x"} {
		if err := config.ValidateURL(u, true); err == nil {
			t.Errorf("source URL %q accepted", u)
		}
	}
	f, err := filestate.Lock(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if second, err := filestate.Lock(filepath.Dir(f.Name())); err == nil {
		_ = second.Close()
		t.Error("second process lock accepted")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("unknown_key: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Error("unknown YAML field accepted")
	}
}

func policy() usecase.RoutePolicy {
	return usecase.RoutePolicy{AllowedNetworks: []string{"198.51.100.0/24"}, GatewayMap: map[string]string{"192.0.2.1": "WAN_GW"}, ControllerPath: []string{"udapi", "routes/static"}, NetworkField: "destination", GatewayField: "next_hop"}
}

func TestRoutePolicyAndConflicts(t *testing.T) {
	t.Parallel()
	routes, err := usecase.ExtractRoutes([]byte(`{"udapi":{"routes/static":[{"destination":"198.51.100.0/25","next_hop":"192.0.2.1"}]}}`), policy())
	if err != nil {
		t.Fatal(err)
	}
	p, err := usecase.BuildRoutePlan(identity(), "pending", routes, nil, policy())
	if err != nil || len(p.Additions) != 1 {
		t.Fatalf("route plan = %+v, %v", p, err)
	}
	for _, network := range []string{"0.0.0.0/0", "203.0.113.0/24", "198.51.100.1/25", "198.51.100.0/23"} {
		if _, err := usecase.BuildRoutePlan(identity(), "", []domain.Route{{Network: network, Gateway: "WAN_GW"}}, nil, policy()); err == nil {
			t.Errorf("route %q accepted", network)
		}
	}
	for _, old := range []domain.Route{{Network: routes[0].Network, Gateway: "OTHER"}, {Network: routes[0].Network, Gateway: "WAN_GW", Disabled: true}} {
		if _, err := usecase.BuildRoutePlan(identity(), "", routes, []domain.Route{old}, policy()); err == nil {
			t.Errorf("conflicting route %+v accepted", old)
		}
	}
	if _, err := usecase.ExtractRoutes([]byte(`{"udapi":{}}`), policy()); err == nil {
		t.Error("missing route path accepted as empty desired config")
	}
}

func TestRouteApplyAndChangedBaseline(t *testing.T) {
	t.Parallel()
	inventory := []domain.Route{}
	var writes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/routes/routes/searchroute":
			rows := make([]map[string]string, 0, len(inventory))
			for _, v := range inventory {
				rows = append(rows, map[string]string{"network": v.Network, "gateway": v.Gateway, "descr": v.Description, "disabled": "0"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total": len(rows), "rows": rows})
		case "/api/routes/routes/addroute":
			if r.Method != "POST" {
				t.Error("route addition was not POST")
			}
			var body struct {
				Route struct {
					Network     string `json:"network"`
					Gateway     string `json:"gateway"`
					Description string `json:"descr"`
				} `json:"route"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			inventory = append(inventory, domain.Route{Network: body.Route.Network, Gateway: body.Route.Gateway, Description: body.Route.Description})
			writes++
			_, _ = io.WriteString(w, `{"result":"saved","uuid":"test-route-uuid"}`)
		case "/api/routes/routes/reconfigure":
			writes++
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		default:
			t.Errorf("unexpected endpoint %q", r.URL.Path)
		}
	}))
	defer srv.Close()
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := usecase.BuildRoutePlan(identity(), "", []domain.Route{{Network: "198.51.100.0/25", Gateway: "WAN_GW", Description: "test"}}, nil, policy())
	if err != nil {
		t.Fatal(err)
	}
	plan.SourceURL = srv.URL
	options := usecase.ApplyOptions{Plan: plan, Identity: identity(), SourceURL: srv.URL, Policy: policy()}
	result, err := usecase.ApplyRoutePlan(t.Context(), client, options)
	if err != nil || !result.Verified || !result.Reconfigured || len(result.AddedUUIDs) != 1 {
		t.Fatalf("apply result = %+v, %v", result, err)
	}
	if _, err := usecase.ApplyRoutePlan(t.Context(), client, options); err == nil {
		t.Error("stale plan applied")
	}
	if writes != 2 {
		t.Errorf("writes = %d, want 2", writes)
	}
	plan.SourceURL = "https://192.0.2.99"
	options.Plan = plan
	if _, err := usecase.ApplyRoutePlan(t.Context(), client, options); err == nil {
		t.Error("wrong appliance plan accepted")
	}
}

func TestAPIRejectsErrorsAndIncompleteInventory(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{}`, `{"total":2,"rows":[]}`, `{"total":1,"rows":[{"network":"198.51.100.0/25","gateway":"WAN_GW"}]}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
			defer srv.Close()
			client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Routes(t.Context()); err == nil {
				t.Errorf("inventory %s accepted", body)
			}
		})
	}
	if _, err := transport.ReadBody(strings.NewReader(strings.Repeat("x", transport.MaxBody+1))); err == nil {
		t.Error("oversized API body accepted")
	}
	if _, err := unifi.ParseResponse([]byte(fmt.Sprintf(`{"_type":"setparam","mgmt_cfg":"authkey=%s"}`, "bad")), domain.Exchange{}); err == nil {
		t.Error("malformed adoption key accepted")
	}
}
