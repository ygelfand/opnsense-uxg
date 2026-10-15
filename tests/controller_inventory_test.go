package framework_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifiapi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

type inventoryServer struct {
	mu              sync.Mutex
	networks        []map[string]any
	assignments     []map[string]any
	writes          int
	posts           int
	loseCreateReply bool
}

func (s *inventoryServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.Header.Get("X-API-KEY") != "test-key" {
			t.Error("missing API authentication")
		}
		result := map[string]any{"meta": map[string]any{"rc": "ok"}, "data": []any{}}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/self/sites":
			result["data"] = []any{map[string]any{"name": "test-site"}}
		case r.Method == http.MethodGet && r.URL.Path == "/api/s/test-site/stat/device":
			result["data"] = []any{map[string]any{"_id": "virtual-device", "mac": identity().MAC, "model": "UXG", "adopted": true, "ethernet_overrides": s.assignments}}
		case r.Method == http.MethodGet && r.URL.Path == "/api/s/test-site/rest/networkconf":
			result["data"] = s.networks
		case r.Method == http.MethodPost && r.URL.Path == "/api/s/test-site/rest/networkconf":
			var n map[string]any
			if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
				t.Error(err)
				return
			}
			s.posts++
			s.writes++
			n["_id"] = fmt.Sprintf("wan-%d", s.posts)
			s.networks = append(s.networks, n)
			result["data"] = []any{n}
			if s.loseCreateReply {
				s.loseCreateReply = false
				w.WriteHeader(500)
				return
			}
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/s/test-site/rest/networkconf/"):
			var fields map[string]any
			if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
				t.Error(err)
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/api/s/test-site/rest/networkconf/")
			found := false
			for _, n := range s.networks {
				if n["_id"] == id {
					for k, v := range fields {
						n[k] = v
					}
					found = true
				}
			}
			if !found {
				t.Error("updated unknown network")
			}
			s.writes++
		case r.Method == http.MethodPut && r.URL.Path == "/api/s/test-site/rest/device/virtual-device":
			var fields struct {
				Assignments []map[string]any `json:"ethernet_overrides"`
			}
			if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
				t.Error(err)
				return
			}
			s.assignments = fields.Assignments
			s.writes++
		default:
			t.Errorf("unexpected inventory request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(result); err != nil {
			t.Error(err)
		}
	}
}

func inventorySnapshot() domain.Snapshot {
	return domain.Snapshot{SourceID: "edge", ObservedAt: time.Now(), Interfaces: []domain.Interface{{Name: "source-wan", Description: "Internet", IPv4Mode: "dhcp"}}}
}

func inventoryClient(srv *httptest.Server, state *unifiapi.State) *unifiapi.Client {
	c := &unifiapi.Client{URL: srv.URL, Key: "test-key", HTTP: srv.Client(), Identity: identity(), Bindings: []domain.Binding{{Port: 1, Interface: "source-wan", Role: "wan"}}, SyncWANs: true}
	c.Load = func() (unifiapi.State, error) {
		var v unifiapi.State
		b, err := json.Marshal(state)
		if err != nil {
			return v, err
		}
		err = json.Unmarshal(b, &v)
		return v, err
	}
	c.Save = func(v unifiapi.State) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return json.Unmarshal(b, state)
	}
	return c
}

func TestControllerInventorySeedsAndReconcilesOnlyOwnedFields(t *testing.T) {
	t.Parallel()
	app := &inventoryServer{networks: []map[string]any{{"_id": "unrelated-lan", "purpose": "corporate", "name": "Internal"}}, assignments: []map[string]any{{"ifname": "eth1", "networkgroup": "LAN", "extra": "preserve"}}}
	srv := httptest.NewServer(app.handler(t))
	defer srv.Close()
	var state unifiapi.State
	snap := inventorySnapshot()
	r, err := inventoryClient(srv, &state).Sync(t.Context(), snap)
	if err != nil || r.Created != 1 || !r.AssignmentsUpdated {
		t.Fatalf("initial inventory sync: %v", err)
	}
	r, err = inventoryClient(srv, &state).Sync(t.Context(), snap)
	if err != nil || r.Created != 0 || r.Updated != 0 || r.AssignmentsUpdated {
		t.Fatalf("sync was not idempotent: %v", err)
	}
	snap.Interfaces[0].Description = "Renamed source"
	r, err = inventoryClient(srv, &state).Sync(t.Context(), snap)
	if err != nil || r.Updated != 1 {
		t.Fatalf("owned name did not reconcile: %v", err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.networks[0]["name"] != "Internal" || app.assignments[0]["extra"] != "preserve" || app.posts != 1 {
		t.Fatal("unrelated configuration changed or duplicate WAN created")
	}
	if app.networks[1]["wan_load_balance_type"] != "failover-only" {
		t.Fatal("created WAN omitted required snapshot metadata")
	}
}

func TestControllerInventoryRepairsOnlyMissingOwnedLoadBalanceMetadata(t *testing.T) {
	t.Parallel()
	app := &inventoryServer{}
	srv := httptest.NewServer(app.handler(t))
	defer srv.Close()
	var state unifiapi.State
	if _, err := inventoryClient(srv, &state).Sync(t.Context(), inventorySnapshot()); err != nil {
		t.Fatal(err)
	}
	app.mu.Lock()
	delete(app.networks[0], "wan_load_balance_type")
	app.mu.Unlock()
	r, err := inventoryClient(srv, &state).Sync(t.Context(), inventorySnapshot())
	if err != nil || r.Updated != 1 {
		t.Fatalf("missing metadata not repaired: %v", err)
	}
	app.mu.Lock()
	app.networks[0]["wan_load_balance_type"] = "weighted"
	app.mu.Unlock()
	r, err = inventoryClient(srv, &state).Sync(t.Context(), inventorySnapshot())
	if err != nil || r.Updated != 0 {
		t.Fatalf("existing policy was changed: %v", err)
	}
}

func TestControllerInventoryRecoversLostCreationResponse(t *testing.T) {
	t.Parallel()
	app := &inventoryServer{loseCreateReply: true}
	srv := httptest.NewServer(app.handler(t))
	defer srv.Close()
	var state unifiapi.State
	if _, err := inventoryClient(srv, &state).Sync(t.Context(), inventorySnapshot()); err == nil {
		t.Fatal("lost response treated as successful")
	}
	if !state.Networks["WAN"].Pending {
		t.Fatal("creation was not journaled before request")
	}
	if _, err := inventoryClient(srv, &state).Sync(t.Context(), inventorySnapshot()); err != nil {
		t.Fatal(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.posts != 1 || state.Networks["WAN"].ID == "" || state.Networks["WAN"].Pending {
		t.Fatal("retry duplicated or lost ownership of created WAN")
	}
}

func TestControllerInventoryConflictsAndIdentityMismatchMakeNoWrites(t *testing.T) {
	t.Parallel()
	app := &inventoryServer{networks: []map[string]any{{"_id": "operator-wan", "purpose": "wan", "wan_networkgroup": "WAN", "wan_type": "static", "name": "Operator"}}}
	srv := httptest.NewServer(app.handler(t))
	defer srv.Close()
	var state unifiapi.State
	if _, err := inventoryClient(srv, &state).Sync(t.Context(), inventorySnapshot()); err == nil {
		t.Fatal("conflicting unmanaged WAN accepted")
	}
	c := inventoryClient(srv, &state)
	c.Identity.MAC = "02:00:00:00:00:99"
	if _, err := c.Sync(t.Context(), inventorySnapshot()); err == nil {
		t.Fatal("missing virtual device accepted")
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.writes != 0 {
		t.Fatal("conflict or missing device caused writes")
	}
}

func TestControllerInventoryLeavesNativeVLANToDefaultNetwork(t *testing.T) {
	t.Parallel()
	for _, native := range []int{0, 99} {
		srv := &inventoryServer{networks: []map[string]any{
			{"_id": "default", "name": "Default", "purpose": "corporate", "attr_hidden_id": "LAN", "ip_subnet": "192.0.2.1/24"},
			{"_id": "mgmt", "name": "mgmt", "purpose": "vlan-only", "vlan": 99, "vlan_enabled": true},
		}}
		server := httptest.NewServer(srv.handler(t))
		state := &unifiapi.State{Networks: map[string]unifiapi.OwnedNetwork{"VLAN:99": {ID: "mgmt", Fields: map[string]any{"purpose": "corporate", "gateway_type": "default", "vlan_enabled": true, "ip_subnet": "192.0.2.1/24", "dhcpd_enabled": false}}}}
		client := inventoryClient(server, state)
		client.SyncVLANs, client.NativeVLAN = true, native
		snap := inventorySnapshot()
		snap.SourceID = identity().ID
		snap.Interfaces = append(snap.Interfaces, domain.Interface{Name: "vlan-a", Addresses: []string{"198.51.100.1/24"}}, domain.Interface{Name: "vlan-b", Addresses: []string{"192.0.2.1/24"}})
		snap.VLANs = []domain.VLAN{{Interface: "vlan-a", Tag: 3}, {Interface: "vlan-b", Tag: 99}}
		_, err := client.Sync(t.Context(), snap)
		server.Close()
		if native == 0 {
			if err == nil {
				t.Fatal("operator change to an owned VLAN was not reported as a conflict")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, network := range srv.networks {
			if fmt.Sprint(network["vlan"]) == "99" && network["_id"] != "mgmt" || network["_id"] == "mgmt" && network["purpose"] != "vlan-only" {
				t.Fatalf("native VLAN network was recreated or rewritten: %v", network)
			}
		}
		created := 0
		for _, network := range srv.networks {
			if fmt.Sprint(network["vlan"]) == "3" {
				created++
			}
		}
		if created != 1 {
			t.Fatalf("tagged VLAN 3 created %d times", created)
		}
	}
}
