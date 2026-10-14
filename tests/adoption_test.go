package framework_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/filestate"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

func TestAdoptionKeyHandoff(t *testing.T) {
	t.Parallel()
	const key = "0123456789abcdef0123456789abcdef"
	const later = "abcdef0123456789abcdef0123456789"
	for _, reply := range []string{
		`{"_type":"cmd","cmd":"set-adopt","key":"` + key + `","uri":"http://192.0.2.200:8080/inform"}`,
		`{"_type":"cmd","cmd":"adopt","key":"` + key + `"}`,
		`{"_type":"setparam","mgmt_cfg":"authkey=` + key + `\nuse_aes_gcm=true"}`,
	} {
		ex, err := unifi.ParseResponse([]byte(reply), domain.Exchange{Adoption: domain.Adoption{MAC: identity().MAC}})
		if err != nil || ex.Adoption.AuthKey != key || ex.IgnoredCommand {
			t.Fatalf("fresh handoff failed: %v", err)
		}
		ex, err = unifi.ParseResponse([]byte(`{"_type":"setparam","mgmt_cfg":"authkey=`+later+`"}`), ex)
		if err != nil || ex.Adoption.AuthKey != key {
			t.Fatalf("later mgmt_cfg replaced the established key: %v", err)
		}
		ex, err = unifi.ParseResponse([]byte(`{"_type":"cmd","cmd":"set-adopt","key":"`+later+`"}`), ex)
		if err != nil || ex.Adoption.AuthKey != later {
			t.Fatalf("explicit set-adopt failed to rotate the key: %v", err)
		}
	}
}

// This synthetic controller exercises fresh adoption and a process restart.
func TestCommandAdoptionPersistsAcrossRestart(t *testing.T) {
	t.Parallel()
	const key = "0123456789abcdef0123456789abcdef"
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		auth := ""
		if requests > 1 {
			auth = key
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		plain, err := unifi.DecodePacket(body, auth)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload struct {
			Default bool   `json:"default"`
			CFG     string `json:"cfgversion"`
		}
		if err := json.Unmarshal(plain, &payload); err != nil {
			t.Error(err)
			return
		}
		if payload.Default != (requests == 1) || payload.CFG != "0" {
			t.Error("incorrect fresh/restarted adoption payload")
		}
		reply := `{"_type":"noop"}`
		if requests == 1 {
			reply = `{"_type":"cmd","cmd":"set-adopt","key":"` + key + `"}`
		}
		packet, err := unifi.EncodePacket(identity().MAC, auth, requests > 1, []byte(reply))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(packet)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "adoption.json")
	for range 2 {
		store := &filestate.Store{Path: path, MAC: identity().MAC}
		pub := &unifi.Publisher{Identity: identity(), Bindings: bindings(), URL: srv.URL, Client: srv.Client(), StartedAt: time.Now()}
		worker := &usecase.Worker{ID: "edge", Source: healthySource{}, Publisher: pub, Store: store, Interval: 10 * time.Second, Timeout: time.Minute}
		if _, err := worker.Cycle(t.Context()); err != nil {
			t.Fatal(err)
		}
		state, err := store.Load()
		if err != nil || state.AuthKey != key {
			t.Fatalf("adoption key not persisted: %v", err)
		}
	}
}

func TestInvalidAdoptionKeyRejected(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"", "invalid", "ba86f2bbe107c7c57eb5f2690775c712"} {
		state := domain.Adoption{MAC: identity().MAC}
		ex, err := unifi.ParseResponse([]byte(`{"_type":"cmd","cmd":"set-adopt","key":"`+key+`"}`), domain.Exchange{Adoption: state})
		if err == nil || ex.Adoption != state {
			t.Fatal("invalid adoption command modified state")
		}
	}
}
