package framework_test

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/jamesbraid/unifi-emu/inform"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/filestate"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

func TestWireGuardCommandRetriesDeduplicatesAndResets(t *testing.T) {
	t.Parallel()
	const key = "0123456789abcdef0123456789abcdef"
	var count int
	var cachedPrivate, cachedPublic string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		auth := key
		if count == 6 {
			auth = inform.DefaultKey
		}
		packet, err := inform.Decode(body, auth)
		if err != nil {
			t.Error(err)
			http.Error(w, "packet", 400)
			return
		}
		var payload struct {
			AsNotif      bool   `json:"inform_as_notif"`
			Reason       string `json:"notif_reason"`
			Default      bool   `json:"default"`
			Notification struct {
				Event   string `json:"event_string"`
				Request string `json:"request_id"`
				Params  struct {
					Private string `json:"private_key"`
					Public  string `json:"public_key"`
				} `json:"params"`
			} `json:"notif_payload"`
		}
		if err := json.Unmarshal(packet.Payload, &payload); err != nil {
			t.Error(err)
			return
		}
		if count >= 2 && count <= 4 {
			if !payload.AsNotif || payload.Reason != "cmd" || payload.Notification.Event != "wg-genkeypair" || payload.Notification.Request != "test-request" {
				t.Error("missing or uncorrelated command notification")
			}
			private, public := payload.Notification.Params.Private, payload.Notification.Params.Public
			if count == 2 {
				cachedPrivate, cachedPublic = private, public
				priv, err := base64.StdEncoding.DecodeString(private)
				if err != nil || len(priv) != 32 {
					t.Error("invalid private key encoding")
					return
				}
				if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
					t.Error("WireGuard scalar was not clamped")
				}
				derived, err := ecdh.X25519().NewPrivateKey(priv)
				if err != nil || base64.StdEncoding.EncodeToString(derived.PublicKey().Bytes()) != public {
					t.Error("command key pair does not match")
				}
			} else if private != cachedPrivate || public != cachedPublic {
				t.Error("retry/duplicate regenerated key material")
			}
		} else if payload.AsNotif {
			t.Error("unexpected pending command notification")
		}
		if count == 6 && !payload.Default {
			t.Error("inform after reset was still adopted")
		}
		response := `{"_type":"noop"}`
		switch count {
		case 1, 3:
			response = `{"_type":"cmd","cmd":"wg-genkeypair","request_id":"test-request"}`
		case 2:
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		case 5:
			response = `{"_type":"cmd","cmd":"restore-default"}`
		}
		encoded, err := unifi.EncodePacket(identity().MAC, auth, count != 6, []byte(response))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(encoded)
	}))
	defer srv.Close()
	pub := &unifi.Publisher{Identity: identity(), Bindings: bindings(), URL: srv.URL, Client: srv.Client(), StartedAt: time.Now()}
	store := &filestate.Store{Path: filepath.Join(t.TempDir(), "adoption.json"), MAC: identity().MAC}
	if err := store.Save(domain.Adoption{MAC: identity().MAC, AuthKey: key, UseGCM: true}); err != nil {
		t.Fatal(err)
	}
	resetCount := 0
	worker := &usecase.Worker{ID: "edge", Source: healthySource{}, Publisher: pub, Store: store, Timeout: time.Minute, OnReset: func() error { resetCount++; return nil }}
	for cycle := 1; cycle <= 6; cycle++ {
		r, err := worker.Cycle(t.Context())
		if cycle == 2 {
			if err == nil || !r.Commands.Pending {
				t.Error("failed notification lost pending result")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if cycle == 3 && (r.Commands.Duplicates != 1 || r.Commands.Handled != 1 || !r.Commands.Pending) {
			t.Errorf("duplicate status = %+v", r.Commands)
		}
		if cycle == 4 && (r.Commands.Delivered != 2 || r.Commands.Pending) {
			t.Errorf("delivery status = %+v", r.Commands)
		}
		if cycle == 5 && (!r.Reset || r.Adopted || resetCount != 1) {
			t.Errorf("reset state = %+v, callbacks %d", r, resetCount)
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), key) || strings.Contains(string(b), "test-request") || cachedPrivate != "" && strings.Contains(string(b), cachedPrivate) {
			t.Error("cycle status leaked command/adoption material")
		}
	}
}

func TestCipherFallbackAndNegotiatedGCM(t *testing.T) {
	t.Parallel()
	const key = "0123456789abcdef0123456789abcdef"
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if binary.BigEndian.Uint16(body[14:16])&8 != 0 {
			http.Error(w, "legacy cipher", 400)
			return
		}
		response, err := unifi.EncodePacket(identity().MAC, key, false, []byte(`{"_type":"noop"}`))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(response)
	}))
	defer srv.Close()
	pub := &unifi.Publisher{Identity: identity(), Bindings: bindings(), URL: srv.URL, Client: srv.Client(), StartedAt: time.Now()}
	snap, err := (healthySource{}).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ex, err := pub.Publish(t.Context(), snap, domain.Adoption{MAC: identity().MAC, AuthKey: key})
	if err != nil || !ex.CipherFallback || ex.Cipher != "aes-cbc" || requests != 2 {
		t.Fatalf("fallback = %+v, %v, requests %d", ex, err, requests)
	}
	_, err = pub.Publish(t.Context(), snap, domain.Adoption{MAC: identity().MAC, AuthKey: key, UseGCM: true})
	if err != nil || requests != 3 {
		t.Errorf("pinned GCM request count = %d, error %v", requests, err)
	}
}

func TestUnsupportedCommandsAndPendingConfigRemainHeld(t *testing.T) {
	t.Parallel()
	state := domain.Adoption{MAC: identity().MAC, AuthKey: "0123456789abcdef0123456789abcdef", CFGVersion: "applied", PendingCFGVersion: "pending", Provisioning: "awaiting_local_review"}
	ex, err := unifi.ParseResponse([]byte(`{"_type":"setparam","mgmt_cfg":"cfgversion=pending"}`), domain.Exchange{Adoption: state})
	if err != nil || ex.Adoption.CFGVersion != "applied" {
		t.Errorf("pending config falsely acknowledged: %+v, %v", ex, err)
	}
	for _, body := range []string{`{"_type":"cmd","cmd":"wg-genkeypair"}`, `{"_type":"cmd","cmd":"wg-genkeypair","request_id":"test","args":["write"]}`, `{"_type":"cmd","cmd":"reboot"}`, `{"_type":"upgrade","version":"different"}`} {
		ex, err := unifi.ParseResponse([]byte(body), domain.Exchange{Adoption: state})
		if err != nil || !ex.IgnoredCommand || ex.Command.Name != "" || ex.ResetRequested {
			t.Errorf("unsafe/malformed command accepted: %s", body)
		}
	}
}

func TestBoundedSnappyAndVersionZeroResponses(t *testing.T) {
	t.Parallel()
	header := make([]byte, 40)
	copy(header, "TNBU")
	binary.BigEndian.PutUint32(header[32:36], 1)
	binary.BigEndian.PutUint16(header[14:16], 4)
	body := snappy.Encode(nil, []byte(`{"_type":"noop"}`))
	binary.BigEndian.PutUint32(header[36:40], uint32(len(body)))
	plain, err := unifi.DecodePacket(append(header, body...), "")
	if err != nil || string(plain) != `{"_type":"noop"}` {
		t.Errorf("v0 snappy = %s, %v", plain, err)
	}
	body = snappy.Encode(nil, []byte(strings.Repeat("x", (4<<20)+1)))
	binary.BigEndian.PutUint32(header[36:40], uint32(len(body)))
	if _, err := unifi.DecodePacket(append(header, body...), ""); err == nil {
		t.Error("oversized snappy accepted")
	}
}
