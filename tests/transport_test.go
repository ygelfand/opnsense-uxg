package framework_test

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/opnsense"
	"github.com/ygelfand/opnsense-uxg/internal/transport"
)

func TestPrivateCAAndRedirectOwnership(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, interfaceJSON) }))
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	httpClient, err := transport.NewClient(time.Second, caPath)
	if err != nil {
		t.Fatal(err)
	}
	client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&opnsense.Source{ID: "edge", Client: client}).Collect(t.Context()); err != nil {
		t.Fatalf("trusted private CA collection: %v", err)
	}
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err = opnsense.NewClient(redirect.URL, "test-key", "test-secret", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&opnsense.Source{ID: "edge", Client: client}).Collect(t.Context()); err == nil {
		t.Error("redirected API collection succeeded")
	}
	if targetCalls.Load() != 0 {
		t.Error("credentials/request followed an endpoint redirect")
	}
}

func TestSourceCertificateValidationIsIndependent(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, interfaceJSON) }))
	defer srv.Close()
	for _, skip := range []bool{false, true, false} {
		httpClient, err := transport.NewClientWithTLS(time.Second, transport.TLSOptions{InsecureSkipVerify: skip})
		if err != nil {
			t.Fatal(err)
		}
		client, err := opnsense.NewClient(srv.URL, "test-key", "test-secret", httpClient)
		if err != nil {
			t.Fatal(err)
		}
		_, err = (&opnsense.Source{ID: "edge", Client: client}).Collect(t.Context())
		if (err == nil) != skip {
			t.Errorf("collection with skip_verify=%v returned %v", skip, err)
		}
	}
}
