// Package transport provides bounded HTTP exchanges and operator-owned TLS trust.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// MaxBody limits API and inform response bodies to four MiB.
const MaxBody = 4 << 20

// NewClient creates a TLS client with an optional additional CA certificate.
// Redirects return their original response to preserve endpoint ownership.
func NewClient(timeout time.Duration, caFile string) (*http.Client, error) {
	return NewClientWithTLS(timeout, TLSOptions{CAFile: caFile})
}

// TLSOptions configures certificate trust for one endpoint.
type TLSOptions struct {
	CAFile             string
	InsecureSkipVerify bool
}

// NewClientWithTLS creates a client using the endpoint's certificate policy.
func NewClientWithTLS(timeout time.Duration, options TLSOptions) (*http.Client, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.InsecureSkipVerify} // Explicit per-source operator setting.
	if options.CAFile != "" && !options.InsecureSkipVerify {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		b, err := os.ReadFile(options.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("CA file contains no certificates")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Timeout: timeout, Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// ReadBody consumes a response with a fixed upper bound.
func ReadBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBody {
		return nil, fmt.Errorf("response exceeds %d bytes", MaxBody)
	}
	return b, nil
}
