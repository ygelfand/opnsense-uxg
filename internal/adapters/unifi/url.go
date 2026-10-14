package unifi

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
)

// ResolveInformURL produces the IP-literal URL reported inside an inform.
// HTTP requests still use the configured URL for routing and TLS verification.
func ResolveInformURL(ctx context.Context, raw string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Scheme != "http" && u.Scheme != "https" || u.User != nil {
		return "", fmt.Errorf("invalid controller inform URL")
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return u.String(), nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", u.Hostname())
	if err != nil {
		return "", fmt.Errorf("resolve controller inform address: %w", err)
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("controller inform hostname has no IPv4 address")
	}
	host := addresses[0].Unmap().String()
	if u.Port() != "" {
		host = net.JoinHostPort(host, u.Port())
	}
	u.Host = host
	return u.String(), nil
}
