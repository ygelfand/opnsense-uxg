// Package cymru resolves WAN providers through the Team Cymru IP-to-ASN DNS zones.
package cymru

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// Resolver queries origin and AS-name TXT records.
type Resolver struct {
	LookupTXT func(context.Context, string) ([]string, error)
}

// Lookup returns the origin ASN of addr and its registered description.
func (r Resolver) Lookup(ctx context.Context, addr netip.Addr) (domain.Provider, error) {
	lookup := r.LookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	records, err := lookup(ctx, originName(addr))
	if err != nil {
		return domain.Provider{}, err
	}
	asn, bits := uint32(0), -1
	for _, record := range records {
		fields := splitFields(record)
		if len(fields) < 2 {
			continue
		}
		prefix, err := netip.ParsePrefix(fields[1])
		if err != nil || prefix.Bits() <= bits {
			continue
		}
		first, _, _ := strings.Cut(fields[0], " ")
		value, err := strconv.ParseUint(first, 10, 32)
		if err != nil || value == 0 {
			continue
		}
		asn, bits = uint32(value), prefix.Bits()
	}
	if asn == 0 {
		return domain.Provider{}, fmt.Errorf("no origin ASN for %s", addr)
	}
	provider := domain.Provider{ASN: asn}
	records, err = lookup(ctx, "AS"+strconv.FormatUint(uint64(asn), 10)+".asn.cymru.com")
	if err != nil {
		return domain.Provider{}, err
	}
	for _, record := range records {
		if fields := splitFields(record); len(fields) >= 5 && fields[4] != "" {
			provider.Name = description(fields[4], fields[1])
			break
		}
	}
	return provider, nil
}

func originName(addr netip.Addr) string {
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	}
	b := addr.As16()
	digits := hex.EncodeToString(b[:])
	labels := make([]string, 0, len(digits)+1)
	for i := len(digits) - 1; i >= 0; i-- {
		labels = append(labels, digits[i:i+1])
	}
	return strings.Join(append(labels, "origin6.asn.cymru.com"), ".")
}

func splitFields(record string) []string {
	fields := strings.Split(record, "|")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	return fields
}

func description(name, country string) string {
	if _, rest, ok := strings.Cut(name, " - "); ok && strings.TrimSpace(rest) != "" {
		name = strings.TrimSpace(rest)
	}
	if country != "" {
		name = strings.TrimSuffix(name, ", "+country)
	}
	return name
}
