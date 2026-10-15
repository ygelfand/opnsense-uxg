// Package domain defines gateway observations, identities, and sync contracts.
package domain

import (
	"context"
	"net/netip"
	"time"
)

// Identity identifies one virtual UXG; it is independent of the physical NICs.
type Identity struct {
	ID           string `json:"id" yaml:"id"`
	MAC          string `json:"mac" yaml:"mac"`
	Hostname     string `json:"hostname" yaml:"hostname"`
	Model        string `json:"model" yaml:"model"`
	ManagementIP string `json:"management_ip" yaml:"management_ip"`
}

// Binding associates a virtual physical port with an explicit source interface.
type Binding struct {
	Port      int    `json:"port" yaml:"port"`
	Interface string `json:"interface" yaml:"interface"`
	Role      string `json:"role" yaml:"role"`
}

// Counters holds measured octets and packets; nil fields are unknown.
type Counters struct {
	RXBytes   *uint64 `json:"rx_bytes,omitempty"`
	TXBytes   *uint64 `json:"tx_bytes,omitempty"`
	RXPackets *uint64 `json:"rx_packets,omitempty"`
	TXPackets *uint64 `json:"tx_packets,omitempty"`
}

// Interface is observed state of an OPNsense interface, not desired config.
type Interface struct {
	CARP         []CARPObservation `json:"carp,omitempty"`
	GatewayIP    string            `json:"gateway_ip,omitempty"`
	IPv4Mode     string            `json:"ipv4_mode,omitempty"`
	AdminEnabled *bool             `json:"admin_enabled,omitempty"`
	Description  string            `json:"description,omitempty"`
	Name         string            `json:"name"`
	MAC          string            `json:"mac,omitempty"`
	Addresses    []string          `json:"addresses"`
	Up           *bool             `json:"up,omitempty"`
	SpeedMbps    *int              `json:"speed_mbps,omitempty"`
	Duplex       string            `json:"duplex,omitempty"`
	Counters     Counters          `json:"counters"`
	Rates        Rates             `json:"rates"`
}

// Rates holds traffic measured between consecutive successful collections.
type Rates struct {
	RXBytesPerSecond *float64 `json:"rx_bytes_per_second,omitempty"`
	TXBytesPerSecond *float64 `json:"tx_bytes_per_second,omitempty"`
}

// System holds measured appliance resources and operating-system information.
type System struct {
	Hostname         string        `json:"hostname,omitempty"`
	Versions         []string      `json:"versions,omitempty"`
	UptimeSeconds    *int64        `json:"uptime_seconds,omitempty"`
	LoadAverage      []float64     `json:"load_average,omitempty"`
	CPUPercent       *float64      `json:"cpu_percent,omitempty"`
	MemoryTotalBytes *uint64       `json:"memory_total_bytes,omitempty"`
	MemoryUsedBytes  *uint64       `json:"memory_used_bytes,omitempty"`
	Temperatures     []Temperature `json:"temperatures,omitempty"`
}

// Temperature is a sensor reading in degrees Celsius.
type Temperature struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Celsius float64 `json:"celsius"`
}

// GatewayMonitor is an explicitly mapped OPNsense WAN monitor observation.
type GatewayMonitor struct {
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Status      string   `json:"status"`
	Connected   *bool    `json:"connected,omitempty"`
	LatencyMS   *float64 `json:"latency_ms,omitempty"`
	LossPercent *float64 `json:"loss_percent,omitempty"`
}

// Provider names the service provider behind one WAN role.
type Provider struct {
	Role string `json:"role"`
	Name string `json:"name,omitempty"`
	ASN  uint32 `json:"asn,omitempty"`
}

// ProviderLookup resolves the provider announcing a public address.
type ProviderLookup func(context.Context, netip.Addr) (Provider, error)

// Snapshot represents a successful, fresh collection from a single appliance.
type Snapshot struct {
	HA                *HAStatus         `json:"ha,omitempty"`
	CARP              []CARPObservation `json:"carp,omitempty"`
	SourceID          string            `json:"source_id"`
	ObservedAt        time.Time         `json:"observed_at"`
	Interfaces        []Interface       `json:"interfaces"`
	System            System            `json:"system"`
	Gateways          []GatewayMonitor  `json:"gateways,omitempty"`
	Warnings          []string          `json:"warnings,omitempty"`
	Neighbors         []Neighbor        `json:"neighbors,omitempty"`
	NeighborsComplete bool              `json:"neighbors_complete"`
	Leases            []Lease           `json:"leases,omitempty"`
	LeasesComplete    bool              `json:"leases_complete"`
	VLANs             []VLAN            `json:"vlans,omitempty"`
	Clients           []Client          `json:"clients,omitempty"`
	Traffic           []ClientTraffic   `json:"traffic,omitempty"`
	TrafficFresh      bool              `json:"traffic_fresh,omitempty"`
	WANHistory        []WANHistory      `json:"wan_history,omitempty"`
	Providers         []Provider        `json:"providers,omitempty"`
}

// Source collects measured state. Collection failure suppresses publication.
type Source interface {
	Collect(context.Context) (Snapshot, error)
}

// Adoption contains only necessary protocol state, including a secret key.
// Never log or include this value in ordinary status output.
type Adoption struct {
	MAC               string `json:"mac"`
	AuthKey           string `json:"auth_key,omitempty"`
	CFGVersion        string `json:"cfgversion,omitempty"`
	UseGCM            bool   `json:"use_gcm"`
	PendingCFGVersion string `json:"pending_cfgversion,omitempty"`
	Provisioning      string `json:"provisioning,omitempty"`
}

// Exchange is a decoded publication result. SystemConfig is ephemeral and secret.
type Exchange struct {
	HTTPStatus          int
	ResponseType        string
	Adoption            Adoption
	Interval            time.Duration
	SystemConfig        []byte
	RequestedCFGVersion string
	IgnoredCommand      bool
	ResetRequested      bool
	Cipher              string
	CipherFallback      bool
	Command             CommandRequest
	CommandStatus       CommandStatus
}

// CommandRequest is an ephemeral supported controller command.
type CommandRequest struct {
	Name      string
	RequestID string
}

// CommandStatus exposes command progress counters suitable for status files.
type CommandStatus struct {
	Name       string `json:"name,omitempty"`
	Handled    int    `json:"handled"`
	Delivered  int    `json:"delivered"`
	Duplicates int    `json:"duplicates"`
	Pending    bool   `json:"pending"`
}

// Publisher sends a snapshot using one identity and current adoption state.
type Publisher interface {
	Publish(context.Context, Snapshot, Adoption) (Exchange, error)
}

// StateStore persists one identity's adoption state atomically.
type StateStore interface {
	Load() (Adoption, error)
	Save(Adoption) error
}
