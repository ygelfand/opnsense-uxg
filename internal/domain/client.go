package domain

import "time"

// Neighbor is one ARP/NDP observation, including unresolved entries.
type Neighbor struct {
	IP           string `json:"ip"`
	MAC          string `json:"mac,omitempty"`
	Interface    string `json:"interface"`
	Hostname     string `json:"hostname,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Incomplete   bool   `json:"incomplete"`
}

// Lease is an observed DHCP assignment and its validity metadata.
type Lease struct {
	IP        string     `json:"ip"`
	MAC       string     `json:"mac,omitempty"`
	Interface string     `json:"interface,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	Backend   string     `json:"backend"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Active    *bool      `json:"active,omitempty"`
	Reserved  bool       `json:"reserved"`
}

// VLAN identifies a logical interface and its physical parent.
type VLAN struct {
	UUID      string `json:"uuid"`
	Interface string `json:"interface"`
	Parent    string `json:"parent"`
	Tag       int    `json:"tag"`
	Name      string `json:"name,omitempty"`
}

// ClientAddress associates an observed address with a virtual physical port.
type ClientAddress struct {
	IP        string `json:"ip"`
	Interface string `json:"interface,omitempty"`
	Port      int    `json:"port,omitempty"`
	VLAN      int    `json:"vlan,omitempty"`
	Role      string `json:"role,omitempty"`
	Network   string `json:"network,omitempty"`
}

// ClientTraffic is IP accounting over a defined interval on one exporter interface.
type ClientTraffic struct {
	IP          string    `json:"ip"`
	Interface   string    `json:"interface"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	RXBytes     *uint64   `json:"rx_bytes,omitempty"`
	TXBytes     *uint64   `json:"tx_bytes,omitempty"`
	Attribution string    `json:"attribution"`
}

// Client records identity, table-observation history, leases, and measured traffic.
type Client struct {
	Key          string          `json:"key"`
	MAC          string          `json:"mac,omitempty"`
	Hostname     string          `json:"hostname,omitempty"`
	Manufacturer string          `json:"manufacturer,omitempty"`
	Addresses    []ClientAddress `json:"addresses"`
	Leases       []Lease         `json:"leases,omitempty"`
	Traffic      []ClientTraffic `json:"traffic,omitempty"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	Presence     string          `json:"presence"`
	Incomplete   bool            `json:"incomplete"`
}

// WANHistory accumulates observed online/offline time and transition events.
type WANHistory struct {
	Role           string    `json:"role"`
	Monitor        string    `json:"monitor"`
	StartedAt      time.Time `json:"started_at"`
	LastSampleAt   time.Time `json:"last_sample_at"`
	Connected      *bool     `json:"connected,omitempty"`
	OnlineSeconds  float64   `json:"online_seconds"`
	OfflineSeconds float64   `json:"offline_seconds"`
	UnknownSeconds float64   `json:"unknown_seconds"`
	StreakSeconds  float64   `json:"streak_seconds"`
	Outages        int       `json:"outages"`
	LastChangeAt   time.Time `json:"last_change_at"`
}
