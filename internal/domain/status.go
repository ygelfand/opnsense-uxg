package domain

import "time"

// CycleStatus records one gateway cycle's telemetry and lifecycle progress.
type CycleStatus struct {
	HA                  *HAStatus         `json:"ha,omitempty"`
	CARP                []CARPObservation `json:"carp,omitempty"`
	Inventory           *InventorySync    `json:"controller_inventory,omitempty"`
	SourceID            string            `json:"source_id"`
	ObservedAt          time.Time         `json:"observed_at"`
	InterfaceCount      int               `json:"interface_count"`
	HTTPStatus          int               `json:"http_status"`
	ResponseType        string            `json:"response_type,omitempty"`
	Adopted             bool              `json:"adopted"`
	Provisioning        string            `json:"provisioning,omitempty"`
	IgnoredCommand      bool              `json:"ignored_command,omitempty"`
	NextDelay           time.Duration     `json:"next_delay"`
	AttemptedAt         time.Time         `json:"attempted_at"`
	LastCollectionAt    time.Time         `json:"last_collection_at,omitempty"`
	LastInformAt        time.Time         `json:"last_inform_at,omitempty"`
	ConsecutiveFailures int               `json:"consecutive_failures"`
	Error               string            `json:"error,omitempty"`
	Warnings            []string          `json:"warnings,omitempty"`
	System              System            `json:"system"`
	Gateways            []GatewayMonitor  `json:"gateways,omitempty"`
	ProvisioningVersion string            `json:"provisioning_version,omitempty"`
	Cipher              string            `json:"cipher,omitempty"`
	CipherFallback      bool              `json:"cipher_fallback,omitempty"`
	Reset               bool              `json:"reset"`
	Commands            CommandStatus     `json:"commands"`
	Clients             []Client          `json:"clients,omitempty"`
	VLANs               []VLAN            `json:"vlans,omitempty"`
	WANHistory          []WANHistory      `json:"wan_history,omitempty"`
}
