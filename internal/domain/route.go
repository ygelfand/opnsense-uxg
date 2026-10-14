package domain

// Route is a locally authorized static route using an OPNsense gateway name.
type Route struct {
	Network     string `json:"network"`
	Gateway     string `json:"gateway"`
	Description string `json:"description"`
	Disabled    bool   `json:"disabled,omitempty"`
}

// RoutePlan proposes additions only; existing appliance routes are never deleted.
type RoutePlan struct {
	SourceID   string  `json:"source_id"`
	SourceURL  string  `json:"source_url"`
	MAC        string  `json:"mac"`
	CFGVersion string  `json:"cfgversion,omitempty"`
	Baseline   string  `json:"baseline"`
	Additions  []Route `json:"additions"`
}

// RouteApplyResult records configuration writes and reconfiguration progress.
type RouteApplyResult struct {
	SourceID        string   `json:"source_id"`
	AddedUUIDs      []string `json:"added_uuids"`
	Reconfigured    bool     `json:"reconfigured"`
	Verified        bool     `json:"verified"`
	Stage           string   `json:"stage"`
	InFlightNetwork string   `json:"in_flight_network,omitempty"`
}
