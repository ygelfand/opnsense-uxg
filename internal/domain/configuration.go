package domain

// ConfigObject is a supported configuration object's canonical desired fields.
type ConfigObject struct {
	Kind     string            `json:"kind"`
	Key      string            `json:"key"`
	Fields   map[string]string `json:"fields"`
	Disabled bool              `json:"disabled,omitempty"`
}

// DesiredConfiguration is locally normalized configuration for one appliance.
type DesiredConfiguration struct {
	SourceID  string         `json:"source_id"`
	Additions []ConfigObject `json:"additions"`
}

// ConfigurationPlan records reviewed additions and the inventory they were based on.
type ConfigurationPlan struct {
	SourceID   string         `json:"source_id"`
	SourceURL  string         `json:"source_url"`
	MAC        string         `json:"mac"`
	CFGVersion string         `json:"cfgversion,omitempty"`
	Kinds      []string       `json:"kinds"`
	Baseline   string         `json:"baseline"`
	Additions  []ConfigObject `json:"additions"`
}

// ConfigurationApplyResult records partial success for local configuration writes.
type ConfigurationApplyResult struct {
	SourceID    string   `json:"source_id"`
	AddedUUIDs  []string `json:"added_uuids"`
	Stage       string   `json:"stage"`
	InFlightKey string   `json:"in_flight_key,omitempty"`
	Verified    bool     `json:"verified"`
}
