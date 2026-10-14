package domain

import "time"

// HAStatus separates the configured controller role from observed CARP ownership.
type HAStatus struct {
	Role                 string     `json:"role"`
	Peer                 string     `json:"peer"`
	CARPState            string     `json:"carp_state"`
	Status               string     `json:"status"`
	VIPCount             int        `json:"vip_count"`
	ObservedTransitionAt *time.Time `json:"observed_transition_at,omitempty"`
}
