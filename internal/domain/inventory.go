package domain

// InventorySync reports controller-only inventory work, never appliance writes.
type InventorySync struct {
	Status             string `json:"status"`
	Created            int    `json:"created"`
	Updated            int    `json:"updated"`
	VLANsCreated       int    `json:"vlans_created,omitempty"`
	VLANsUpdated       int    `json:"vlans_updated,omitempty"`
	AssignmentsUpdated bool   `json:"assignments_updated"`
	Error              string `json:"error,omitempty"`
}
