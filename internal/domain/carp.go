package domain

// CARPObservation records ownership of one shared address on one source interface.
type CARPObservation struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	State     string `json:"state"`
	VHID      *int   `json:"vhid,omitempty"`
}
