package filestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// Status is a point-in-time summary of one worker's latest cycle.
type Status struct {
	Cycle      domain.CycleStatus `json:"cycle"`
	ReadAt     time.Time          `json:"read_at"`
	AgeSeconds float64            `json:"age_seconds"`
	Stale      bool               `json:"stale"`
	Available  bool               `json:"available"`
}

// ReadStatus returns lifecycle data and computes freshness against the current time.
func ReadStatus(path, id string, now time.Time) (Status, error) {
	s := Status{ReadAt: now, Cycle: domain.CycleStatus{SourceID: id}, Stale: true}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s.Cycle); err != nil {
		return s, err
	}
	if s.Cycle.SourceID != id {
		return s, fmt.Errorf("status belongs to another source")
	}
	s.Available = true
	s.AgeSeconds = max(0, now.Sub(s.Cycle.AttemptedAt).Seconds())
	s.Stale = s.Cycle.AttemptedAt.IsZero() || now.Sub(s.Cycle.AttemptedAt) > max(30*time.Second, 2*s.Cycle.NextDelay)
	return s, nil
}
