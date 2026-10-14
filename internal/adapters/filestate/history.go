package filestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// History binds client and WAN observations to the actual source and virtual MAC.
type History struct {
	SourceID  string              `json:"source_id"`
	SourceURL string              `json:"source_url"`
	MAC       string              `json:"mac"`
	Clients   []domain.Client     `json:"clients"`
	WAN       []domain.WANHistory `json:"wan"`
}

// ReadHistory restores private observation data for the configured appliance.
func ReadHistory(path string, expected History) (History, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return expected, nil
	}
	if err != nil {
		return expected, err
	}
	var history History
	if err := json.Unmarshal(b, &history); err != nil {
		return expected, err
	}
	if history.SourceID != expected.SourceID || history.SourceURL != expected.SourceURL || history.MAC != expected.MAC {
		return expected, fmt.Errorf("observation history belongs to another appliance")
	}
	return history, nil
}
