// Package filestate persists identity-bound state and private review artifacts.
package filestate

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// Store binds an adoption file to one virtual MAC.
type Store struct {
	Path string
	MAC  string
}

var _ domain.StateStore = (*Store)(nil)

// Load treats a missing state file as a fresh gateway and rejects invalid keys.
func (s *Store) Load() (domain.Adoption, error) {
	a := domain.Adoption{MAC: s.MAC}
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return a, fmt.Errorf("decode adoption state: %w", err)
	}
	if a.MAC != s.MAC {
		return a, fmt.Errorf("adoption state belongs to a different MAC")
	}
	if a.AuthKey != "" {
		k, err := hex.DecodeString(a.AuthKey)
		if err != nil || len(k) != 16 {
			return a, fmt.Errorf("adoption state contains an invalid key")
		}
	}
	return a, nil
}

// Save writes adoption state using a private atomic replacement.
func (s *Store) Save(a domain.Adoption) error {
	if a.MAC != s.MAC {
		return fmt.Errorf("refusing state for a different MAC")
	}
	return WriteJSON(s.Path, a)
}

// WriteJSON writes a private JSON artifact atomically within its directory.
func WriteJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".opnsense-uxg-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }() // Removes abandoned temporary files.
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
