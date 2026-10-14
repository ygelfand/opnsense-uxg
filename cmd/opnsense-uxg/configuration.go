package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/filestate"
	"github.com/ygelfand/opnsense-uxg/internal/config"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/transport"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

func readJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	b, err := transport.ReadBody(f)
	if err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("configuration must contain one JSON document")
	}
	return nil
}

func planConfiguration(ctx context.Context, cfg config.Config, path string) error {
	var desired domain.DesiredConfiguration
	if err := readJSON(path, &desired); err != nil {
		return err
	}
	for _, g := range cfg.Gateways {
		if g.Identity.ID != desired.SourceID {
			continue
		}
		client, _, err := openSource(g)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		current, err := client.Configuration(ctx, usecase.ConfigurationKinds(desired.Additions))
		if err != nil {
			return err
		}
		plan, err := usecase.BuildConfigurationPlan(g.Identity, g.Source.URL, "", desired.Additions, current, g.Control.Policy)
		if err != nil {
			return err
		}
		if err := filestate.WriteJSON(filepath.Join(cfg.StateDir, g.Identity.ID, "configuration-plan.json"), plan); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(plan)
	}
	return fmt.Errorf("configuration source is absent from gateway config")
}

func applyConfiguration(ctx context.Context, cfg config.Config, path string) error {
	var plan domain.ConfigurationPlan
	if err := readJSON(path, &plan); err != nil {
		return err
	}
	for _, g := range cfg.Gateways {
		if g.Identity.ID != plan.SourceID {
			continue
		}
		if !g.Control.AllowApply {
			return fmt.Errorf("configuration apply is disabled for gateway %q", g.Identity.ID)
		}
		client, _, err := openSource(g)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		record := func(result domain.ConfigurationApplyResult) error {
			return filestate.WriteJSON(filepath.Join(cfg.StateDir, g.Identity.ID, "configuration-apply.json"), result)
		}
		result, applyErr := usecase.ApplyConfigurationPlan(ctx, client, plan, g.Identity, g.Source.URL, g.Control.Policy, record)
		return errors.Join(applyErr, record(result), json.NewEncoder(os.Stdout).Encode(result))
	}
	return fmt.Errorf("configuration plan source is absent from gateway config")
}
