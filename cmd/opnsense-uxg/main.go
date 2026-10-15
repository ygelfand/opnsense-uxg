package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/adapters/cymru"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/filestate"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/opnsense"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifi"
	"github.com/ygelfand/opnsense-uxg/internal/adapters/unifiapi"
	"github.com/ygelfand/opnsense-uxg/internal/config"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/transport"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
)

func main() {
	if err := run(); err != nil {
		slog.Error("opnsense-uxg failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "operator YAML configuration")
	validate := flag.Bool("validate", false, "validate configuration without network access")
	collect := flag.Bool("collect-once", false, "collect real OPNsense observations as JSON")
	dryRun := flag.Bool("dry-run", false, "collect and render gateway JSON without sending inform")
	serve := flag.Bool("serve", false, "run independent gateway inform loops")
	status := flag.Bool("status", false, "print per-source status without contacting appliances or controller")
	apply := flag.String("apply-plan", "", "apply a reviewed route-plan file (requires routes.allow_apply)")
	planConfig := flag.String("plan-config", "", "build a reviewed VLAN/reservation/alias plan from normalized JSON")
	applyConfig := flag.String("apply-config-plan", "", "apply a reviewed configuration plan (requires control.allow_apply)")
	flag.Parse()
	modes := 0
	for _, enabled := range []bool{*validate, *collect, *dryRun, *serve, *status, *apply != "", *planConfig != "", *applyConfig != ""} {
		if enabled {
			modes++
		}
	}
	if modes != 1 || flag.NArg() != 0 {
		return fmt.Errorf("select one of -validate, -collect-once, -dry-run, -serve, -status, -apply-plan, -plan-config, or -apply-config-plan")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *validate {
		fmt.Printf("configuration valid: %d gateways\n", len(cfg.Gateways))
		return nil
	}
	if *status {
		return printStatus(cfg)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *serve || *apply != "" || *planConfig != "" || *applyConfig != "" {
		lock, err := filestate.Lock(cfg.StateDir)
		if err != nil {
			return err
		}
		defer func() { _ = lock.Close() }() // Closing releases the process lock.
	}
	if *apply != "" {
		return applyPlan(ctx, cfg, *apply)
	}
	if *planConfig != "" {
		return planConfiguration(ctx, cfg, *planConfig)
	}
	if *applyConfig != "" {
		return applyConfiguration(ctx, cfg, *applyConfig)
	}
	workers := make([]*usecase.Worker, 0, len(cfg.Gateways))
	var collectErrors []error
	for _, g := range cfg.Gateways {
		client, source, err := openSource(g)
		if err != nil {
			return fmt.Errorf("source %q: %w", g.Identity.ID, err)
		}
		if *collect || *dryRun {
			if err := collectOne(ctx, g, source, *dryRun, cfg.StateDir); err != nil {
				collectErrors = append(collectErrors, fmt.Errorf("source %q: %w", g.Identity.ID, err))
			}
			continue
		}
		if g.Controller.URL == "" {
			return fmt.Errorf("gateway %q requires controller URL for -serve", g.Identity.ID)
		}
		httpClient, err := transport.NewClient(g.Controller.Timeout, g.Controller.CAFile)
		if err != nil {
			return err
		}
		store := &filestate.Store{Path: filepath.Join(cfg.StateDir, g.Identity.ID, "adoption.json"), MAC: g.Identity.MAC}
		if _, err := store.Load(); err != nil {
			return fmt.Errorf("gateway %q: %w", g.Identity.ID, err)
		}
		publisher := &unifi.Publisher{Identity: g.Identity, Bindings: g.Bindings, UplinkInterface: g.UplinkInterface, MinInterval: g.Controller.MinInterval, URL: g.Controller.URL, Client: httpClient, StartedAt: time.Now()}
		worker := &usecase.Worker{ID: g.Identity.ID, Source: source, Publisher: publisher, Store: store, Interval: g.Controller.Interval, MinInterval: g.Controller.MinInterval, Timeout: g.Source.Timeout + g.Controller.Timeout}
		worker.Bindings = g.Bindings
		if g.HA != nil {
			worker.HA = usecase.HATracker{Role: g.HA.Role, Peer: g.HA.Peer}
		}
		if a := g.Controller.API; a != nil && (a.SyncWANs || a.SyncVLANs) && (g.HA == nil || g.HA.Role == "primary" || len(a.DisabledPorts) > 0) {
			base, key := os.Getenv(a.URLEnv), os.Getenv(a.KeyEnv)
			if err := config.ValidateURL(base, true); err != nil || key == "" {
				return fmt.Errorf("gateway %q requires controller API URL and key environment variables", g.Identity.ID)
			}
			apiHTTP, err := transport.NewClient(g.Controller.Timeout, g.Controller.CAFile)
			if err != nil {
				return err
			}
			prefix := strings.TrimRight(a.NetworkPath, "/")
			bindings := g.Bindings
			if g.HA != nil && g.HA.Role == "shadow" {
				bindings = make([]domain.Binding, 0, 2)
				for _, binding := range g.Bindings {
					if binding.Role == "lan" || binding.Role == "lan2" {
						bindings = append(bindings, binding)
					}
				}
			}
			inventory := &unifiapi.Client{URL: strings.TrimRight(base, "/"), Key: key, Site: a.Site, Prefix: prefix, HTTP: apiHTTP, Identity: g.Identity, Bindings: bindings, DisabledPorts: a.DisabledPorts, SyncWANs: a.SyncWANs, SyncVLANs: a.SyncVLANs, NativeVLAN: a.NativeVLAN}
			if g.HA != nil {
				for _, peer := range cfg.Gateways {
					if peer.Identity.ID == g.HA.Peer {
						inventory.PeerMAC = peer.Identity.MAC
						break
					}
				}
			}
			path := filepath.Join(cfg.StateDir, g.Identity.ID, "controller-inventory.json")
			inventory.Load = func() (unifiapi.State, error) {
				var state unifiapi.State
				data, err := os.ReadFile(path)
				if errors.Is(err, os.ErrNotExist) {
					return state, nil
				}
				if err != nil {
					return state, err
				}
				if err := json.Unmarshal(data, &state); err != nil {
					return state, err
				}
				return state, nil
			}
			inventory.Save = func(state unifiapi.State) error { return filestate.WriteJSON(path, state) }
			worker.SyncInventory = inventory.Sync
		}
		worker.Clients.TTL = g.ClientTTL
		historyPath := filepath.Join(cfg.StateDir, g.Identity.ID, "history.json")
		history, err := filestate.ReadHistory(historyPath, filestate.History{SourceID: g.Identity.ID, SourceURL: g.Source.URL, MAC: g.Identity.MAC})
		if err != nil {
			return err
		}
		worker.Clients.Entries, worker.WAN.Entries = history.Clients, history.WAN
		worker.WAN.MaxGap = 2 * g.Controller.Interval
		worker.Providers.Names = g.Source.ISPNames
		if g.Source.ISPLookup {
			worker.Providers.Lookup = cymru.Resolver{}.Lookup
		}
		worker.SaveHistory = func(clients []domain.Client, wan []domain.WANHistory) error {
			history.Clients, history.WAN = clients, wan
			return filestate.WriteJSON(historyPath, history)
		}
		if g.Discovery.Enabled {
			discoverer := &unifi.Discoverer{Identity: g.Identity, Targets: g.Discovery.Targets, Interval: g.Discovery.Interval}
			worker.Discover = discoverer.Send
		}
		previous, err := filestate.ReadStatus(filepath.Join(cfg.StateDir, g.Identity.ID, "status.json"), g.Identity.ID, time.Now())
		if err != nil {
			return fmt.Errorf("gateway %q status: %w", g.Identity.ID, err)
		}
		if previous.Available {
			worker.RestoreStatus(previous.Cycle)
		}
		worker.OnReset = func() error {
			for _, file := range []string{"route-plan.json", "configuration-plan.json", "pending-system-config.json", "virtual-system-config.json"} {
				err := os.Remove(filepath.Join(cfg.StateDir, g.Identity.ID, file))
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			return nil
		}
		worker.InvalidatePlans = worker.OnReset
		worker.MonitorOnly = g.Controller.Provisioning == "monitor"
		configFile := "pending-system-config.json"
		if worker.MonitorOnly {
			configFile = "virtual-system-config.json"
		}
		worker.RecordProvisioning = func(data []byte, version string) error {
			return filestate.WriteJSON(filepath.Join(cfg.StateDir, g.Identity.ID, configFile), struct {
				SourceID string          `json:"source_id"`
				MAC      string          `json:"mac"`
				Version  string          `json:"cfgversion"`
				Config   json.RawMessage `json:"system_cfg"`
			}{g.Identity.ID, g.Identity.MAC, version, json.RawMessage(data)})
		}
		if len(g.Routes.ControllerPath) > 0 {
			worker.Plan = func(ctx context.Context, data []byte, version string) error {
				desired, err := usecase.ExtractRoutes(data, routePolicy(g.Routes))
				if err != nil {
					return err
				}
				current, err := client.Routes(ctx)
				if err != nil {
					return err
				}
				plan, err := usecase.BuildRoutePlan(g.Identity, version, desired, current, routePolicy(g.Routes))
				if err != nil {
					return err
				}
				plan.SourceURL = strings.TrimRight(g.Source.URL, "/")
				return filestate.WriteJSON(filepath.Join(cfg.StateDir, g.Identity.ID, "route-plan.json"), plan)
			}
		}
		if len(g.Control.Extractors) > 0 {
			routePlan := worker.Plan
			worker.Plan = func(ctx context.Context, data []byte, version string) error {
				if routePlan != nil {
					if err := routePlan(ctx, data, version); err != nil {
						return err
					}
				}
				desired, err := usecase.ExtractConfiguration(data, g.Control.Extractors)
				if err != nil {
					return err
				}
				current, err := client.Configuration(ctx, usecase.ConfigurationKinds(desired))
				if err != nil {
					return err
				}
				plan, err := usecase.BuildConfigurationPlan(g.Identity, g.Source.URL, version, desired, current, g.Control.Policy)
				if err != nil {
					return err
				}
				return filestate.WriteJSON(filepath.Join(cfg.StateDir, g.Identity.ID, "configuration-plan.json"), plan)
			}
		}
		workers = append(workers, worker)
	}
	if *collect || *dryRun {
		return errors.Join(collectErrors...)
	}
	usecase.Run(ctx, workers, func(r usecase.CycleResult, err error) {
		if err != nil {
			r.Error = err.Error()
		}
		if statusErr := filestate.WriteJSON(filepath.Join(cfg.StateDir, r.SourceID, "status.json"), r); statusErr != nil {
			slog.Warn("status write failed", "source_id", r.SourceID, "err", statusErr)
		}
		if err != nil {
			slog.Warn("gateway cycle failed", "source_id", r.SourceID, "err", err, "next_delay", r.NextDelay)
			return
		}
		if r.Inventory != nil {
			if r.Inventory.Error != "" {
				slog.Warn("controller inventory sync failed", "source_id", r.SourceID, "err", r.Inventory.Error)
			} else if r.Inventory.Created > 0 || r.Inventory.Updated > 0 || r.Inventory.VLANsCreated > 0 || r.Inventory.VLANsUpdated > 0 || r.Inventory.AssignmentsUpdated {
				slog.Info("controller inventory synced", "source_id", r.SourceID, "created", r.Inventory.Created, "updated", r.Inventory.Updated, "vlans_created", r.Inventory.VLANsCreated, "vlans_updated", r.Inventory.VLANsUpdated, "assignments_updated", r.Inventory.AssignmentsUpdated)
			}
		}
		slog.Info("gateway cycle completed", "source_id", r.SourceID, "http_status", r.HTTPStatus, "response_type", r.ResponseType, "adopted", r.Adopted, "provisioning", r.Provisioning, "ignored_command", r.IgnoredCommand, "warnings", r.Warnings, "next_delay", r.NextDelay)
	})
	return nil
}

func openSource(g config.Gateway) (*opnsense.Client, *opnsense.Source, error) {
	httpClient, err := transport.NewClientWithTLS(g.Source.Timeout, transport.TLSOptions{CAFile: g.Source.CAFile, InsecureSkipVerify: g.Source.InsecureSkipVerify})
	if err != nil {
		return nil, nil, err
	}
	client, err := opnsense.NewClient(g.Source.URL, os.Getenv(g.Source.KeyEnv), os.Getenv(g.Source.SecretEnv), httpClient)
	if err != nil {
		return nil, nil, err
	}
	return client, &opnsense.Source{Client: client, Assignments: g.Controller.API != nil && g.Controller.API.SyncWANs, ID: g.Identity.ID, Statistics: g.Source.Statistics, System: g.Source.System, CPU: g.Source.CPU, Temperature: g.Source.Temperature, GatewayMonitors: g.Source.GatewayMonitors, Timeout: g.Source.Timeout, Neighbors: g.Source.Neighbors, DHCPBackends: g.Source.DHCPBackends, VLANs: g.Source.VLANs, FullInterval: time.Minute, Accounting: opnsense.AccountingOptions{Enabled: g.Source.Accounting.Enabled, Interfaces: g.Source.Accounting.Interfaces, Window: g.Source.Accounting.Window, MaxRows: g.Source.Accounting.MaxRows}}, nil
}

func printStatus(cfg config.Config) error {
	for _, g := range cfg.Gateways {
		s, err := filestate.ReadStatus(filepath.Join(cfg.StateDir, g.Identity.ID, "status.json"), g.Identity.ID, time.Now())
		if err != nil {
			return err
		}
		if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
			return err
		}
	}
	return nil
}

func collectOne(ctx context.Context, g config.Gateway, source domain.Source, dryRun bool, stateDir string) error {
	ctx, cancel := context.WithTimeout(ctx, g.Source.Timeout)
	defer cancel()
	snap, err := source.Collect(ctx)
	if err != nil {
		return err
	}
	tracker := usecase.ClientTracker{TTL: g.ClientTTL}
	snap = tracker.Apply(snap, g.Bindings)
	if g.HA != nil {
		ha := usecase.HATracker{Role: g.HA.Role, Peer: g.HA.Peer}
		snap = ha.Apply(snap, g.Bindings)
	}
	if !dryRun {
		return json.NewEncoder(os.Stdout).Encode(snap)
	}
	store := &filestate.Store{Path: filepath.Join(stateDir, g.Identity.ID, "adoption.json"), MAC: g.Identity.MAC}
	state, err := store.Load()
	if err != nil {
		return err
	}
	reportedURL, err := unifi.ResolveInformURL(ctx, g.Controller.URL)
	if err != nil {
		return err
	}
	b, err := unifi.Render(g.Identity, g.Bindings, g.UplinkInterface, snap, state, reportedURL, time.Second, g.Controller.MinInterval)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		SourceID string          `json:"source_id"`
		Payload  json.RawMessage `json:"payload"`
	}{SourceID: g.Identity.ID, Payload: b})
}

func routePolicy(p config.RoutePolicy) usecase.RoutePolicy {
	return usecase.RoutePolicy{AllowedNetworks: p.AllowedNetworks, GatewayMap: p.GatewayMap, ControllerPath: p.ControllerPath, NetworkField: p.NetworkField, GatewayField: p.GatewayField}
}

func applyPlan(ctx context.Context, cfg config.Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // Plan file cleanup.
	b, err := transport.ReadBody(f)
	if err != nil {
		return err
	}
	var plan domain.RoutePlan
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&plan); err != nil {
		return fmt.Errorf("decode route plan: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("route plan must contain one JSON document")
	}
	for _, g := range cfg.Gateways {
		if g.Identity.ID != plan.SourceID {
			continue
		}
		if !g.Routes.AllowApply {
			return fmt.Errorf("route apply is disabled for gateway %q", g.Identity.ID)
		}
		client, _, err := openSource(g)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		record := func(r domain.RouteApplyResult) error {
			return filestate.WriteJSON(filepath.Join(cfg.StateDir, g.Identity.ID, "route-apply.json"), r)
		}
		result, applyErr := usecase.ApplyRoutePlan(ctx, client, usecase.ApplyOptions{Plan: plan, Identity: g.Identity, SourceURL: strings.TrimRight(g.Source.URL, "/"), Policy: routePolicy(g.Routes), Record: record})
		journalErr := record(result)
		outputErr := json.NewEncoder(os.Stdout).Encode(result)
		return errors.Join(applyErr, journalErr, outputErr)
	}
	return fmt.Errorf("plan source is absent from configuration")
}
