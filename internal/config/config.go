// Package config loads operator configuration and credential environment names.
package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/usecase"
	"gopkg.in/yaml.v3"
)

// Config lists independent appliance-to-virtual-gateway bridges.
type Config struct {
	StateDir string    `yaml:"state_dir"`
	Gateways []Gateway `yaml:"gateways"`
}

// Gateway configures one real source and its fake identity.
type Gateway struct {
	HA         *HA              `yaml:"ha"`
	Identity   domain.Identity  `yaml:"identity"`
	Source     Source           `yaml:"source"`
	Controller Controller       `yaml:"controller"`
	Bindings   []domain.Binding `yaml:"bindings"`
	// UplinkInterface selects a source LAN interface or VLAN for UniFi's uplink field.
	UplinkInterface string        `yaml:"uplink_interface"`
	Routes          RoutePolicy   `yaml:"routes"`
	ClientTTL       time.Duration `yaml:"client_ttl"`
	Discovery       Discovery     `yaml:"discovery"`
	Control         Control       `yaml:"control"`
}

// HA opts a reciprocal Enterprise pair into read-only managed-shadow reporting.
type HA struct {
	Role string `yaml:"role"`
	Peer string `yaml:"peer"`
}

// Control configures write policy and explicit controller-field projections.
type Control struct {
	AllowApply bool                             `yaml:"allow_apply"`
	Policy     usecase.ConfigurationPolicy      `yaml:"policy"`
	Extractors []usecase.ConfigurationExtractor `yaml:"extractors"`
}

// Source supplies OPNsense connection settings and credential environment names.
type Source struct {
	URL                string            `yaml:"url"`
	KeyEnv             string            `yaml:"key_env"`
	SecretEnv          string            `yaml:"secret_env"`
	CAFile             string            `yaml:"ca_file"`
	InsecureSkipVerify bool              `yaml:"insecure_skip_verify"`
	Timeout            time.Duration     `yaml:"timeout"`
	Statistics         bool              `yaml:"statistics"`
	System             bool              `yaml:"system"`
	CPU                bool              `yaml:"cpu"`
	Temperature        bool              `yaml:"temperature"`
	GatewayMonitors    map[string]string `yaml:"gateway_monitors"`
	Neighbors          bool              `yaml:"neighbors"`
	DHCPBackends       []string          `yaml:"dhcp_backends"`
	VLANs              bool              `yaml:"vlans"`
	Accounting         Accounting        `yaml:"accounting"`
}

// Accounting selects IP flow queries and the observation interval.
type Accounting struct {
	Enabled    bool          `yaml:"enabled"`
	Interfaces []string      `yaml:"interfaces"`
	Window     time.Duration `yaml:"window"`
	MaxRows    int           `yaml:"max_rows"`
}

// Discovery sends announcements only to explicitly configured targets.
type Discovery struct {
	Enabled  bool          `yaml:"enabled"`
	Targets  []string      `yaml:"targets"`
	Interval time.Duration `yaml:"interval"`
}

// Controller settings are local; provisioning cannot redirect the inform target.
type Controller struct {
	API          *ControllerAPI `yaml:"api"`
	Provisioning string         `yaml:"provisioning"`
	URL          string         `yaml:"url"`
	CAFile       string         `yaml:"ca_file"`
	Interval     time.Duration  `yaml:"interval"`
	Timeout      time.Duration  `yaml:"timeout"`
}

// ControllerAPI enables OPNsense-to-UniFi WAN inventory mirroring.
type ControllerAPI struct {
	URLEnv        string `yaml:"url_env"`
	KeyEnv        string `yaml:"key_env"`
	Site          string `yaml:"site"`
	NetworkPath   string `yaml:"network_path"`
	SyncWANs      bool   `yaml:"sync_wans"`
	SyncVLANs     bool   `yaml:"sync_vlans"`
	DisabledPorts []int  `yaml:"disabled_ports"`
}

// RoutePolicy restricts review plans and defines capture-derived field mappings.
// Controller fields deliberately have no defaults; configure them from a capture.
type RoutePolicy struct {
	AllowApply      bool              `yaml:"allow_apply"`
	AllowedNetworks []string          `yaml:"allowed_networks"`
	GatewayMap      map[string]string `yaml:"gateway_map"`
	ControllerPath  []string          `yaml:"controller_path"`
	NetworkField    string            `yaml:"network_field"`
	GatewayField    string            `yaml:"gateway_field"`
}

// Load reads a single YAML document, rejects unknown fields, and validates it.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("config must contain one YAML document")
	}
	if c.StateDir == "" {
		c.StateDir = "state"
	}
	for i := range c.Gateways {
		g := &c.Gateways[i]
		if g.Source.Timeout == 0 {
			g.Source.Timeout = 10 * time.Second
		}
		if g.ClientTTL == 0 {
			g.ClientTTL = 5 * time.Minute
		}
		if g.Discovery.Interval == 0 {
			g.Discovery.Interval = time.Minute
		}
		if g.Source.Accounting.Window == 0 {
			g.Source.Accounting.Window = 5 * time.Minute
		}
		if g.Source.Accounting.MaxRows == 0 {
			g.Source.Accounting.MaxRows = 10000
		}
		if g.Controller.Timeout == 0 {
			g.Controller.Timeout = 10 * time.Second
		}
		if g.Controller.Interval == 0 {
			g.Controller.Interval = 10 * time.Second
		}
		if g.Controller.Provisioning == "" {
			g.Controller.Provisioning = "review"
		}
		if a := g.Controller.API; a != nil {
			if a.URLEnv == "" {
				a.URLEnv = "UNIFI_URL"
			}
			if a.KeyEnv == "" {
				a.KeyEnv = "UNIFI_API_KEY"
			}
			if a.NetworkPath == "" {
				a.NetworkPath = "/proxy/network"
			}
		}
	}
	return c, c.Validate()
}

// Validate enforces unique identities, explicit bindings, and bounded settings.
func (c Config) Validate() error {
	if len(c.Gateways) == 0 {
		return fmt.Errorf("at least one gateway is required")
	}
	ids, macs := map[string]bool{}, map[string]bool{}
	safeID := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
	for _, g := range c.Gateways {
		id := g.Identity
		if g.HA != nil {
			if id.Model != "UXGENT" || g.Controller.Provisioning != "monitor" || (g.HA.Role != "primary" && g.HA.Role != "shadow") || g.HA.Peer == id.ID {
				return fmt.Errorf("gateway %q has invalid Enterprise HA settings", id.ID)
			}
			found := false
			for _, peer := range c.Gateways {
				if peer.Identity.ID != g.HA.Peer {
					continue
				}
				found = true
				if peer.HA == nil || peer.Identity.Model != "UXGENT" || peer.HA.Peer != id.ID || peer.HA.Role == g.HA.Role || peer.Controller.URL != g.Controller.URL {
					return fmt.Errorf("gateway %q requires a reciprocal Enterprise peer on the same controller", id.ID)
				}
			}
			if !found {
				return fmt.Errorf("gateway %q references a missing HA peer", id.ID)
			}
		}
		if !safeID.MatchString(id.ID) || ids[id.ID] {
			return fmt.Errorf("invalid or duplicate gateway id %q", id.ID)
		}
		ids[id.ID] = true
		mac, err := net.ParseMAC(id.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || macs[mac.String()] {
			return fmt.Errorf("gateway %q requires a unique unicast MAC", id.ID)
		}
		macs[mac.String()] = true
		if id.Hostname == "" {
			return fmt.Errorf("gateway %q requires hostname", id.ID)
		}
		if _, err := netip.ParseAddr(id.ManagementIP); err != nil {
			return fmt.Errorf("gateway %q requires management_ip", id.ID)
		}
		count := 0
		switch id.Model {
		case "UXG":
			count = 2
		case "UXGPRO":
			count = 4
		case "UXGENT":
			count = 6
		default:
			return fmt.Errorf("unsupported gateway model %q", id.Model)
		}
		if err := ValidateURL(g.Source.URL, true); err != nil {
			return fmt.Errorf("source %q: %w", id.ID, err)
		}
		if g.Source.KeyEnv == "" || g.Source.SecretEnv == "" {
			return fmt.Errorf("source %q requires credential environment names", id.ID)
		}
		if g.Controller.URL != "" {
			if err := ValidateURL(g.Controller.URL, false); err != nil {
				return fmt.Errorf("controller %q: %w", id.ID, err)
			}
		}
		if g.Source.Timeout <= 0 || g.Source.Timeout > time.Minute || g.Controller.Timeout <= 0 || g.Controller.Timeout > time.Minute || g.Controller.Interval < 5*time.Second || g.Controller.Interval > time.Minute {
			return fmt.Errorf("gateway %q has invalid timeout or interval", id.ID)
		}
		if g.Controller.Provisioning != "review" && g.Controller.Provisioning != "monitor" {
			return fmt.Errorf("gateway %q provisioning must be review or monitor", id.ID)
		}
		if g.Controller.Provisioning == "monitor" && (g.Control.AllowApply || g.Routes.AllowApply) {
			return fmt.Errorf("gateway %q monitoring mode cannot enable configuration writes", id.ID)
		}
		if a := g.Controller.API; a != nil {
			if a.URLEnv == "" || a.KeyEnv == "" || a.NetworkPath != "/proxy/network" && a.NetworkPath != "/" {
				return fmt.Errorf("gateway %q has invalid controller API settings", id.ID)
			}
			if a.SyncVLANs && !g.Source.VLANs {
				return fmt.Errorf("gateway %q requires source.vlans for controller VLAN sync", id.ID)
			}
			if a.Site != "" && !safeID.MatchString(a.Site) {
				return fmt.Errorf("gateway %q has invalid controller site", id.ID)
			}
		}
		ports, ifaces, roles := map[int]bool{}, map[string]bool{}, map[string]bool{}
		if len(g.Bindings) == 0 {
			return fmt.Errorf("gateway %q requires bindings", id.ID)
		}
		for _, b := range g.Bindings {
			if b.Port < 1 || b.Port > count || ports[b.Port] || b.Interface == "" || ifaces[b.Interface] {
				return fmt.Errorf("gateway %q has invalid or duplicate binding", id.ID)
			}
			ports[b.Port], ifaces[b.Interface] = true, true
			switch b.Role {
			case "wan", "wan2", "lan", "lan2":
			default:
				return fmt.Errorf("invalid role %q", b.Role)
			}
			if roles[b.Role] {
				return fmt.Errorf("duplicate role %q", b.Role)
			}
			roles[b.Role] = true
		}
		if g.UplinkInterface != "" && !roles["lan"] && !roles["lan2"] {
			return fmt.Errorf("gateway %q uplink_interface requires a LAN binding", id.ID)
		}
		if api := g.Controller.API; api != nil {
			if len(api.DisabledPorts) > 0 && !api.SyncWANs && !api.SyncVLANs {
				return fmt.Errorf("gateway %q requires controller API sync to manage disabled ports", id.ID)
			}
			disabled := map[int]bool{}
			for _, port := range api.DisabledPorts {
				if port < 1 || port > count || ports[port] || disabled[port] {
					return fmt.Errorf("gateway %q has an invalid or already bound disabled controller port", id.ID)
				}
				disabled[port] = true
			}
		}
		for role, name := range g.Source.GatewayMonitors {
			if (role != "wan" && role != "wan2") || name == "" || !roles[role] {
				return fmt.Errorf("gateway %q has invalid WAN monitor mapping", id.ID)
			}
		}
		if g.ClientTTL < time.Second || g.ClientTTL > 24*time.Hour {
			return fmt.Errorf("invalid client TTL")
		}
		for _, extractor := range g.Control.Extractors {
			if len(extractor.Path) == 0 || len(extractor.Fields) == 0 || (extractor.Kind != "vlan" && extractor.Kind != "reservation" && extractor.Kind != "alias") {
				return fmt.Errorf("invalid controller configuration extractor")
			}
		}
		for _, tag := range g.Control.Policy.AllowedTags {
			if tag < 1 || tag > 4094 {
				return fmt.Errorf("invalid allowed VLAN tag")
			}
		}
		for _, prefix := range g.Control.Policy.AllowedSubnets {
			if _, err := netip.ParsePrefix(prefix); err != nil {
				return fmt.Errorf("invalid reservation subnet policy")
			}
		}
		for _, prefix := range g.Control.Policy.AllowedNetworks {
			if _, err := netip.ParsePrefix(prefix); err != nil {
				return fmt.Errorf("invalid alias network policy")
			}
		}
		backends := map[string]bool{}
		for _, backend := range g.Source.DHCPBackends {
			if backends[backend] {
				return fmt.Errorf("duplicate DHCP backend")
			}
			backends[backend] = true
			switch backend {
			case "kea4", "kea6", "dnsmasq":
			default:
				return fmt.Errorf("unsupported DHCP backend %q", backend)
			}
		}
		if g.Source.Accounting.Enabled && (len(g.Source.Accounting.Interfaces) == 0 || g.Source.Accounting.Window < time.Minute || g.Source.Accounting.Window > 24*time.Hour || g.Source.Accounting.MaxRows < 1 || g.Source.Accounting.MaxRows > 100000) {
			return fmt.Errorf("invalid accounting configuration")
		}
		points := map[string]bool{}
		for _, point := range g.Source.Accounting.Interfaces {
			if points[point] || !regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`).MatchString(point) {
				return fmt.Errorf("invalid or duplicate accounting interface")
			}
			points[point] = true
		}
		if g.Discovery.Enabled {
			if len(g.Discovery.Targets) == 0 || g.Discovery.Interval < 5*time.Second || g.Discovery.Interval > time.Hour {
				return fmt.Errorf("invalid discovery configuration")
			}
			if ip := net.ParseIP(id.ManagementIP); ip.To4() == nil {
				return fmt.Errorf("discovery requires an IPv4 identity address")
			}
			for _, target := range g.Discovery.Targets {
				host, port, err := net.SplitHostPort(target)
				if err != nil || host == "" || port != "10001" {
					return fmt.Errorf("discovery targets must use host:10001")
				}
			}
		}
		for _, n := range g.Routes.AllowedNetworks {
			if _, err := netip.ParsePrefix(n); err != nil {
				return fmt.Errorf("invalid route allowlist prefix %q", n)
			}
		}
		if len(g.Routes.ControllerPath) > 0 && (g.Routes.NetworkField == "" || g.Routes.GatewayField == "" || len(g.Routes.GatewayMap) == 0 || len(g.Routes.AllowedNetworks) == 0) {
			return fmt.Errorf("gateway %q requires complete route extraction and policy", id.ID)
		}
	}
	return nil
}

// ValidateURL rejects userinfo, query strings, and fragments. Sources require TLS.
func ValidateURL(raw string, source bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("invalid endpoint URL")
	}
	if source && (u.Scheme != "https" || strings.Trim(u.Path, "/") != "") {
		return fmt.Errorf("OPNsense URL must be an HTTPS origin")
	}
	if !source && (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("inform URL must use HTTP or HTTPS")
	}
	return nil
}
