package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// ConfigurationPolicy limits supported object additions to locally selected resources.
type ConfigurationPolicy struct {
	AllowedParents  []string          `yaml:"allowed_parents"`
	AllowedTags     []int             `yaml:"allowed_tags"`
	AllowedSubnets  map[string]string `yaml:"allowed_subnets"`
	AliasPrefix     string            `yaml:"alias_prefix"`
	AllowedNetworks []string          `yaml:"allowed_networks"`
}

// ConfigurationExtractor maps one captured controller array to canonical fields.
type ConfigurationExtractor struct {
	Kind   string                       `yaml:"kind"`
	Path   []string                     `yaml:"path"`
	Fields map[string]string            `yaml:"fields"`
	Values map[string]map[string]string `yaml:"values"`
}

// ConfigurationRepository inventories and creates supported objects.
type ConfigurationRepository interface {
	Configuration(context.Context, []string) ([]domain.ConfigObject, error)
	CreateConfiguration(context.Context, domain.ConfigObject) (string, error)
	ReconfigureConfiguration(context.Context, string) error
}

// ExtractConfiguration converts explicit controller field mappings into additions.
func ExtractConfiguration(data []byte, extractors []ConfigurationExtractor) ([]domain.ConfigObject, error) {
	var root any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	objects := []domain.ConfigObject{}
	for _, extractor := range extractors {
		current := root
		for _, key := range extractor.Path {
			obj, ok := current.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("configuration path must traverse objects")
			}
			current, ok = obj[key]
			if !ok {
				return nil, fmt.Errorf("configured controller path is missing")
			}
		}
		rows, ok := current.([]any)
		if !ok {
			return nil, fmt.Errorf("configured controller path must contain an array")
		}
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("controller configuration row must be an object")
			}
			object := domain.ConfigObject{Kind: extractor.Kind, Fields: map[string]string{}}
			for canonical, key := range extractor.Fields {
				var value string
				switch raw := row[key].(type) {
				case string:
					value = raw
				case json.Number:
					value = raw.String()
				default:
					return nil, fmt.Errorf("controller configuration field has an unsupported type")
				}
				if mapping := extractor.Values[canonical]; mapping != nil {
					mapped, ok := mapping[value]
					if !ok {
						return nil, fmt.Errorf("controller configuration field lacks a local value mapping")
					}
					value = mapped
				}
				object.Fields[canonical] = value
			}
			objects = append(objects, object)
		}
	}
	return objects, nil
}

// ConfigurationKinds returns the sorted feature set required by the additions.
func ConfigurationKinds(objects []domain.ConfigObject) []string {
	seen := map[string]bool{}
	for _, object := range objects {
		seen[object.Kind] = true
	}
	kinds := make([]string, 0, len(seen))
	for kind := range seen {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// BuildConfigurationPlan validates additions and rejects conflicting existing keys.
func BuildConfigurationPlan(id domain.Identity, url, version string, desired, current []domain.ConfigObject, policy ConfigurationPolicy) (domain.ConfigurationPlan, error) {
	baseline := append([]domain.ConfigObject{}, current...)
	sort.Slice(baseline, func(i, j int) bool {
		a, b := baseline[i], baseline[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Key < b.Key
	})
	b, err := json.Marshal(baseline)
	if err != nil {
		return domain.ConfigurationPlan{}, err
	}
	sum := sha256.Sum256(b)
	plan := domain.ConfigurationPlan{SourceID: id.ID, SourceURL: url, MAC: id.MAC, CFGVersion: version, Baseline: hex.EncodeToString(sum[:]), Kinds: ConfigurationKinds(desired), Additions: []domain.ConfigObject{}}
	seen := map[string]bool{}
	for _, object := range desired {
		if object.Disabled {
			return plan, fmt.Errorf("configuration additions must be enabled")
		}
		object, err = validateConfiguration(object, policy)
		if err != nil {
			return plan, err
		}
		key := object.Kind + "/" + object.Key
		if seen[key] {
			return plan, fmt.Errorf("duplicate desired configuration key")
		}
		seen[key] = true
		exists := false
		for _, old := range current {
			if object.Kind == "reservation" && old.Kind == "reservation" && old.Fields["subnet"] == object.Fields["subnet"] && old.Fields["ip"] == object.Fields["ip"] && old.Key != object.Key {
				return plan, fmt.Errorf("reservation address conflicts with an existing MAC")
			}
			if old.Kind == object.Kind && old.Key == object.Key {
				if old.Disabled || !reflect.DeepEqual(old.Fields, object.Fields) {
					return plan, fmt.Errorf("configuration conflicts with an existing object")
				}
				exists = true
			}
		}
		if !exists {
			for _, planned := range plan.Additions {
				if object.Kind == "reservation" && planned.Kind == "reservation" && planned.Fields["subnet"] == object.Fields["subnet"] && planned.Fields["ip"] == object.Fields["ip"] {
					return plan, fmt.Errorf("duplicate desired reservation address")
				}
			}
			plan.Additions = append(plan.Additions, object)
		}
	}
	sort.Slice(plan.Additions, func(i, j int) bool {
		a, b := plan.Additions[i], plan.Additions[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Key < b.Key
	})
	return plan, nil
}

func validateConfiguration(object domain.ConfigObject, policy ConfigurationPolicy) (domain.ConfigObject, error) {
	fields := map[string]string{}
	for key, value := range object.Fields {
		fields[key] = value
	}
	object.Fields = fields
	allowed := map[string]bool{"description": true}
	key := ""
	contains := func(values []string, value string) bool {
		for _, item := range values {
			if item == value {
				return true
			}
		}
		return false
	}
	switch object.Kind {
	case "vlan":
		allowed["parent"], allowed["tag"] = true, true
		if !contains(policy.AllowedParents, fields["parent"]) {
			return object, fmt.Errorf("VLAN parent is outside policy")
		}
		tag, err := strconv.Atoi(fields["tag"])
		if err != nil || tag < 1 || tag > 4094 {
			return object, fmt.Errorf("invalid VLAN tag")
		}
		permitted := false
		for _, n := range policy.AllowedTags {
			if tag == n {
				permitted = true
			}
		}
		if !permitted {
			return object, fmt.Errorf("VLAN tag is outside policy")
		}
		fields["tag"] = strconv.Itoa(tag)
		key = fields["parent"] + "/" + fields["tag"]
	case "reservation":
		for _, field := range []string{"subnet", "ip", "mac", "hostname"} {
			allowed[field] = true
		}
		prefix, ok := policy.AllowedSubnets[fields["subnet"]]
		if !ok {
			return object, fmt.Errorf("reservation subnet is outside policy")
		}
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			return object, fmt.Errorf("invalid reservation subnet policy")
		}
		ip, err := netip.ParseAddr(fields["ip"])
		if err != nil || !ip.Is4() || ip.IsUnspecified() || !p.Contains(ip) {
			return object, fmt.Errorf("reservation address is outside subnet")
		}
		fields["ip"] = ip.String()
		fields["mac"] = CanonicalMAC(fields["mac"])
		if fields["mac"] == "" {
			return object, fmt.Errorf("reservation requires a unicast MAC")
		}
		if fields["hostname"] != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`).MatchString(fields["hostname"]) {
			return object, fmt.Errorf("invalid reservation hostname")
		}
		key = fields["subnet"] + "/" + fields["mac"]
	case "alias":
		allowed["name"], allowed["type"], allowed["content"] = true, true, true
		if policy.AliasPrefix == "" || !strings.HasPrefix(fields["name"], policy.AliasPrefix) || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}$`).MatchString(fields["name"]) {
			return object, fmt.Errorf("alias name is outside policy")
		}
		if fields["type"] != "host" && fields["type"] != "network" {
			return object, fmt.Errorf("only address-based aliases are supported")
		}
		values := strings.Split(fields["content"], "\n")
		if len(values) == 0 || len(values) > 1024 {
			return object, fmt.Errorf("invalid alias content")
		}
		for _, value := range values {
			var prefix netip.Prefix
			if fields["type"] == "host" {
				ip, err := netip.ParseAddr(value)
				if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
					return object, fmt.Errorf("invalid alias host")
				}
				prefix = netip.PrefixFrom(ip, ip.BitLen())
			} else {
				p, err := netip.ParsePrefix(value)
				if err != nil || p != p.Masked() || p.Bits() == 0 {
					return object, fmt.Errorf("invalid alias network")
				}
				prefix = p
			}
			permitted := false
			for _, n := range policy.AllowedNetworks {
				p, err := netip.ParsePrefix(n)
				if err == nil && p.Addr().BitLen() == prefix.Addr().BitLen() && p.Bits() <= prefix.Bits() && p.Contains(prefix.Addr()) {
					permitted = true
				}
			}
			if !permitted {
				return object, fmt.Errorf("alias content is outside policy")
			}
		}
		sort.Strings(values)
		fields["content"] = strings.Join(values, "\n")
		key = fields["name"]
	default:
		return object, fmt.Errorf("unsupported configuration feature")
	}
	for field := range fields {
		if !allowed[field] {
			return object, fmt.Errorf("unsupported configuration field %q", field)
		}
	}
	if len(fields["description"]) > 256 {
		return object, fmt.Errorf("configuration description is too long")
	}
	if _, exists := fields["description"]; !exists {
		fields["description"] = ""
	}
	if object.Kind == "reservation" {
		if _, exists := fields["hostname"]; !exists {
			fields["hostname"] = ""
		}
	}
	if object.Key != "" && object.Key != key {
		return object, fmt.Errorf("configuration key does not match its fields")
	}
	object.Key = key
	return object, nil
}

// ApplyConfigurationPlan checks identity, policy, and baseline before journaled writes.
func ApplyConfigurationPlan(ctx context.Context, repo ConfigurationRepository, plan domain.ConfigurationPlan, id domain.Identity, url string, policy ConfigurationPolicy, record func(domain.ConfigurationApplyResult) error) (domain.ConfigurationApplyResult, error) {
	result := domain.ConfigurationApplyResult{SourceID: id.ID, AddedUUIDs: []string{}}
	if plan.SourceID != id.ID || plan.MAC != id.MAC || plan.SourceURL != url {
		return result, fmt.Errorf("configuration plan belongs to another appliance")
	}
	listed := map[string]bool{}
	for _, kind := range plan.Kinds {
		if listed[kind] || (kind != "vlan" && kind != "reservation" && kind != "alias") {
			return result, fmt.Errorf("invalid plan inventory scope")
		}
		listed[kind] = true
	}
	for _, object := range plan.Additions {
		if !listed[object.Kind] {
			return result, fmt.Errorf("plan omitted a feature from its inventory scope")
		}
	}
	current, err := repo.Configuration(ctx, plan.Kinds)
	if err != nil {
		return result, err
	}
	fresh, err := BuildConfigurationPlan(id, url, plan.CFGVersion, plan.Additions, current, policy)
	if err != nil {
		return result, err
	}
	if fresh.Baseline != plan.Baseline || len(fresh.Additions) != len(plan.Additions) {
		return result, fmt.Errorf("configuration inventory changed; review a new plan")
	}
	journal := func(stage string) error {
		result.Stage = stage
		if record != nil {
			return record(result)
		}
		return nil
	}
	changed := map[string]bool{}
	for _, object := range fresh.Additions {
		result.InFlightKey = object.Kind + "/" + object.Key
		if err := journal("adding"); err != nil {
			return result, err
		}
		uuid, err := repo.CreateConfiguration(ctx, object)
		if err != nil {
			return result, err
		}
		result.AddedUUIDs = append(result.AddedUUIDs, uuid)
		result.InFlightKey = ""
		changed[object.Kind] = true
		if err := journal("saved"); err != nil {
			return result, err
		}
	}
	for _, kind := range plan.Kinds {
		if changed[kind] {
			result.InFlightKey = kind
			if err := journal("reconfiguring"); err != nil {
				return result, err
			}
			if err := repo.ReconfigureConfiguration(ctx, kind); err != nil {
				return result, err
			}
		}
	}
	result.InFlightKey = ""
	updated, err := repo.Configuration(ctx, plan.Kinds)
	if err != nil {
		return result, err
	}
	verify, err := BuildConfigurationPlan(id, url, plan.CFGVersion, plan.Additions, updated, policy)
	if err != nil {
		return result, err
	}
	if len(verify.Additions) != 0 {
		return result, fmt.Errorf("configuration readback did not match plan")
	}
	result.Verified = true
	return result, journal("verified")
}
