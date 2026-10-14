package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

func (s *Source) collectTelemetry(ctx context.Context, snap *domain.Snapshot) {
	if s.System {
		if err := s.systemInfo(ctx, &snap.System); err != nil {
			snap.Warnings = append(snap.Warnings, "system_information_unavailable")
		}
		if err := s.systemTime(ctx, &snap.System); err != nil {
			snap.Warnings = append(snap.Warnings, "system_time_unavailable")
		}
		if err := s.memory(ctx, &snap.System); err != nil {
			snap.Warnings = append(snap.Warnings, "system_resources_unavailable")
		}
	}
	if s.CPU {
		cpuCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		cpu, err := s.Client.CPUUsage(cpuCtx)
		cancel()
		if err != nil {
			snap.Warnings = append(snap.Warnings, "cpu_usage_unavailable")
		} else {
			snap.System.CPUPercent = &cpu
		}
	}
	if s.Temperature {
		if err := s.temperatures(ctx, &snap.System); err != nil {
			snap.Warnings = append(snap.Warnings, "system_temperature_unavailable")
		}
	}
	if len(s.GatewayMonitors) > 0 {
		gateways, err := s.gatewayStatus(ctx)
		if err != nil {
			snap.Warnings = append(snap.Warnings, "gateway_status_unavailable")
		} else {
			snap.Gateways = gateways
		}
	}
}

func (s *Source) systemInfo(ctx context.Context, out *domain.System) error {
	var response struct {
		Name     string   `json:"name"`
		Versions []string `json:"versions"`
	}
	if err := s.Client.request(ctx, httpGET, "/diagnostics/system/system_information", nil, &response); err != nil {
		return err
	}
	if response.Name == "" && len(response.Versions) == 0 {
		return fmt.Errorf("system information omitted recognized fields")
	}
	out.Hostname, out.Versions = response.Name, response.Versions
	return nil
}

func (s *Source) systemTime(ctx context.Context, out *domain.System) error {
	var response struct {
		Uptime string `json:"uptime"`
		Load   string `json:"loadavg"`
	}
	if err := s.Client.request(ctx, httpGET, "/diagnostics/system/system_time", nil, &response); err != nil {
		return err
	}
	uptime, err := parseUptime(response.Uptime)
	if err != nil {
		return err
	}
	out.UptimeSeconds = &uptime
	parts := strings.Split(response.Load, ",")
	if len(parts) == 3 {
		load := make([]float64, 0, 3)
		for _, part := range parts {
			value, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
			if err != nil || !finite(value) || value < 0 {
				return fmt.Errorf("invalid system load average")
			}
			load = append(load, value)
		}
		out.LoadAverage = load
	}
	return nil
}

func (s *Source) memory(ctx context.Context, out *domain.System) error {
	var response struct {
		Memory struct {
			Total json.RawMessage `json:"total"`
			Used  json.RawMessage `json:"used"`
		} `json:"memory"`
	}
	if err := s.Client.request(ctx, httpGET, "/diagnostics/system/system_resources", nil, &response); err != nil {
		return err
	}
	total, err := numeric(response.Memory.Total, "")
	if err != nil {
		return err
	}
	used, err := numeric(response.Memory.Used, "")
	if err != nil {
		return err
	}
	if total == nil || used == nil {
		return nil
	}
	if *total <= 0 || *total > 1<<53 || *used < 0 || *used > *total || math.Trunc(*total) != *total || math.Trunc(*used) != *used {
		return fmt.Errorf("invalid memory measurement")
	}
	t, u := uint64(*total), uint64(*used)
	out.MemoryTotalBytes, out.MemoryUsedBytes = &t, &u
	return nil
}

func (s *Source) temperatures(ctx context.Context, out *domain.System) error {
	var response []struct {
		Device      string          `json:"device"`
		Type        string          `json:"type"`
		Temperature json.RawMessage `json:"temperature"`
	}
	if err := s.Client.request(ctx, httpGET, "/diagnostics/system/system_temperature", nil, &response); err != nil {
		return err
	}
	sensors := make([]domain.Temperature, 0, len(response))
	for _, row := range response {
		value, err := numeric(row.Temperature, "C")
		if err != nil {
			return err
		}
		if value == nil {
			continue
		}
		if row.Device == "" || *value < -273.15 {
			return fmt.Errorf("invalid sensor measurement")
		}
		sensors = append(sensors, domain.Temperature{Name: row.Device, Type: row.Type, Celsius: *value})
	}
	sort.Slice(sensors, func(i, j int) bool { return sensors[i].Name < sensors[j].Name })
	out.Temperatures = sensors
	return nil
}

func (s *Source) gatewayStatus(ctx context.Context) ([]domain.GatewayMonitor, error) {
	var response struct {
		Status string `json:"status"`
		Items  []struct {
			Name   string          `json:"name"`
			Status string          `json:"status"`
			Delay  json.RawMessage `json:"delay"`
			Loss   json.RawMessage `json:"loss"`
		} `json:"items"`
	}
	if err := s.Client.request(ctx, httpGET, "/routes/gateway/status", nil, &response); err != nil {
		return nil, err
	}
	if response.Status != "ok" || response.Items == nil {
		return nil, fmt.Errorf("gateway status table is unavailable")
	}
	byName := make(map[string]domain.GatewayMonitor, len(response.Items))
	for _, row := range response.Items {
		if row.Name == "" {
			return nil, fmt.Errorf("gateway status omitted monitor name")
		}
		if _, exists := byName[row.Name]; exists {
			return nil, fmt.Errorf("duplicate gateway monitor")
		}
		latency, err := numeric(row.Delay, "ms")
		if err != nil {
			return nil, err
		}
		loss, err := numeric(row.Loss, "%")
		if err != nil {
			return nil, err
		}
		if latency != nil && (*latency < 0 || *latency > math.MaxInt32) || loss != nil && (*loss < 0 || *loss > 100) {
			return nil, fmt.Errorf("invalid gateway monitor metrics")
		}
		monitor := domain.GatewayMonitor{Name: row.Name, Status: row.Status, LatencyMS: latency, LossPercent: loss}
		status := strings.ToLower(strings.TrimSpace(row.Status))
		switch status {
		case "none", "online", "up":
			value := true
			monitor.Connected = &value
		case "down", "offline":
			value := false
			monitor.Connected = &value
		}
		byName[row.Name] = monitor
	}
	out := make([]domain.GatewayMonitor, 0, len(s.GatewayMonitors))
	for role, name := range s.GatewayMonitors {
		monitor, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("configured gateway monitor is missing")
		}
		monitor.Role = role
		out = append(out, monitor)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out, nil
}

func numeric(raw json.RawMessage, unit string) (*float64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	text := string(raw)
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, err
		}
	}
	text = strings.TrimSpace(text)
	switch text {
	case "", "~", "N/A", "n/a":
		return nil, nil
	}
	if unit != "" {
		text = strings.TrimSpace(strings.TrimSuffix(text, unit))
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || !finite(value) {
		return nil, fmt.Errorf("invalid numeric measurement")
	}
	return &value, nil
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func parseUptime(text string) (int64, error) {
	// The API's optional day label is localized; only its count is significant.
	days, clock := int64(0), strings.TrimSpace(text)
	if before, after, ok := strings.Cut(clock, ","); ok {
		parts := strings.Fields(before)
		if len(parts) < 2 {
			return 0, fmt.Errorf("invalid appliance uptime")
		}
		value, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || value < 0 || value > 365000 {
			return 0, fmt.Errorf("invalid appliance uptime")
		}
		days, clock = value, strings.TrimSpace(after)
	}
	parts := strings.Split(clock, ":")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid appliance uptime")
	}
	var values [3]int64
	for i, part := range parts {
		value, err := strconv.ParseInt(part, 10, 64)
		if err != nil || value < 0 {
			return 0, fmt.Errorf("invalid appliance uptime")
		}
		values[i] = value
	}
	if values[0] > 23 || values[1] > 59 || values[2] > 59 {
		return 0, fmt.Errorf("invalid appliance uptime")
	}
	return days*86400 + values[0]*3600 + values[1]*60 + values[2], nil
}
