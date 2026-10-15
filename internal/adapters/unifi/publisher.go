package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jamesbraid/unifi-emu/inform"
	"github.com/ygelfand/opnsense-uxg/internal/domain"
	"github.com/ygelfand/opnsense-uxg/internal/transport"
)

// Publisher represents a single virtual UXG protocol session.
type Publisher struct {
	Identity domain.Identity
	Bindings []domain.Binding
	// UplinkInterface is the configured source interface reported to UniFi.
	UplinkInterface string
	MinInterval     time.Duration
	URL             string
	Client          *http.Client
	StartedAt       time.Time
	Now             func() time.Time
	commands        commandCache
	reportedURL     string
}

type packetDecodeError struct{ err error }

func (e *packetDecodeError) Error() string { return "decode inform response: " + e.err.Error() }
func (e *packetDecodeError) Unwrap() error { return e.err }

var _ domain.Publisher = (*Publisher)(nil)

// Publish sends fresh observations and returns sanitized adoption transitions.
func (p *Publisher) Publish(ctx context.Context, snap domain.Snapshot, state domain.Adoption) (domain.Exchange, error) {
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	if p.reportedURL == "" {
		resolved, err := ResolveInformURL(ctx, p.URL)
		if err != nil {
			return domain.Exchange{}, err
		}
		p.reportedURL = resolved
	}
	payload, err := Render(p.Identity, p.Bindings, p.UplinkInterface, snap, state, p.reportedURL, now().Sub(p.StartedAt), p.MinInterval)
	if err != nil {
		return domain.Exchange{}, err
	}
	payload, err = p.commands.attach(payload)
	if err != nil {
		return domain.Exchange{}, err
	}
	modes := []bool{state.UseGCM}
	if state.AuthKey != "" && !state.UseGCM {
		modes = []bool{true, false}
	}
	var ex domain.Exchange
	for i, gcm := range modes {
		ex, err = p.exchange(ctx, payload, state, gcm)
		ex.CipherFallback = i > 0
		var decodeErr *packetDecodeError
		if i == 0 && len(modes) > 1 && (errors.As(err, &decodeErr) || err == nil && ex.HTTPStatus != http.StatusOK) {
			continue
		}
		break
	}
	ex.CommandStatus = p.commands.status
	if err != nil || ex.HTTPStatus != http.StatusOK {
		return ex, err
	}
	p.commands.delivered()
	if ex.ResetRequested {
		p.commands = commandCache{}
	} else {
		if err := p.commands.queue(ex.Command); err != nil {
			return ex, err
		}
	}
	ex.CommandStatus = p.commands.status
	return ex, nil
}

func (p *Publisher) exchange(ctx context.Context, payload []byte, state domain.Adoption, gcm bool) (domain.Exchange, error) {
	ex := domain.Exchange{Adoption: state, Cipher: "aes-cbc"}
	if gcm {
		ex.Cipher = "aes-gcm"
	}
	packet, err := EncodePacket(p.Identity.MAC, state.AuthKey, gcm, payload)
	if err != nil {
		return ex, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, bytes.NewReader(packet))
	if err != nil {
		return ex, err
	}
	req.Header.Set("Content-Type", "application/x-binary")
	req.Header.Set("Accept", "application/x-binary")
	req.Header.Set("User-Agent", "AirControl Agent v1.0")
	resp, err := p.Client.Do(req)
	if err != nil {
		return ex, fmt.Errorf("inform exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // Response cleanup after bounded consumption.
	body, err := transport.ReadBody(resp.Body)
	ex.HTTPStatus = resp.StatusCode
	if err != nil {
		return ex, err
	}
	if resp.StatusCode != http.StatusOK {
		return ex, nil
	}
	if len(body) == 0 {
		return ex, fmt.Errorf("empty successful inform response")
	}
	plain, err := DecodePacket(body, state.AuthKey)
	if err != nil {
		return ex, &packetDecodeError{err: err}
	}
	ex, err = ParseResponse(plain, ex)
	if err == nil && p.MinInterval > 0 && ex.ResponseType == "noop" {
		var live struct {
			LiveUpdate json.RawMessage `json:"live_update"`
		}
		if json.Unmarshal(plain, &live) == nil && (string(live.LiveUpdate) == "true" || string(live.LiveUpdate) == "1") {
			ex.Interval = p.MinInterval
		}
	}
	if err == nil && gcm && !ex.ResetRequested {
		ex.Adoption.UseGCM = true
	}
	return ex, err
}

// ParseResponse applies adoption settings and extracts provisioning for planning.
func ParseResponse(data []byte, ex domain.Exchange) (domain.Exchange, error) {
	var r struct {
		Type       string          `json:"_type"`
		Mgmt       string          `json:"mgmt_cfg"`
		System     json.RawMessage `json:"system_cfg"`
		CFGVersion string          `json:"cfgversion"`
		Interval   int             `json:"interval"`
		Cmd        string          `json:"cmd"`
		Key        string          `json:"key"`
		RequestID  string          `json:"request_id"`
		Args       json.RawMessage `json:"args"`
		Params     json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return ex, fmt.Errorf("decode controller reply: %w", err)
	}
	ex.ResponseType = r.Type
	if resetCommand(r.Type) || r.Type == "cmd" && resetCommand(r.Cmd) {
		ex.Adoption = domain.Adoption{MAC: ex.Adoption.MAC}
		ex.ResetRequested = true
		return ex, nil
	}
	switch r.Type {
	case "setparam":
		hasConfig := len(r.System) > 0 && string(r.System) != "null"
		for _, line := range strings.Split(r.Mgmt, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			switch key {
			case "authkey":
				if ex.Adoption.AuthKey != "" && ex.Adoption.AuthKey != inform.DefaultKey {
					continue
				}
				if _, err := authKey(value); err != nil || value == "" {
					return ex, fmt.Errorf("controller supplied an invalid authkey")
				}
				if !strings.EqualFold(value, inform.DefaultKey) {
					ex.Adoption.AuthKey = strings.ToLower(value)
				}
			case "use_aes_gcm":
				if value != "true" && value != "false" {
					return ex, fmt.Errorf("invalid controller cipher setting")
				}
				ex.Adoption.UseGCM = value == "true"
			case "cfgversion":
				if hasConfig || ex.Adoption.PendingCFGVersion != "" {
					ex.RequestedCFGVersion = value
				} else {
					ex.Adoption.CFGVersion = value
				}
			}
		}
		if hasConfig {
			if len(r.System) > 0 && r.System[0] == '"' {
				var s string
				if err := json.Unmarshal(r.System, &s); err != nil {
					return ex, err
				}
				ex.SystemConfig = []byte(s)
			} else {
				ex.SystemConfig = append([]byte{}, r.System...)
			}
			if !json.Valid(ex.SystemConfig) {
				return ex, fmt.Errorf("invalid controller system_cfg JSON")
			}
			if r.CFGVersion != "" {
				ex.RequestedCFGVersion = r.CFGVersion
			}
		}
	case "noop":
		if r.Interval > 0 {
			ex.Interval = time.Duration(max(5, min(60, r.Interval))) * time.Second
		}
	case "cmd":
		if r.Cmd == "set-adopt" || r.Cmd == "adopt" {
			if _, err := authKey(r.Key); err != nil || r.Key == "" || strings.EqualFold(r.Key, inform.DefaultKey) {
				return ex, fmt.Errorf("controller supplied an invalid adoption key")
			}
			ex.Adoption.AuthKey = strings.ToLower(r.Key)
			return ex, nil
		}
		if r.Cmd == "wg-genkeypair" && r.RequestID != "" && len(r.RequestID) <= 256 && emptyArguments(r.Args) && emptyArguments(r.Params) {
			ex.Command = domain.CommandRequest{Name: r.Cmd, RequestID: r.RequestID}
		} else {
			ex.IgnoredCommand = true
		}
	default:
		ex.IgnoredCommand = true
	}
	return ex, nil
}

func emptyArguments(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "[]", "{}":
		return true
	default:
		return false
	}
}
