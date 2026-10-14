package unifi

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

type commandCache struct {
	request    domain.CommandRequest
	privateKey string
	publicKey  string
	status     domain.CommandStatus
}

func (c *commandCache) queue(request domain.CommandRequest) error {
	if request.Name == "" {
		return nil
	}
	if request.Name == c.request.Name && request.RequestID == c.request.RequestID {
		c.status.Duplicates++
		c.status.Pending = true
		return nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate command key: %w", err)
	}
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return err
	}
	c.request = request
	c.privateKey = base64.StdEncoding.EncodeToString(key)
	c.publicKey = base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
	c.status.Name, c.status.Pending = request.Name, true
	c.status.Handled++
	return nil
}

func (c *commandCache) attach(payload []byte) ([]byte, error) {
	if !c.status.Pending {
		return payload, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return nil, err
	}
	notification, err := json.Marshal(map[string]any{
		"event_string": c.request.Name, "request_id": c.request.RequestID,
		"params": map[string]string{"private_key": c.privateKey, "public_key": c.publicKey},
	})
	if err != nil {
		return nil, err
	}
	root["inform_as_notif"] = json.RawMessage("true")
	root["notif_reason"] = json.RawMessage(`"cmd"`)
	root["notif_payload"] = notification
	return json.Marshal(root)
}

func (c *commandCache) delivered() {
	if c.status.Pending {
		c.status.Pending = false
		c.status.Delivered++
	}
}

func resetCommand(value string) bool {
	switch value {
	case "forget", "remove", "delete", "restore-default", "setdefault", "reset2defaults":
		return true
	default:
		return false
	}
}
