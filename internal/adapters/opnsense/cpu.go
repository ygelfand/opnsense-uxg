package opnsense

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CPUUsage reads one complete CPU event and closes the diagnostic stream.
func (c *Client) CPUUsage(ctx context.Context) (float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/api/diagnostics/cpu_usage/stream", nil)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth(c.key, c.secret)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("CPU stream returned HTTP %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return 0, fmt.Errorf("CPU endpoint did not return an event stream")
	}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 64<<10))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
		if line != "" || len(data) == 0 {
			continue
		}
		var sample struct {
			Total json.RawMessage `json:"total"`
		}
		if err := json.Unmarshal([]byte(strings.Join(data, "\n")), &sample); err != nil {
			return 0, fmt.Errorf("invalid CPU event")
		}
		value, err := numeric(sample.Total, "")
		if err != nil || value == nil || *value < 0 || *value > 100 {
			return 0, fmt.Errorf("invalid CPU utilization")
		}
		return *value, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("CPU stream ended before a complete sample")
}
