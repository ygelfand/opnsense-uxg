package usecase

import (
	"sort"
	"time"

	"github.com/ygelfand/opnsense-uxg/internal/domain"
)

// WANTracker retains observed availability, treating long collection gaps as unknown.
type WANTracker struct {
	Entries []domain.WANHistory
	MaxGap  time.Duration
}

// Apply advances each configured monitor's availability and transition history.
func (t *WANTracker) Apply(snap domain.Snapshot) domain.Snapshot {
	gap := t.MaxGap
	if gap <= 0 {
		gap = time.Minute
	}
	old := map[string]domain.WANHistory{}
	for _, row := range t.Entries {
		old[row.Role] = row
	}
	seen := map[string]bool{}
	advance := func(row domain.WANHistory, next *bool) domain.WANHistory {
		seconds := snap.ObservedAt.Sub(row.LastSampleAt).Seconds()
		if !row.LastSampleAt.IsZero() && seconds > 0 {
			switch {
			case seconds > gap.Seconds() || row.Connected == nil:
				row.UnknownSeconds += seconds
			case *row.Connected:
				row.OnlineSeconds += seconds
			default:
				row.OfflineSeconds += seconds
			}
			if next != nil && row.Connected != nil && *next != *row.Connected {
				row.LastChangeAt = snap.ObservedAt
				if !*next {
					row.Outages++
				}
			}
		}
		row.Connected = nil
		if next != nil {
			v := *next
			row.Connected = &v
		}
		row.LastSampleAt = snap.ObservedAt
		return row
	}
	for _, monitor := range snap.Gateways {
		row, exists := old[monitor.Role]
		if !exists || row.Monitor != monitor.Name {
			row = domain.WANHistory{Role: monitor.Role, Monitor: monitor.Name, StartedAt: snap.ObservedAt}
		}
		old[monitor.Role] = advance(row, monitor.Connected)
		seen[monitor.Role] = true
	}
	for role, row := range old {
		if !seen[role] {
			old[role] = advance(row, nil)
		}
	}
	rows := make([]domain.WANHistory, 0, len(old))
	for _, row := range old {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Role < rows[j].Role })
	t.Entries, snap.WANHistory = rows, rows
	return snap
}
