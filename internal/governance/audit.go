package governance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
	"github.com/StealthMoud/AgentPort/internal/model"
)

type AuditEvent struct {
	EventID         string    `json:"event_id"`
	Timestamp       time.Time `json:"timestamp"`
	Actor           string    `json:"actor"` // e.g. "user", "import", "safe_optimizer", "memory_compiler", "sync_merge", "migration"
	Operation       string    `json:"operation"`
	TargetID        string    `json:"target_id"`
	BeforeHash      string    `json:"before_hash,omitempty"`
	AfterHash       string    `json:"after_hash,omitempty"`
	ProposalID      string    `json:"proposal_id,omitempty"`
	StateRootBefore string    `json:"state_root_before,omitempty"`
	StateRootAfter  string    `json:"state_root_after,omitempty"`
	SnapshotID      string    `json:"snapshot_id,omitempty"`
}

type Journal struct {
	mu  sync.Mutex
	cfg *config.Config
}

func NewJournal(cfg *config.Config) *Journal {
	return &Journal{cfg: cfg}
}

// RecordEvent appends an audit event entry to local persistent audit log.
func (j *Journal) RecordEvent(event *AuditEvent) error {
	_, err := j.RecordEventWithFilePath(event)
	return err
}

// RecordEventWithFilePath appends an audit event entry and returns the written file path.
func (j *Journal) RecordEventWithFilePath(event *AuditEvent) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if event.EventID == "" {
		event.EventID = model.GenerateEntityID("evt")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	auditDir := filepath.Join(j.cfg.VaultDir, "audit")
	if err := os.MkdirAll(auditDir, 0700); err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return "", err
	}

	eventFile := filepath.Join(auditDir, fmt.Sprintf("%s_%s.json", event.Timestamp.Format("20060102_150405"), event.EventID))
	err = fsutil.WriteFileAtomic(eventFile, data, 0600)
	if err != nil {
		return "", err
	}
	return eventFile, nil
}

// ListEvents returns all historical audit events in chronological order.
func (j *Journal) ListEvents() ([]*AuditEvent, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	auditDir := filepath.Join(j.cfg.VaultDir, "audit")
	if _, err := os.Stat(auditDir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(auditDir)
	if err != nil {
		return nil, err
	}

	events := make([]*AuditEvent, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(auditDir, entry.Name()))
		if err != nil {
			continue
		}
		evt := &AuditEvent{}
		if err := json.Unmarshal(data, evt); err == nil {
			events = append(events, evt)
		}
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	return events, nil
}
