package governance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/StealthMoud/AgentPort/internal/compiler"
	"github.com/StealthMoud/AgentPort/internal/config"
	"github.com/StealthMoud/AgentPort/internal/fsutil"
)

type ProposalStore struct {
	mu  sync.RWMutex
	cfg *config.Config
}

func NewProposalStore(cfg *config.Config) *ProposalStore {
	return &ProposalStore{cfg: cfg}
}

// SaveProposal persists a proposal to local vault proposal store.
func (ps *ProposalStore) SaveProposal(prop *compiler.Proposal) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	propDir := filepath.Join(ps.cfg.VaultDir, "proposals")
	if err := os.MkdirAll(propDir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(prop, "", "  ")
	if err != nil {
		return err
	}

	filePath := filepath.Join(propDir, prop.ID+".json")
	return fsutil.WriteFileAtomic(filePath, data, 0600)
}

// DeleteProposal removes a proposal from local vault proposal store.
func (ps *ProposalStore) DeleteProposal(id string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	propDir := filepath.Join(ps.cfg.VaultDir, "proposals")
	filePath := filepath.Join(propDir, id+".json")
	return os.Remove(filePath)
}

// GetProposal retrieves a proposal by ID.
func (ps *ProposalStore) GetProposal(id string) (*compiler.Proposal, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	propDir := filepath.Join(ps.cfg.VaultDir, "proposals")
	filePath := filepath.Join(propDir, id+".json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false
	}

	prop := &compiler.Proposal{}
	if err := json.Unmarshal(data, prop); err != nil {
		return nil, false
	}

	return prop, true
}

// ListProposals lists all persistent proposals in vault.
func (ps *ProposalStore) ListProposals() ([]*compiler.Proposal, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	propDir := filepath.Join(ps.cfg.VaultDir, "proposals")
	if _, err := os.Stat(propDir); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := os.ReadDir(propDir)
	if err != nil {
		return nil, err
	}

	res := make([]*compiler.Proposal, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(propDir, entry.Name()))
		if err != nil {
			continue
		}
		prop := &compiler.Proposal{}
		if err := json.Unmarshal(data, prop); err == nil {
			res = append(res, prop)
		}
	}

	return res, nil
}
