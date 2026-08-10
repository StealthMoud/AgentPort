package compiler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/StealthMoud/AgentPort/internal/model"
)

var (
	ErrBackendUnavailable = errors.New("model backend unavailable")
	ErrInvalidProposal    = errors.New("invalid proposal structure")
	ErrInvalidModelOutput = errors.New("invalid model output JSON structure")
)

type ProposalOperation string

const (
	OpCreate       ProposalOperation = "CREATE"
	OpMerge        ProposalOperation = "MERGE"
	OpRefine       ProposalOperation = "REFINE"
	OpSupersede    ProposalOperation = "SUPERSEDE"
	OpArchive      ProposalOperation = "ARCHIVE"
	OpMarkConflict ProposalOperation = "MARK_CONFLICT"
	OpMarkStale    ProposalOperation = "MARK_STALE"
	OpReclassify   ProposalOperation = "RECLASSIFY"
)

type ProposalStatus string

const (
	ProposalStatusPending    ProposalStatus = "pending"
	ProposalStatusAccepted   ProposalStatus = "accepted"
	ProposalStatusRejected   ProposalStatus = "rejected"
	ProposalStatusExpired    ProposalStatus = "expired"
	ProposalStatusSuperseded ProposalStatus = "superseded"
)

type Proposal struct {
	ID                  string            `json:"id"`
	ProposalSetID       string            `json:"proposal_set_id"`
	Operation           ProposalOperation `json:"operation"`
	TargetIDs           []string          `json:"target_ids"`
	SourceEvidence      []string          `json:"source_evidence,omitempty"`
	BeforeState         string            `json:"before_state"`
	ProposedState       string            `json:"proposed_state"`
	Rationale           string            `json:"rationale"`
	Confidence          float64           `json:"confidence"`
	Backend             string            `json:"backend"`
	Model               string            `json:"model"`
	PromptVersion       string            `json:"prompt_version"`
	InputStateRoot      string            `json:"input_state_root"`
	CreatedAt           time.Time         `json:"created_at"`
	Status              ProposalStatus    `json:"status"`
	EstimatedTokenDelta int               `json:"estimated_token_delta"`
}

type AnalysisRequest struct {
	Scope          model.Scope         `json:"scope"`
	InputStateRoot string              `json:"input_state_root"`
	Artifacts      []*model.Artifact   `json:"artifacts"`
	Entities       []*model.EnvelopeV2 `json:"entities"`
}

type AnalysisResponse struct {
	StateRoot string      `json:"state_root,omitempty"`
	Proposals []*Proposal `json:"proposals"`
	Metrics   *Metrics    `json:"metrics"`
}

type Metrics struct {
	AnalyzedCount        int `json:"analyzed_count"`
	DuplicateProposals   int `json:"duplicate_proposals"`
	ConflictProposals    int `json:"conflict_proposals"`
	StaleProposals       int `json:"stale_proposals"`
	EstimatedTokenBefore int `json:"estimated_token_before"`
	EstimatedTokenAfter  int `json:"estimated_token_after"`
}

type Backend interface {
	Name() string
	Health(ctx context.Context) error
	Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error)
}

// TestBackend provides a deterministic fake backend for unit tests and CI.
type TestBackend struct{}

func NewTestBackend() *TestBackend {
	return &TestBackend{}
}

func (b *TestBackend) Name() string {
	return "test"
}

func (b *TestBackend) Health(ctx context.Context) error {
	return nil
}

func (b *TestBackend) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	proposals := make([]*Proposal, 0)
	analyzedCount := len(req.Artifacts) + len(req.Entities)

	// 1. V2 entities analysis
	seenV2Content := make(map[string]*model.EnvelopeV2)
	for _, env := range req.Entities {
		if env.Memory == nil {
			continue
		}
		norm := model.NormalizeContent(env.Memory.Statement)
		if first, exists := seenV2Content[norm]; exists {
			prop := &Proposal{
				ID:                  model.GenerateEntityID("prop"),
				ProposalSetID:       model.GenerateEntityID("propset"),
				Operation:           OpMerge,
				TargetIDs:           []string{first.ID, env.ID},
				BeforeState:         fmt.Sprintf("A: %s\nB: %s", first.Memory.Statement, env.Memory.Statement),
				ProposedState:       first.Memory.Statement,
				Rationale:           "Deterministic duplicate memory content detected across V2 entities",
				Confidence:          1.0,
				Backend:             b.Name(),
				Model:               "test-fake",
				PromptVersion:       "v2.0",
				InputStateRoot:      req.InputStateRoot,
				CreatedAt:           time.Now(),
				Status:              ProposalStatusPending,
				EstimatedTokenDelta: -len(env.Memory.Statement) / 4,
			}
			proposals = append(proposals, prop)
		} else {
			seenV2Content[norm] = env
		}
	}

	// 2. Legacy V1 artifacts fallback
	seenContent := make(map[string]*model.Artifact)
	for _, art := range req.Artifacts {
		norm := model.NormalizeContent(art.Content)
		if first, exists := seenContent[norm]; exists {
			prop := &Proposal{
				ID:                  model.GenerateEntityID("prop"),
				ProposalSetID:       model.GenerateEntityID("propset"),
				Operation:           OpMerge,
				TargetIDs:           []string{first.ID, art.ID},
				BeforeState:         fmt.Sprintf("A: %s\nB: %s", first.Content, art.Content),
				ProposedState:       first.Content,
				Rationale:           "Deterministic duplicate memory content detected",
				Confidence:          1.0,
				Backend:             b.Name(),
				Model:               "test-fake",
				PromptVersion:       "v1.0",
				InputStateRoot:      req.InputStateRoot,
				CreatedAt:           time.Now(),
				Status:              ProposalStatusPending,
				EstimatedTokenDelta: -len(art.Content) / 4,
			}
			proposals = append(proposals, prop)
		} else {
			seenContent[norm] = art
		}
	}

	return &AnalysisResponse{
		Proposals: proposals,
		Metrics: &Metrics{
			AnalyzedCount:      analyzedCount,
			DuplicateProposals: len(proposals),
		},
	}, nil
}
