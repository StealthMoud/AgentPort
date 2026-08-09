package optimizer

import (
	"sort"
	"strings"

	"github.com/StealthMoud/AgentPort/internal/model"
	"github.com/StealthMoud/AgentPort/internal/vault"
)

type OptimizeResult struct {
	ScannedCount            int  `json:"scanned_count"`
	ExactDuplicatesRemoved  int  `json:"exact_duplicates_removed"`
	ProvenanceEntriesMerged int  `json:"provenance_entries_merged"`
	BeforeCount             int  `json:"before_count"`
	AfterCount              int  `json:"after_count"`
	DryRun                  bool `json:"dry_run"`
}

type SafeOptimizer struct{}

func NewSafeOptimizer() *SafeOptimizer {
	return &SafeOptimizer{}
}

// Optimize executes deterministic, safe optimization on vault artifacts.
func (opt *SafeOptimizer) Optimize(v *vault.Vault, dryRun bool) (*OptimizeResult, error) {
	artifacts := v.ListArtifacts()

	res := &OptimizeResult{
		ScannedCount: len(artifacts),
		BeforeCount:  len(artifacts),
		DryRun:       dryRun,
	}

	// Group artifacts by Fingerprint
	groups := make(map[string][]*model.Artifact)
	for _, art := range artifacts {
		// Normalize artifact text content
		art.Content = model.NormalizeContent(art.Content)
		art.Tags = deduplicateAndSortTags(art.Tags)
		art.UpdateFingerprint()

		groups[art.Fingerprint] = append(groups[art.Fingerprint], art)
	}

	finalArtifacts := make([]*model.Artifact, 0, len(groups))

	for _, group := range groups {
		if len(group) == 1 {
			finalArtifacts = append(finalArtifacts, group[0])
			continue
		}

		// Exact duplicate group found! Keep primary artifact, merge provenances
		primary := group[0]
		provMap := make(map[string]model.Provenance)

		for _, p := range primary.Provenance {
			key := p.Provider + "|" + p.MachineID + "|" + p.SourcePath
			provMap[key] = p
		}

		for i := 1; i < len(group); i++ {
			dup := group[i]
			res.ExactDuplicatesRemoved++

			for _, p := range dup.Provenance {
				key := p.Provider + "|" + p.MachineID + "|" + p.SourcePath
				if _, exists := provMap[key]; !exists {
					provMap[key] = p
					res.ProvenanceEntriesMerged++
				}
			}

			// Merge tags
			primary.Tags = append(primary.Tags, dup.Tags...)
		}

		// Rebuild primary provenance slice deterministically
		mergedProv := make([]model.Provenance, 0, len(provMap))
		for _, p := range provMap {
			mergedProv = append(mergedProv, p)
		}
		sort.Slice(mergedProv, func(i, j int) bool {
			return mergedProv[i].SourcePath < mergedProv[j].SourcePath
		})

		primary.Provenance = mergedProv
		primary.Tags = deduplicateAndSortTags(primary.Tags)
		primary.UpdateFingerprint()

		finalArtifacts = append(finalArtifacts, primary)
	}

	res.AfterCount = len(finalArtifacts)

	if !dryRun {
		// Apply changes to vault: delete duplicates, update primary artifacts
		for _, group := range groups {
			if len(group) > 1 {
				for i := 1; i < len(group); i++ {
					_ = v.DeleteArtifact(group[i].ID)
				}
				_ = v.SaveArtifact(group[0])
			}
		}
	}

	return res, nil
}

func deduplicateAndSortTags(tags []string) []string {
	if len(tags) == 0 {
		return tags
	}

	tagMap := make(map[string]bool)
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" {
			tagMap[t] = true
		}
	}

	res := make([]string, 0, len(tagMap))
	for t := range tagMap {
		res = append(res, t)
	}
	sort.Strings(res)
	return res
}
