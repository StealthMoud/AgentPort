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
	entities := v.ListEntities()
	artifacts := v.ListArtifacts()

	res := &OptimizeResult{
		ScannedCount: len(entities) + len(artifacts),
		BeforeCount:  len(entities) + len(artifacts),
		DryRun:       dryRun,
	}

	// 1. Optimize V2 Entities
	if len(entities) > 0 {
		groups := make(map[string][]*model.EnvelopeV2)
		for _, env := range entities {
			if env.Kind == model.KindSourceRecord {
				continue
			}
			fp := env.RevisionHash
			if env.Memory != nil {
				norm := model.NormalizeContent(env.Memory.Statement)
				fp = model.ComputeFingerprint(model.Kind(env.Kind), env.Scope, "", norm, nil)
			}
			groups[fp] = append(groups[fp], env)
		}

		finalEntities := make([]*model.EnvelopeV2, 0)
		for _, group := range groups {
			if len(group) == 1 {
				finalEntities = append(finalEntities, group[0])
				continue
			}

			primary := group[0].Clone()
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
				primary.Tags = append(primary.Tags, dup.Tags...)
			}

			mergedProv := make([]model.Provenance, 0, len(provMap))
			for _, p := range provMap {
				mergedProv = append(mergedProv, p)
			}
			sort.Slice(mergedProv, func(i, j int) bool {
				return mergedProv[i].SourcePath < mergedProv[j].SourcePath
			})

			primary.Provenance = mergedProv
			primary.Tags = deduplicateAndSortTags(primary.Tags)

			if !dryRun {
				for i := 1; i < len(group); i++ {
					_ = v.DeleteEntity(group[i].ID)
				}
				_ = v.UpdateEntity(primary)
			}

			finalEntities = append(finalEntities, primary)
		}

		res.AfterCount = len(finalEntities) + len(artifacts)
		return res, nil
	}

	// 2. Optimize V1 Artifacts (legacy fallback)
	groups := make(map[string][]*model.Artifact)
	for _, art := range artifacts {
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

			primary.Tags = append(primary.Tags, dup.Tags...)
		}

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
