package syncv2

import (
	"fmt"
	"sort"
	"time"

	"github.com/StealthMoud/AgentPort/internal/conflict"
	"github.com/StealthMoud/AgentPort/internal/crypt"
	"github.com/StealthMoud/AgentPort/internal/device"
	"github.com/StealthMoud/AgentPort/internal/revision"
)

type MergeResult struct {
	MergedCatalog     *Catalog
	UpdatedRevisions  map[string]*revision.RevisionRecord
	NewConflicts      map[string]*conflict.ConflictRecord
	HasConflicts      bool
	IsCleanConvergence bool
}

// MergeCatalogs performs application-level 3-way/ancestral graph merge between local and remote catalogs.
func MergeCatalogs(localCat, remoteCat *Catalog, activeRegistry *device.RegistryEpoch, writerKeys *device.DeviceKeys) (*MergeResult, error) {
	if localCat == nil && remoteCat == nil {
		return nil, fmt.Errorf("both local and remote catalogs are nil")
	}
	if localCat == nil {
		return &MergeResult{
			MergedCatalog:      remoteCat,
			UpdatedRevisions:   remoteCat.RevisionGraph,
			NewConflicts:       make(map[string]*conflict.ConflictRecord),
			IsCleanConvergence: true,
		}, nil
	}
	if remoteCat == nil {
		return &MergeResult{
			MergedCatalog:      localCat,
			UpdatedRevisions:   localCat.RevisionGraph,
			NewConflicts:       make(map[string]*conflict.ConflictRecord),
			IsCleanConvergence: true,
		}, nil
	}

	// 1. Build combined revision graph
	combinedGraph := make(map[string]*revision.RevisionRecord)
	for id, rev := range localCat.RevisionGraph {
		combinedGraph[id] = rev
	}
	for id, rev := range remoteCat.RevisionGraph {
		combinedGraph[id] = rev
	}

	// 2. Build combined entity list
	allEntities := make(map[string]bool)
	for entID := range localCat.EntityHeads {
		allEntities[entID] = true
	}
	for entID := range remoteCat.EntityHeads {
		allEntities[entID] = true
	}

	mergedEntityHeads := make(map[string]string)
	mergedConflicts := make(map[string]*conflict.ConflictRecord)
	// Retain existing conflicts from both
	for id, cnf := range localCat.Conflicts {
		if cnf.Status == conflict.StatusUnresolved {
			mergedConflicts[id] = cnf
		}
	}
	for id, cnf := range remoteCat.Conflicts {
		if cnf.Status == conflict.StatusUnresolved {
			mergedConflicts[id] = cnf
		}
	}

	updatedRevisions := make(map[string]*revision.RevisionRecord)
	mergedTombstones := make(map[string]bool)
	for _, ts := range localCat.Tombstones {
		mergedTombstones[ts] = true
	}
	for _, ts := range remoteCat.Tombstones {
		mergedTombstones[ts] = true
	}

	newConflictsCount := 0

	// 3. Process each entity
	for entID := range allEntities {
		localHeadID, hasLocal := localCat.EntityHeads[entID]
		remoteHeadID, hasRemote := remoteCat.EntityHeads[entID]

		if hasLocal && !hasRemote {
			// Entity only in local -> keep local
			mergedEntityHeads[entID] = localHeadID
			continue
		}
		if !hasLocal && hasRemote {
			// Entity only in remote -> adopt remote
			mergedEntityHeads[entID] = remoteHeadID
			continue
		}

		if localHeadID == remoteHeadID {
			// Identical head -> no-op
			mergedEntityHeads[entID] = localHeadID
			continue
		}

		localRev := combinedGraph[localHeadID]
		remoteRev := combinedGraph[remoteHeadID]

		if localRev == nil || remoteRev == nil {
			// Missing revision record -> error
			return nil, fmt.Errorf("corrupt catalog revision reference for entity %s", entID)
		}

		// Check ancestral relationships
		if revision.IsAncestor(combinedGraph, localHeadID, remoteHeadID) {
			// Remote is descendant -> adopt remote
			mergedEntityHeads[entID] = remoteHeadID
			continue
		}
		if revision.IsAncestor(combinedGraph, remoteHeadID, localHeadID) {
			// Local is descendant -> keep local
			mergedEntityHeads[entID] = localHeadID
			continue
		}

		// Divergent heads! Check semantic equality
		if localRev.SemanticRevisionHash == remoteRev.SemanticRevisionHash && localRev.Deleted == remoteRev.Deleted {
			// Identical content, divergent RevisionIDs -> create automatic convergence revision record
			maxRevNum := localRev.RevisionNumber
			if remoteRev.RevisionNumber > maxRevNum {
				maxRevNum = remoteRev.RevisionNumber
			}

			convRev := &revision.RevisionRecord{
				RevisionID:           revision.GenerateRevisionID(),
				EntityID:             entID,
				RevisionNumber:       maxRevNum + 1,
				SemanticRevisionHash: localRev.SemanticRevisionHash,
				ParentRevisionIDs:    []string{localHeadID, remoteHeadID},
				AuthorDeviceID:       writerKeys.DeviceID,
				CreatedAt:            time.Now().UTC(),
				Deleted:              localRev.Deleted,
			}

			combinedGraph[convRev.RevisionID] = convRev
			updatedRevisions[convRev.RevisionID] = convRev
			mergedEntityHeads[entID] = convRev.RevisionID
			continue
		}

		// Delete vs Modify divergence
		if localRev.Deleted || remoteRev.Deleted {
			// Safe deletion check: if local is deletion and remote is unchanged ancestor -> deletion wins cleanly
			if localRev.Deleted && len(remoteRev.ParentRevisionIDs) > 0 && revision.IsAncestor(combinedGraph, remoteHeadID, localHeadID) {
				mergedEntityHeads[entID] = localHeadID
				continue
			}
			if remoteRev.Deleted && len(localRev.ParentRevisionIDs) > 0 && revision.IsAncestor(combinedGraph, localHeadID, remoteHeadID) {
				mergedEntityHeads[entID] = remoteHeadID
				continue
			}

			// Genuine Delete/Modify conflict!
			lca, _ := revision.FindLowestCommonAncestor(graphMap(combinedGraph), localHeadID, remoteHeadID)
			baseRevID := ""
			if lca != nil {
				baseRevID = lca.RevisionID
			}

			cnf := &conflict.ConflictRecord{
				ConflictID:       conflict.GenerateConflictID(),
				EntityID:         entID,
				Type:             conflict.TypeDeleteModify,
				BaseRevisionID:   baseRevID,
				LocalRevisionID:  localHeadID,
				RemoteRevisionID: remoteHeadID,
				DetectedAt:       time.Now().UTC(),
				Status:           conflict.StatusUnresolved,
			}
			mergedConflicts[cnf.ConflictID] = cnf
			newConflictsCount++
			continue
		}

		// Modify / Modify conflict
		lca, _ := revision.FindLowestCommonAncestor(graphMap(combinedGraph), localHeadID, remoteHeadID)
		baseRevID := ""
		if lca != nil {
			baseRevID = lca.RevisionID
		}

		cnf := &conflict.ConflictRecord{
			ConflictID:       conflict.GenerateConflictID(),
			EntityID:         entID,
			Type:             conflict.TypeModifyModify,
			BaseRevisionID:   baseRevID,
			LocalRevisionID:  localHeadID,
			RemoteRevisionID: remoteHeadID,
			DetectedAt:       time.Now().UTC(),
			Status:           conflict.StatusUnresolved,
		}
		mergedConflicts[cnf.ConflictID] = cnf
		newConflictsCount++
	}

	// 4. Construct merged catalog
	parentIDs := make([]string, 0)
	if localCat.CatalogID != "" {
		parentIDs = append(parentIDs, localCat.CatalogID)
	}
	if remoteCat.CatalogID != "" && remoteCat.CatalogID != localCat.CatalogID {
		parentIDs = append(parentIDs, remoteCat.CatalogID)
	}

	tombstoneList := make([]string, 0, len(mergedTombstones))
	for ts := range mergedTombstones {
		tombstoneList = append(tombstoneList, ts)
	}
	sort.Strings(tombstoneList)

	mergedCat := &Catalog{
		ProtocolVersion:  "2.0",
		VaultID:          localCat.VaultID,
		CatalogID:        GenerateCatalogID(),
		ParentCatalogIDs: parentIDs,
		RegistryEpoch:    activeRegistry.Epoch,
		RegistryHash:     mustHashRegistry(activeRegistry),
		RecipientSetHash: crypt.RecipientSetHash(activeRegistry.ActiveRecipients()),
		CreatedAt:        time.Now().UTC(),
		WriterDeviceID:   writerKeys.DeviceID,
		StateRoot:        ComputeStateRoot(mergedEntityHeads, combinedGraph),
		EntityHeads:      mergedEntityHeads,
		RevisionGraph:    combinedGraph,
		ObjectRefs:       make(map[string]*ObjectRefInfo),
		Tombstones:       tombstoneList,
		Conflicts:        mergedConflicts,
	}

	// Re-populate ObjectRefs from local and remote
	for ref, obj := range localCat.ObjectRefs {
		mergedCat.ObjectRefs[ref] = obj
	}
	for ref, obj := range remoteCat.ObjectRefs {
		mergedCat.ObjectRefs[ref] = obj
	}

	if err := SignCatalog(mergedCat, writerKeys); err != nil {
		return nil, fmt.Errorf("failed signing merged catalog: %w", err)
	}

	return &MergeResult{
		MergedCatalog:      mergedCat,
		UpdatedRevisions:   updatedRevisions,
		NewConflicts:       mergedConflicts,
		HasConflicts:       len(mergedConflicts) > 0,
		IsCleanConvergence: newConflictsCount == 0,
	}, nil
}

func graphMap(m map[string]*revision.RevisionRecord) map[string]*revision.RevisionRecord {
	return m
}

func mustHashRegistry(ep *device.RegistryEpoch) string {
	h, _ := device.ComputeRegistryHash(ep)
	return h
}
