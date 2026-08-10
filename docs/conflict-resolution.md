# AgentPort Conflict Detection & Resolution

## Application-Level Merge Rules
Merge logic operates per canonical `EntityID` using 3-way ancestral graph analysis:
1. **Same Head**: No-op.
2. **Local Ancestor of Remote**: Adopt remote head.
3. **Remote Ancestor of Local**: Keep local head.
4. **Independent Entities**: Auto-merge cleanly.
5. **Identical Content, Divergent Revisions**: Create automatic convergence revision with both parent revision IDs (`ParentRevisionIDs = [localRevID, remoteRevID]`). No user conflict required.
6. **Divergent Modifications**: Create `modify_modify` conflict record. No silent overwrites.
7. **Delete/Modify Divergence**: Create `delete_modify` conflict record. No auto-resurrection or auto-deletion.
8. **Safe Deletion Propagation**: Deletion wins if remote/local is unchanged ancestor.

## Resolution Workflow
Unresolved conflicts are managed via CLI:
```bash
agentport conflicts list

agentport conflicts show <conflict-id>

agentport conflicts resolve <conflict-id> --take local|remote
```
Resolving a conflict creates a NEW merge revision record with both divergent parent revisions as parents (`ParentRevisionIDs = [localRevID, remoteRevID]`), updating `ConflictRecord.Status = resolved`.
