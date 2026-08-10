# AgentPort Sync Protocol V2 Threat Model

## Trust Boundaries

### Trusted
- The user.
- Locally authorized AgentPort devices.
- Locally stored private device keys (`~/.agentport/keys/`).
- Explicitly created offline recovery authority credentials.

### Untrusted / Partially Trusted
- The Git remote host.
- Untrusted Git branch contents and pairing requests.
- Other devices until explicitly approved.
- LLM outputs and external provider responses.

---

## Security Guarantees
1. **Remote Plaintext Secrecy**: A compromise of the Git remote host reveals zero canonical plaintext context.
2. **Registry Authenticity**: Remote attackers cannot authorize a device by editing JSON; all registry updates require a valid Ed25519 signature from an active device or recovery key.
3. **Forward Secrecy Post-Revocation**: A revoked device cannot decrypt future state encrypted after revocation.
4. **Catalog Integrity & Non-Repudiation**: Remote hosts cannot forge canonical state; catalog headers are signed and encrypted.
5. **Divergence Protection**: Remote branch divergence cannot overwrite canonical state; all conflicts are preserved at the application level.
6. **Rollback Protection**: Devices detect and reject registry and catalog rollback attempts based on local trust history.

---

## Non-Guarantees
- **Erasure of Already-Obtained Plaintext**: Device revocation prevents decryption of *future* state, but cannot cryptographically erase plaintext or historical ciphertext previously obtained by a revoked physical device.
- **Remote Host Availability**: A malicious Git remote host can delete remote history or refuse pushes, but cannot corrupt local canonical state.
