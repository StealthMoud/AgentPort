# AgentPort Pairing & Onboarding Protocol

## Overview
New device onboarding is performed through an out-of-band human-verifiable pairing workflow.

## Verification Code
A 12-character formatted fingerprint (e.g. `8C4A-91D2-77F0`) is derived deterministically from public pairing parameters:
$$\text{Code} = \text{Format}(\text{SHA-256}(\text{RequestID} \parallel \text{DeviceID} \parallel \text{AgeRecipient} \parallel \text{SigningPublicKey} \parallel \text{Nonce}))$$

The joining device displays this verification code to the user, who verifies it matches when running `agentport device approve <request-id>` on an already authorized device.

## Approval Receipt
Upon approval, the approver device creates a signed receipt (`pairing/approvals/<request-id>.json`) containing `approved_registry_epoch`, `approved_registry_hash`, and signature (`agentport/pairing-approval/v2`).
