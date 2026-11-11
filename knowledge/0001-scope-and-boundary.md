# 0001 — Scope and Boundary

## Status

Accepted (records current state, 2026-11-12)

## Decision

Grail is the HA ecosystem's artifact distribution upstream: an origin
plus tiered mirrors, publishing signed artifacts across three channels
(`ci`, `candidate`, `release`). Its external contract is HA-Contract
`docs/api/openapi/grail.yaml` (METHOD+path drift-checked against
`internal/server/router.go::NewRouter`); its semantics source is the
design document
`/home/lnb/Desktop/HA/GRAIL-DESIGN-20261112.md (field: 决策记录)`.

In scope:

- content-addressed blob store with size caps and digest-verified
  atomic writes (`internal/store/store.go::PutBlob`);
- Ed25519 signing chain: root key signs the keyring, per-project keys
  sign version manifests (`internal/signing/signing.go::VerifyEnvelope`);
- publishing with lineage and permanent version consumption
  (`internal/server/handlers_write.go::handlePublish`);
- yank + grace-period state machine with referenced-version refusal
  (`internal/server/server.go::SweepExpiredGrace`);
- pull-only mirror sync with signature verification and byte fetching
  (`internal/syncer/syncer.go::RunOnce`);
- auth layering: anonymous release reads on public nodes, read tokens
  for ci/candidate, registered node identities for sync
  (`internal/server/auth.go::verifyNodeIdentity`).

Out of scope (by decision, see the design document's decision record):

- building artifacts (CI's job);
- process management and deploy orchestration (Tinyvisor / Cupbearer);
- container-image tier sync this round (design doc "未来实现" section);
- deploy leases (known risk, trigger conditions recorded in the design).

The Cupbearer consumes Grail through its `grail` bare-metal artifact
source (HA-Cupbearer `internal/artifact/grail.go`, contract
`ha-cupbearer.yaml` 1.4.0).
[xref] HA-Cupbearer `internal/artifact/grail.go::resolveGrailArtifact` — cross-repo, not checked from here.
