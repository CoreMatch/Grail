# 0002 — Local End-to-End Verification (native + containerized, 2026-11-12)

## Status

Accepted (verification record; describes past local runs, not live state)

## Context

The first implementation of Grail required real closed-loop evidence
before merge — not unit tests alone. This entry records what was
verified on a single local host with isolated ports/directories
(`/tmp/grail-e2e`, ports 18300–18311), and which parts were real.
Test machine 192.168.1.227 was authorized for verification but was
unreachable at the time (100% packet loss from 192.168.1.141, machine
down); verification therefore stops at local full-green, recorded here.

## What was verified

### Loop 1 — native nodes, full chain

1. Root origin on 127.0.0.1:18300 (`grail init` generated the root key;
   keyring seq started at 1).
2. Project `demo` registered (project key `demo-1`); downstream node
   `mirror-1` registered (private key returned once).
3. Published `candidate/0.6` (build A) and a **rebuilt** `release/0.6`
   (build B) carrying lineage `derived_from candidate/0.6` — the
   candidate→release rebuild semantics, not a pointer move.
4. Mirror on 127.0.0.1:18301 synced: 2 manifests verified against the
   anchor→keyring→project-key chain, **2 blobs really fetched and
   stored** (`blobs_fetched=2`).
5. HA-Services-Deployer with the `grail` source pointed at the
   **mirror** deployed `demo` through Tinyvisor: preflight reported
   `signature chain verified`; run record steps
   `resolve -> artifact(stage grail) -> symlink -> ensure-script ->
   restart -> health`, outcome `deployed`.
6. Binary-level proof: staged artifact and running process image
   (`/proc/<pid>/exe`) both hashed to the published release digest
   `sha256:1dd48330181c…`; `/healthz` answered `version 0.6`.

### Loop 2 — upgrade, idempotence, revocation drill (native)

1. Published `release/1.0`; mirror re-sync fetched it; Deployer
   `latest` resolved 1.0 and upgraded (`current: 0.6 -> 1.0`), process
   fingerprint switched to `sha256:317eee5a6aa3…`. This exercised the
   resolved-version alignment fix: version dirs follow the resolved
   grail version, not the manifest's declared one.
2. Idempotent re-run: outcome `up-to-date`, no restart.
3. Yank drill: `yank release/1.0` at root → mirror sync propagated the
   states document → next deploy resolved `latest` to 0.6 and
   downgraded (symlink `1.0 -> 0.6`, health green); `unyank` → next
   deploy returned to 1.0.

### Loop 3 — containerized nodes (`grail:local` image)

1. Root origin container on 127.0.0.1:18310, mirror container on
   127.0.0.1:18311 (both `--network host`, volumes under
   `/tmp/grail-e2e/ctr/`).
2. Published `release/0.6`, `release/1.0`, then `release/1.1`
   (`sha256:cf128f0a79c7…`); the mirror's periodic loop picked 1.1 up
   automatically (`applied=1 blobs_fetched=1`).
3. Deployer re-anchored to the container root's public key and
   re-pointed at the container mirror deployed 1.1:
   `resolve -> version 1.1`, `stage grail (sha256 cf128f0a79c7)`,
   symlink `1.0 -> 1.1`, health green; running process fingerprint
   equals the published digest `sha256:cf128f0a79c7…`.

## Real vs placeholder

**Real:** both node roles ran as actual processes/containers; every
byte traveled HTTP between separate nodes; all signatures were real
Ed25519 with generated keys; Deployer and Tinyvisor were genuine
binaries; fingerprints above are literal `sha256sum` outputs.

**Placeholder / not yet exercised:**

- Test machine 192.168.1.227 deployment (machine unreachable; local
  full-green stands in until it returns).
- Production replacement: not attempted — preconditions (test-machine
  green + backup + rollback) unmet by definition without the test
  machine.
- Container-image tier sync (deferred by design, "未来实现").
- Multi-tier beyond one mirror hop, offline-node operation, and key
  rotation drills (designed, not yet run).

## Evidence

- Run records under `/tmp/grail-e2e/deployer/data/deploy/` (ephemeral):
  runs `20261112-030245` (deploy 1.0), `20261112-031127` (container
  mirror deploy 1.1).
- Node logs: `/tmp/grail-e2e/root/server.log`, `docker logs
  grail-root-ctr` / `grail-mirror-ctr` (sync summaries quoted above).
- Digests: `sha256sum` of staged artifacts and `/proc/<pid>/exe`
  (values inline).
