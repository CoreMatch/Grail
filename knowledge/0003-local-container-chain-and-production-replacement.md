# 0003 — Local Container Chain E2E + Production Replacement (2026-11-12)

## Status

Accepted (verification + production-change record; the production state
described is live as of 2026-11-12)

## Context

[0002](./0002-local-e2e-verification.md) verified the Grail→Cupbearer chain
locally but stopped short of production: the test machine (192.168.1.227) was
unreachable, and production replacement was defined as unmet without it. The
author relaxed the gate (2026-11-12): the test machine is skipped for now —
local containers running the full chain count as the pass criterion, then the
current artifacts may replace production (atomic file replacement, rollback
material kept until verification passes).

## What was verified locally (containers where applicable)

Environment `/tmp/ha-chain-e2e` (ports 18320/18321 grail, 17891 tinyvisor,
18330/18331 cupbearer/mv):

1. **Grail tier (containers)**: root origin `grail-root-e2e` on 127.0.0.1:18320
   (fresh root key, 8 projects registered, publish/read tokens), mirror
   `grail-mirror-e2e` on 127.0.0.1:18321. Eight real service binaries (built
   from the service repos' HEAD, `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`,
   linux-amd64) published to `release`; mirror sync
   `applied=8 blobs_fetched=8 failures=0`.
2. **Cupbearer bare-metal path (grail source)**: preflight reported
   `grail hrpauth/release resolved version=62526 (digest sha256:a925e3939f1a…,
   signature chain verified)`; run `20261112-162713` steps
   `resolve -> artifact(stage grail) -> symlink -> ensure-script -> restart ->
   health`, outcome `deployed`; staged artifact, Grail release digest, and
   running process image `/proc/28397/exe` all `sha256:a925e3939f1a25e5…`.
3. **Container trigger path**: `POST /api/v1/deploy/container/trigger` run
   `20261112-164003-ct` — 8 image references pinned from manifests, compose
   up ok; stack 9/9 healthy, host-side probes all 200 (hrpauth/ygg/hasl/hasp/
   winnerproxy/mca/sdkhandler/cupbearer/maintenance-view). One failure triaged
   on this path: a manual `docker compose up` without the trigger's override
   loses the `ha-infra` network attachment (`lookup mysql … no such host`) —
   re-triggering through the endpoint restored it; the override is load-bearing.
4. **Bootstrap infra + MV auto-hosting**: one-click MySQL/Redis
   (`ha-infra-mysql-1`/`ha-infra-redis-1`, healthy, dual addressing
   127.0.0.1:3306|6379 ↔ mysql:3306|redis:6379); bootstrap run
   `20261112-163352` all steps ok (4 databases created + app account
   connectivity verified, 10 secrets generated, RSA-4096 signing keys,
   `.env` merged with 65 variables); Cupbearer auto-launched the MV binary
   (`mode=managed`, healthy).

## Production replacement (2026-11-12, all measured)

All eight production Go services were replaced with the same Grail release
artifacts (scp to `/tmp/ha-upgrade-20261112`, staging sha256 checked against
the release digests before touching anything). Per service: stop → old binary
renamed `<name>.bak-20261112` (kept) → new binary renamed into place (atomic
same-directory rename) → panel script restart → health 200 → `/proc/<pid>/exe`
sha256 equals the release digest.

| Service | Path | Release digest (== staged == /proc/exe) | Post-replace health |
|---|---|---|---|
| HRPAuth | /www/wwwroot/ha | `sha256:a925e3939f1a25e5…` | 200 `/health` |
| HAygg | /www/wwwroot/hay | `sha256:3d1e9c90ad2e4035…` | 200 `/health` |
| hasl | /www/wwwroot/sl | `sha256:f66b9a6a0711a5fb…` | 200 `/health` |
| hasp | /www/wwwroot/hasp | `sha256:ef5e543c6e537a5b…` | 200 `/health` |
| winnerproxy | /www/wwwroot/wp | `sha256:8f3080052ba51f91…` | 200 `/health` |
| mca | /www/wwwroot/mca | `sha256:268df8187ddd17b0…` | 200 `/api/status` (version 1.13.0) |
| sdkhandler | /www/wwwroot/sdkh | `sha256:722ad9f774684937…` | 200 `/health` |
| hasmv | /www/wwwroot/hasmv | `sha256:bcf253c325db5361…` | 200 `/healthz` |

Public surface spot check after the swap: `https://auth.mcnb.dev/` → 200.

Rollback material: every old binary kept as `<name>.bak-20261112` next to the
live one; rollback = rename back + panel script restart. Nothing old was
deleted.

## Boundaries / honest limits

- Production still runs **no Grail node, no Cupbearer, no Tinyvisor**: the
  replacement was a direct atomic file swap (the panel scripts stay the
  process managers), validated against Grail release digests. Orchestration
  in production remains future work.
- The replaced binaries were built from the service repos' HEAD at build
  time; production config files were left untouched (config auto-migration
  handles schema drift at startup; mca reports its current version 1.13.0).
- Local E2E leftovers kept for reference: the two grail containers (they hold
  the published releases cited above), the ha-infra + ha-platform stacks, and
  `/tmp/ha-chain-e2e`. The pre-existing `deploy/.env` was preserved as
  `deploy/.env.bak-20261112` before bootstrap wrote the new one.
- The test machine remains unexercised (author waived it for this round).
