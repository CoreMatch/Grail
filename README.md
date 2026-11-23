<div align="center">
  <h1>Grail</h1>
  <p><strong>The same artifact bytes, wherever they are fetched.</strong></p>
  <p><a href="./README.zh-CN.md">简体中文</a></p>
</div>

Grail is signed artifact distribution for the HA ecosystem. It gives release publishers and service operators immutable versions and a canonical URL without tying consumers to the node that stores each file.

## Why Grail

- **Address content, not locations.** Content-addressed storage keeps artifact identity separate from where bytes happen to live.
- **Verify the publisher.** Ed25519 signatures let consumers check signed release metadata.
- **Separate release stages.** `ci`, `candidate`, and `release` channels distinguish builds intended for different audiences.
- **Distribute by pulling.** Pull-only mirrors retrieve artifacts without a push-based replication path.
- **Retire versions deliberately.** Yank and deprecation states make withdrawal and grace periods explicit.

## Learn more

- [Grail on GitHub](https://github.com/CoreMatch/Grail) — canonical source repository
- [Grail API contract](https://github.com/CoreMatch/HA-Contract/blob/main/docs/api/openapi/grail.yaml) — versioned distribution surface
- [Server routes](internal/server/router.go) — registered HTTP surface
- [Deployer documentation](https://wiki.mcnb.dev/deploy/) — HA operations guidance

## Boundary

There is no public node yet, and multi-tier mirroring, container synchronization, build lineage, and live-production behavior remain unproven.

## License

[AGPL-3.0](LICENSE)
