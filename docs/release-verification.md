# Verifying a Tunnelfolio release

This guide verifies that a downloaded Linux archive matches its published checksum and GitHub attestation before installation.

## Prerequisites

- GitHub CLI 2.49.0 or newer, authenticated for attestation verification. Confirm `gh attestation verify --help` succeeds before downloading a release.
- `sha256sum`, `tar`, `jq`, `cmp`, and a supported Linux host.
- The release archive, `SHA256SUMS`, and corresponding `.spdx.json` SBOM from the same GitHub release.

## Verify checksum and attestation

Run these commands in the download directory, replacing the version and architecture with the files you downloaded:

```bash
grep 'tunnelfolio_v0.1.0_linux_arm64.tar.gz$' SHA256SUMS | sha256sum -c -
gh attestation verify tunnelfolio_v0.1.0_linux_arm64.tar.gz --repo Dhi13man/tunnelfolio
gh attestation verify tunnelfolio_v0.1.0_linux_arm64.tar.gz \
  --repo Dhi13man/tunnelfolio \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --format json > verified-sbom-attestation.json
jq -S '.[0].verificationResult.statement.predicate' \
  verified-sbom-attestation.json > attested.spdx.json
jq -S . tunnelfolio_v0.1.0_linux_arm64.spdx.json > downloaded.spdx.json
cmp attested.spdx.json downloaded.spdx.json
```

Expected checksum output ends with `OK`; both attestation verifications must identify `Dhi13man/tunnelfolio` and succeed without a policy error. The final `cmp` must produce no output: it proves the downloaded SPDX document is the predicate authenticated for that archive, rather than relying on a matching filename.

## Inspect the archive

List files before extracting:

```bash
tar -tzf tunnelfolio_v0.1.0_linux_arm64.tar.gz
```

The archive contains one top-level directory with `tunnelfolio`, `tunnelfolio.service`, `tunnelfolio.tmpfiles.conf`, `install.sh`, `README.md`, `LICENSE`, and `THIRD_PARTY_LICENSES`. Reject absolute paths, `..` traversal components, unexpected executables, or additional top-level content.

Extract into an empty directory and verify build identity:

```bash
tar -xzf tunnelfolio_v0.1.0_linux_arm64.tar.gz
./tunnelfolio_v0.1.0_linux_arm64/tunnelfolio --version
```

Expected output begins with `tunnelfolio 0.1.0` and includes the release commit and build date. Each supported archive has its own mechanically verified SBOM attestation.

## Install or upgrade

Read [Operating Tunnelfolio](operations.md) before replacing an active installation. Keep the verified archive, checksum file, SBOM, and pre-upgrade backup together until rollback is no longer required.
