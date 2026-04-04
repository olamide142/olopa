# Agent Installation Plan (`curl | sh`)

## Goal

Provide a simple install command for users:

```bash
curl -fsSL https://olopa.io/install.sh | sh
```

while keeping installation secure, versioned, and maintainable.

## Strategy (3 Layers)

1. Release artifacts
2. Verified installer bootstrap
3. Website install UX

---

## Layer 1: Release Artifacts

Publish versioned agent binaries for supported targets:

- `linux-amd64`
- `linux-arm64`

Recommended release layout:

- `https://downloads.olopa.io/vX.Y.Z/olopa-linux-amd64.tar.gz`
- `https://downloads.olopa.io/vX.Y.Z/olopa-linux-arm64.tar.gz`
- `https://downloads.olopa.io/vX.Y.Z/SHA256SUMS`
- `https://downloads.olopa.io/vX.Y.Z/SHA256SUMS.sig` (optional but recommended)

### Required release outputs

- compressed binaries (or package archives)
- checksums (`SHA256SUMS`)
- optional signature file for checksum verification

---

## Layer 2: Installer Bootstrap (`install.sh`)

Host installer script at:

- `https://olopa.io/install.sh`

This script should stay small and stable.

### Installer behavior

1. Detect OS + architecture.
2. Resolve target version (default: latest stable, override via `--version`).
3. Download matching artifact + checksum file.
4. Verify checksum (and signature if enabled).
5. Install `olopa` to `/usr/local/bin` (or user-provided prefix).
6. Optionally install and enable a `systemd` service.
7. Print post-install verification command.

### Suggested flags

- `--version v0.1.0`
- `--channel stable`
- `--no-service`
- `--prefix /usr/local`

### Security rules

- Treat `curl | sh` as a bootstrap only.
- Never execute unverified downloaded binaries.
- Fail closed on checksum/signature mismatch.
- Prefer immutable, versioned download URLs.

---

## Layer 3: Website Integration

Show a copyable quick-start block:

```bash
curl -fsSL https://olopa.io/install.sh | sh
```

Add optional advanced examples:

```bash
curl -fsSL https://olopa.io/install.sh | sh -s -- --version v0.1.0
curl -fsSL https://olopa.io/install.sh | sh -s -- --no-service
```

---

## CI/CD and Release Workflow

Add a release workflow that:

1. builds agent binaries for target architectures,
2. packages tarballs,
3. generates `SHA256SUMS`,
4. signs checksums (optional but recommended),
5. uploads assets to GitHub Release or object storage,
6. updates `stable` metadata consumed by installer.

---

## Implementation Checklist

- [ ] Add `scripts/install.sh`
- [ ] Add release workflow for multi-arch binaries
- [ ] Add checksum generation + verification flow
- [ ] Add optional checksum-signature verification
- [ ] Add website install snippet + copy button
- [ ] Add docs for uninstall/upgrade paths
- [ ] Add smoke tests for installer in CI

---

## Notes for Later

- Current repo has CI tests but no dedicated release artifact pipeline yet.
- First priority should be release automation + checksum verification.
- Keep the bootstrap script intentionally minimal to reduce security risk.
