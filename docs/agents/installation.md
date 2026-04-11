# install.olopa.io — Infrastructure Guide

## The core problem

`curl -fLs install.olopa.io | sh` sends an HTTP request.
The server needs to return the **right thing based on the User-Agent**:

- **`curl`** → return `install.sh` (the shell script)
- **Browser** → return `index.html` (the landing page)
- **`releases.olopa.io/latest/...`** → return the actual binary

---

## 1. DNS Setup

```
# Cloudflare (recommended) or Route 53
install.olopa.io    CNAME   olopa-install.pages.dev   (or your CDN origin)
releases.olopa.io   CNAME   your-s3-bucket.s3.amazonaws.com
```

Set both to **proxied** through Cloudflare if using CF — you'll use a Worker
to handle the User-Agent routing.

---

## 2. How to serve install.olopa.io (User-Agent routing)

### Option A — Cloudflare Worker (recommended, zero infra)

```js
// cloudflare-worker/index.js
// Deploy: wrangler deploy

export default {
  async fetch(request) {
    const ua = request.headers.get('User-Agent') || '';
    const url = new URL(request.url);

    // curl, wget, fetch without browser UA → serve the shell script
    const isCurl = /^curl\//.test(ua) || /^Wget\//.test(ua);
    const isBrowser = /Mozilla|Chrome|Safari|Firefox|Edge/.test(ua);

    if (isCurl || (!isBrowser && url.pathname === '/')) {
      // Fetch the script from R2 or a static URL
      const script = await fetch('https://releases.olopa.io/latest/install.sh');
      return new Response(await script.text(), {
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-cache',  // always get latest
        },
      });
    }

    // Browser → serve the landing page
    const page = await fetch('https://releases.olopa.io/latest/index.html');
    return new Response(await page.text(), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  },
};
```

Cost: **$0** (CF Workers free tier: 100k requests/day).

### Option B — Nginx (if you have a VPS)

```nginx
# /etc/nginx/sites-available/install.olopa.io

server {
    listen 443 ssl;
    server_name install.olopa.io;

    # TLS via certbot/Let's Encrypt
    ssl_certificate     /etc/letsencrypt/live/install.olopa.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/install.olopa.io/privkey.pem;

    root /var/www/install-olopa;

    location / {
        # User-Agent routing
        if ($http_user_agent ~* "^curl|^Wget|^python-requests") {
            # Return the install script
            add_header Content-Type "text/plain; charset=utf-8";
            add_header Cache-Control "no-cache";
            try_files /install.sh =404;
        }
        # Default: serve the HTML landing page
        try_files /index.html =404;
    }
}
```

### Option C — Caddy (simplest TLS)

```caddyfile
install.olopa.io {
    @curl header User-Agent curl*
    @wget header User-Agent Wget*

    handle @curl {
        rewrite * /install.sh
        file_server
    }
    handle @wget {
        rewrite * /install.sh
        file_server
    }
    handle {
        file_server
    }

    root * /var/www/install-olopa
}
```

---

## 3. Binary release storage (releases.olopa.io)

### S3-compatible bucket structure

```
releases.olopa.io/
├── latest/
│   ├── version                                        ← plain text: "v0.1.0"
│   ├── install.sh                                     ← the installer script
│   ├── index.html                                     ← the landing page
│   ├── checksums.txt                                  ← SHA-256 of all binaries
│   ├── olopa-agent-latest-x86_64-linux-musl           ← binary symlink/copy
│   └── olopa-agent-latest-aarch64-linux-musl
│
└── v0.1.0/
    ├── install.sh
    ├── checksums.txt
    ├── olopa-agent-v0.1.0-x86_64-linux-musl
    └── olopa-agent-v0.1.0-aarch64-linux-musl
```

### S3 bucket policy (public read on releases)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::releases.olopa.io/*"
  }]
}
```

Enable **static website hosting** on the bucket, then CNAME
`releases.olopa.io` to the bucket website endpoint.

### Alternatives to S3

| Option | Cost | Notes |
|--------|------|-------|
| Cloudflare R2 | Free (10GB) | Zero egress cost, CF CDN built in |
| GitHub Releases | Free | `releases.olopa.io` → CNAME → `github.com/olopa-security/olopa-agent/releases/...` via redirect worker |
| Cloudflare Pages | Free | Good for `index.html` + `install.sh`; binaries too large → use R2 |
| Fly.io | ~$3/mo | Static file server, great latency |

**Recommendation for early stage**: Cloudflare R2 + Worker. Zero cost, zero
ops, global CDN, and no egress fees when users download the binary.

---

## 4. Building and releasing the binary

### Cross-compile for musl (from your dev machine)

```bash
# Install cross-compilation toolchain
cargo install cross

# Build for both targets
cross build --release --target x86_64-unknown-linux-musl
cross build --release --target aarch64-unknown-linux-musl

# Output binaries
ls target/x86_64-unknown-linux-musl/release/olopa-agent
ls target/aarch64-unknown-linux-musl/release/olopa-agent
```

Why musl? Static linking — the binary has **zero runtime dependencies**.
It runs on any Linux ≥ 5.4 without `glibc` version mismatches.

### Generate checksums

```bash
VERSION="v0.1.0"

sha256sum \
  olopa-agent-${VERSION}-x86_64-linux-musl \
  olopa-agent-${VERSION}-aarch64-linux-musl \
  > checksums.txt

cat checksums.txt
# e3b0c44298fc1c149afb...  olopa-agent-v0.1.0-x86_64-linux-musl
# 2cf24dba5fb0a30e26e8...  olopa-agent-v0.1.0-aarch64-linux-musl
```

### Upload release script

```bash
#!/bin/bash
# scripts/release.sh

set -euo pipefail
VERSION="${1:-}"
[ -z "$VERSION" ] && { echo "Usage: ./release.sh v0.1.0"; exit 1; }

echo "Releasing ${VERSION}..."

# Build
cross build --release --target x86_64-unknown-linux-musl
cross build --release --target aarch64-unknown-linux-musl

# Stage
mkdir -p "dist/${VERSION}"
cp target/x86_64-unknown-linux-musl/release/olopa-agent  "dist/${VERSION}/olopa-agent-${VERSION}-x86_64-linux-musl"
cp target/aarch64-unknown-linux-musl/release/olopa-agent "dist/${VERSION}/olopa-agent-${VERSION}-aarch64-linux-musl"

# Checksums
(cd "dist/${VERSION}" && sha256sum olopa-agent-* > checksums.txt)

# Copy install script + landing page
cp install.sh   "dist/${VERSION}/install.sh"
cp index.html   "dist/${VERSION}/index.html"
echo "$VERSION" > "dist/${VERSION}/version"

# Upload to R2 / S3
aws s3 sync "dist/${VERSION}/" "s3://releases.olopa.io/${VERSION}/" --acl public-read

# Update latest/
aws s3 sync "dist/${VERSION}/" "s3://releases.olopa.io/latest/"     --acl public-read

echo "Released ${VERSION} ✓"
echo "Test: curl -fLs install.olopa.io | sh"
```

---

## 5. GitHub Actions CI release pipeline

```yaml
# .github/workflows/release.yml

name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build-and-release:
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: Install Rust + cross
        uses: dtolnay/rust-toolchain@stable
      - run: cargo install cross --git https://github.com/cross-rs/cross

      - name: Build x86_64
        run: cross build --release --target x86_64-unknown-linux-musl

      - name: Build aarch64
        run: cross build --release --target aarch64-unknown-linux-musl

      - name: Stage artifacts
        run: |
          VERSION="${GITHUB_REF_NAME}"
          mkdir -p dist
          cp target/x86_64-unknown-linux-musl/release/olopa-agent  dist/olopa-agent-${VERSION}-x86_64-linux-musl
          cp target/aarch64-unknown-linux-musl/release/olopa-agent dist/olopa-agent-${VERSION}-aarch64-linux-musl
          cd dist && sha256sum olopa-agent-* > checksums.txt
          cp ../install.sh dist/
          echo "$VERSION" > dist/version

      - name: Upload to R2
        env:
          AWS_ACCESS_KEY_ID:     ${{ secrets.R2_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.R2_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION:    auto
          AWS_ENDPOINT_URL:      https://<account>.r2.cloudflarestorage.com
        run: |
          VERSION="${GITHUB_REF_NAME}"
          aws s3 sync dist/ s3://releases-olopa-io/${VERSION}/
          aws s3 sync dist/ s3://releases-olopa-io/latest/
```

---

## 6. Testing the full flow locally

```bash
# Simulate what curl does (no browser UA)
curl -fLs install.olopa.io

# Simulate browser visit
curl -fLs -A "Mozilla/5.0" install.olopa.io

# Full install test on a throwaway VM
multipass launch 22.04 --name test-olopa
multipass exec test-olopa -- sudo curl -fLs install.olopa.io | sudo sh

# Verify binary runs
/usr/local/bin/olopa-agent --version

# Check service
systemctl status olopa-agent
```

---

## 7. Complete flow summary

```
User runs:
  curl -fLs install.olopa.io | sh
          │
          ▼
  Cloudflare Worker
  checks User-Agent: curl/* → serve install.sh
          │
          ▼
  install.sh runs on host:
    1. detect arch (x86_64 / aarch64)
    2. GET releases.olopa.io/latest/version → "v0.1.0"
    3. GET releases.olopa.io/v0.1.0/olopa-agent-v0.1.0-x86_64-linux-musl
    4. GET releases.olopa.io/v0.1.0/checksums.txt
    5. sha256sum verify
    6. cp binary → /usr/local/bin/olopa-agent
    7. write /etc/olopa/config.toml
    8. write /etc/systemd/system/olopa-agent.service
    9. systemctl enable + start olopa-agent
          │
          ▼
  Agent connects to ingest.olopa.io:4317 (mTLS gRPC)
  eBPF probes load into kernel
  Telemetry flowing
```

---

## 8. Quick start checklist

- [ ] Register `install.olopa.io` DNS (CNAME to CF Worker or VPS)
- [ ] Register `releases.olopa.io` DNS (CNAME to R2 bucket or S3)
- [ ] Deploy Cloudflare Worker with User-Agent routing
- [ ] Create R2/S3 bucket `releases-olopa-io` with public read
- [ ] Add `cross` targets to Cargo.toml workspace
- [ ] Run `scripts/release.sh v0.1.0` to cut first release
- [ ] Test: `curl -fLs install.olopa.io` on a fresh Ubuntu 22.04 VM