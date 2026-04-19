# Korbit Recon Analysis & Next-Step Attack Plan (2026)

## 1) Current target state from Osmedeus artifacts
- Discovered subdomains: **48** (`subdomain/subdomain-korbit.co.kr.txt`).
- DNS-confirmed hosts: **46** (`probing/nonwild-korbit.co.kr.txt`).
- Live HTTP(S) endpoints: **31** (`probing/http-korbit.co.kr.txt`).
- Non-CDN IPs captured: **31** (`ipspace/non-cdn-ip-korbit.co.kr.txt`).

### High-value live surfaces
- **Trading / user-facing**: `www`, `korbit`, `m`, `exchange`, `biz`, `lightning`, `svelte`.
- **API / developer**: `api`, `developers`, `docs`, `apidocs`, `ws`.
- **Portal / internal-ish naming**: `portal`, `portal-prod`, `portal-cdn`, `cdn.portal`, `w2b`.
- **Marketing / third-party integrated**: `marketing`, `ablink.*`, `email*`, SendGrid-related DNS labels.

## 2) Signals worth immediate exploitation attention

### A) Endpoint anomalies from content discovery
From `content-discovery/filtered-korbit.co.kr.jsonl` and report markdown:
- `https://developers.korbit.co.kr/.aws/credentials` returned **200** in scan artifacts.
- `https://biz.korbit.co.kr/asp~.tar` returned **200**.
- `https://ajax.korbit.co.kr/.babelrc.js` returned **500**.
- `https://marketing.korbit.co.kr/.well-known/apple-app-site-association` returned **200**.
- `https://marketing.korbit.co.kr//show_image_NpAdvCatPG.php?...` returned **302**.

These are likely mixed true findings + edge-cache/WAF noise. Re-validate with header, path-encoding, origin-bypass, and protocol variation.

### B) Externally integrated infra hints
- `email.korbit.co.kr CNAME sendgrid.net`
- `marketing.korbit.co.kr CNAME ...airbridge.io`
- CloudFront-backed assets/docs/lightning hosts.

This opens takeover/misbinding, email abuse, and third-party auth/redirect misconfiguration vectors.

### C) Potential shadow assets not resolved during the run
Subdomains discovered but not DNS-confirmed in this run:
- `account.korbit.co.kr`
- `api.portal.korbit.co.kr`
- `portal-front.korbit.co.kr`
- `status.korbit.co.kr`
- `gw.korbit.co.kr`
- campaign variants (`coinfesta*`, typo `conifesta`)

These are priority for historical DNS and alternate resolver vantage checks.

## 3) Phased recon expansion (not fully covered yet)

### Phase 1 — Passive deepening
- Certificate transparency + historical passive DNS diff (quarterly snapshots).
- Wayback/CommonCrawl host-path extraction with parameter inventory.
- Mobile artifact mining (APK endpoints from archive references).
- Public JS sourcemap + OpenAPI schema harvesting.

### Phase 2 — Semi-active precision probing
- Route census using `GET/POST/OPTIONS/TRACE` with normalized + mangled paths.
- CDN/origin differential probing (`Host`, `X-Forwarded-Host`, protocol-smuggling-safe permutations).
- WebSocket namespace and auth downgrade checks on `ws` + portal stack.

### Phase 3 — Active exploit chains
- API auth chain: OAuth scope confusion → token replay → privilege pivot.
- Cache poisoning / key confusion on CloudFront+Cloudflare mixed edges.
- SSRF-to-metadata and signed URL abuse in asset/document delivery paths.

## 4) Priority actions (execution order)

### P0 (do now)
1. Re-validate all “interesting” ffuf hits with **multi-vantage** requests and raw response diffing.
2. Enumerate API auth surfaces (`/v1/oauth2/*`, developer console routes, hidden OpenAPI paths).
3. Test cache behavior and origin exposure on `docs/assets/cdn/portal-cdn`.
4. Sweep third-party delegated subdomains for takeover and dangling integrations.

### P1
1. JS bundle triage (React/Gatsby apps): secrets, internal API URLs, feature flags, debug routes.
2. Business-logic abuse in `biz`, `exchange`, `portal*` (IDOR, workflow bypass, KYC/docs exposure).
3. WebSocket auth/session fixation and channel authorization drift.

### P2
1. Supply-chain and CI/CD metadata leakage (`.github`, build manifests, old release artifacts).
2. Cloud IAM attack-path modeling from public metadata and leaked endpoint behavior.

## 5) Modern toolstack to use (2025-2026 focused)

> Use latest stable tags at runtime. Pin exact versions in your ops notes before execution.

- `projectdiscovery/httpx`, `nuclei`, `katana`, `naabu` (Go, continuously updated recon core).
- `assetnote/can-i-take-over-xyz` (+ maintained fingerprints forks, 2025+).
- `trufflesecurity/trufflehog` (high-signal secret scanning in JS/mobile/web artifacts).
- `owasp-amass/amass` + `dnsx` + `puredns` for differential DNS enumeration.
- `aquasecurity/trivy` (IaC/container findings if artifacts expand to repos/images).
- `bishopfox/sliver` lab-only for adversary emulation post-initial foothold.
- `ffuf/ffuf` + `feroxbuster/feroxbuster` hybrid path bruting with adaptive filters.
- API-focused: `zaproxy/zaproxy`, `42Crunch/api-security-audit`-style OpenAPI lint/fuzz workflows.
- Cloud/K8s: `aquasecurity/kube-hunter`, `kubescape/kubescape`, `prowler-cloud/prowler`.
- AI-assisted chaining: custom LLM triage pipelines over JSONL outputs (route clustering, anomaly scoring, exploit suggestion ranking).

## 6) Command blocks for next operation wave

```bash
# 1) Differential re-check of high-signal findings
cat content-discovery/filtered-korbit.co.kr.jsonl \
 | jq -r '.url' \
 | httpx -silent -status-code -content-length -title -web-server -tech-detect -follow-redirects -H "Cache-Control: no-cache" \
 | tee revalidate-interesting.txt
```

```bash
# 2) Extract archived + discovered hosts, then expand active probing
(cat subdomain/subdomain-korbit.co.kr.txt; awk '{print $1}' probing/nonwild-korbit.co.kr.txt; cat archive/archive-interesting-urls-korbit.co.kr.txt) \
 | unfurl -u domains \
 | sort -u \
 | dnsx -silent -a -cname -resp \
 | tee dnsx-refresh.txt
```

```bash
# 3) API route discovery with katana + JS endpoint extraction
printf '%s\n' https://api.korbit.co.kr https://developers.korbit.co.kr https://docs.korbit.co.kr \
 | katana -silent -jc -jsl -d 3 -aff -xhr \
 | tee katana-api-surface.txt
```

```bash
# 4) Cloud/CDN misconfig checks (headers + cache key behavior)
cat <<'LIST' | while read u; do
https://cdn.korbit.co.kr
https://assets.korbit.co.kr
https://docs.korbit.co.kr
https://portal-cdn.korbit.co.kr
done
LIST
curl -isk "$u" -H 'X-Forwarded-Host: evil.example' -H 'X-Original-URL: /admin' -H 'Cache-Control: no-cache'
done | tee edge-misconfig-probe.txt
```

```bash
# 5) Takeover candidates from CNAME/third-party delegations
awk '/CNAME/{print $1" "$3}' probing/nonwild-korbit.co.kr.txt \
 | tee cname-targets.txt
```

## 7) Attack chain hypotheses to validate
1. **Archive URL → hidden portal/API endpoint → weak auth check → account data exposure**.
2. **Marketing/airbridge subdomain trust → redirect/open-link abuse → session theft pretext**.
3. **CloudFront asset path confusion → cache poisoning/deception → JS payload swap window**.
4. **WebSocket namespace drift (`ws`, `portal-prod`) → unauthorized subscription/event leakage**.

## 8) Operator notes
- Current live probing from this environment returned broad `403` on direct requests, so preserve Osmedeus snapshots as baseline and use distributed validation nodes.
- Keep stealth-first: low-rate adaptive probing, randomized JA3/User-Agent pools, and per-host request shaping.
