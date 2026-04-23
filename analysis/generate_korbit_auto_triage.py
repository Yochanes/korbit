#!/usr/bin/env python3
"""Generate an evidence-based next-step triage report from local Korbit recon artifacts."""
from __future__ import annotations
import json
from pathlib import Path
from urllib.parse import urlparse
from collections import defaultdict, Counter

ROOT = Path(__file__).resolve().parents[1]

SUBDOMAINS = ROOT / "subdomain/subdomain-korbit.co.kr.txt"
DNS = ROOT / "probing/dns-korbit.co.kr.txt"
HTTP = ROOT / "probing/http-korbit.co.kr.txt"
FFUF = ROOT / "content-discovery/filtered-korbit.co.kr.jsonl"
ARCHIVE = ROOT / "archive/archive-interesting-urls-korbit.co.kr.txt"
FINGERPRINT = ROOT / "fingerprint/http-fingerprint-korbit.co.kr.jsonl"

EXPECTED_ROUND2 = [
    ROOT / "analysis/rest-route-audit.txt",
    ROOT / "analysis/ws-handshake-check.txt",
    ROOT / "analysis/shadow-hosts-tls-http.txt",
    ROOT / "analysis/cdn-differential-cache.txt",
    ROOT / "analysis/cname-map.txt",
]

OUTPUT = ROOT / "analysis/korbit-auto-triage.md"


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]


def parse_ffuf(path: Path):
    out = defaultdict(list)
    for line in read_lines(path):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = item.get("host") or urlparse(item.get("url", "")).hostname or "unknown"
        out[host].append((item.get("status"), item.get("url")))
    return out


def parse_tech(path: Path):
    status = Counter()
    tech = Counter()
    for line in read_lines(path):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        status[item.get("status_code")] += 1
        for t in item.get("tech", []) or []:
            tech[t] += 1
    return status, tech


def main() -> None:
    subs = read_lines(SUBDOMAINS)
    dns = read_lines(DNS)
    http = read_lines(HTTP)
    ffuf = parse_ffuf(FFUF)
    archive = read_lines(ARCHIVE)
    status, tech = parse_tech(FINGERPRINT)

    dns_hosts = sorted({line.split()[0] for line in dns if len(line.split()) >= 1})
    sub_set = set(subs)
    archive_hosts = sorted({urlparse(u).hostname for u in archive if urlparse(u).hostname})
    shadow = [h for h in archive_hosts if h not in sub_set]

    missing_round2 = [p.name for p in EXPECTED_ROUND2 if not p.exists()]

    lines: list[str] = []
    lines.append("# Korbit Auto Triage (generated)")
    lines.append("")
    lines.append("## Snapshot")
    lines.append(f"- Subdomains: **{len(subs)}**")
    lines.append(f"- DNS-confirmed hosts: **{len(dns_hosts)}**")
    lines.append(f"- Live HTTP endpoints: **{len(http)}**")
    lines.append(f"- FFUF high-signal hosts: **{len(ffuf)}**")
    lines.append("")

    lines.append("## High-signal hosts")
    lines.append("| Host | Count | Key signals |")
    lines.append("|---|---:|---|")
    for host, events in sorted(ffuf.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        sig = "; ".join([f"{s} {u.split(host)[-1]}" for s, u in events[:3]])
        lines.append(f"| {host} | {len(events)} | {sig} |")
    lines.append("")

    lines.append("## Shadow hosts from archive")
    for host in shadow:
        lines.append(f"- {host}")
    lines.append("")

    lines.append("## Infra profile")
    lines.append(f"- Status distribution: `{dict(status)}`")
    lines.append(f"- Top technologies: `{tech.most_common(8)}`")
    lines.append("")

    lines.append("## Round-2 artifact check")
    if missing_round2:
        lines.append("Missing files:")
        for name in missing_round2:
            lines.append(f"- {name}")
    else:
        lines.append("All expected round-2 artifacts are present.")
    lines.append("")

    lines.append("## Next actions (non-repeating)")
    lines.append("1. API route audit from docs-derived route IDs.")
    lines.append("2. WebSocket handshake + subscription probe.")
    lines.append("3. TLS/SNI fingerprint for archive-only shadow hosts.")
    lines.append("4. Differential cache drift tests on CDN targets.")
    lines.append("5. CNAME provider mapping and takeover shortlist.")

    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
