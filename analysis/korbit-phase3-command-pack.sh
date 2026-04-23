#!/usr/bin/env bash
set -euo pipefail

# Korbit phase-3 recon/exploitation prep pack (non-repeating focus)
# Output folder
OUT_DIR="analysis/phase3-output"
mkdir -p "$OUT_DIR/js" "$OUT_DIR/http" "$OUT_DIR/ws" "$OUT_DIR/nuclei"

DOCS_RESP="screenshots/korbit.co.kr-screenshots/response/docs.korbit.co.kr/3280d3d56c7514220c8beff4dffdff780c2a34dc.txt"
DEV_RESP="screenshots/korbit.co.kr-screenshots/response/developers.korbit.co.kr/78278fcd4aa3c086a916b559f6d3049a12d0e7c6.txt"
API_RESP="screenshots/korbit.co.kr-screenshots/response/api.korbit.co.kr/6e616483282cc46a0dfdc9e0bf1b3b0767f9ae17.txt"

printf '[*] Step 1/8: build host list from current probing\n'
cp probing/http-korbit.co.kr.txt "$OUT_DIR/http/live-hosts.txt"

printf '[*] Step 2/8: advanced HTTP method matrix (TRACE/PUT/PATCH/DELETE/OPTIONS)\n'
while read -r u; do
  for m in TRACE PUT PATCH DELETE OPTIONS; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X "$m" "$u" || true)
    code=${code:-000}
    echo "$u,$m,$code"
  done
done < "$OUT_DIR/http/live-hosts.txt" > "$OUT_DIR/http/method-matrix.csv"

printf '[*] Step 3/8: host-header poisoning probe (Location/X-Forwarded-Host reflection)\n'
while read -r u; do
  echo "### $u"
  (curl -skI "$u" -H 'Host: poison.test' -H 'X-Forwarded-Host: poison.test' 2>/dev/null || true) \
  | awk '/^HTTP|^Location:|^Set-Cookie:|^X-Forwarded|^Server:|^Via:|^CF-Cache-Status:|^X-Cache:/{print}'
  echo
done < "$OUT_DIR/http/live-hosts.txt" > "$OUT_DIR/http/host-header-probe.txt"

printf '[*] Step 4/8: extract JS assets from saved responses\n'
{
  grep -Eo 'https?://[^""'"'"' ]+\.js[^""'"'"' ]*' "$DOCS_RESP" || true
  grep -Eo 'https?://[^""'"'"' ]+\.js[^""'"'"' ]*' "$DEV_RESP" || true
  grep -Eo 'https?://[^""'"'"' ]+\.js[^""'"'"' ]*' "$API_RESP" || true
  grep -Eo '/assets/[^""'"'"' ]+\.js[^""'"'"' ]*' "$DOCS_RESP" | sed 's#^#https://docs.korbit.co.kr#' || true
  grep -Eo '/assets/[^""'"'"' ]+\.js[^""'"'"' ]*' "$DEV_RESP" | sed 's#^#https://developers.korbit.co.kr#' || true
  grep -Eo '/assets/[^""'"'"' ]+\.js[^""'"'"' ]*' "$API_RESP" | sed 's#^#https://api.korbit.co.kr#' || true
} | sort -u > "$OUT_DIR/js/js-urls.txt"

printf '[*] Step 5/8: download JS and mine endpoints/secrets patterns\n'
while read -r js; do
  f="$OUT_DIR/js/$(echo "$js" | sed 's#https\?://##; s#[^a-zA-Z0-9._-]#_#g').js"
  curl -sk "$js" -o "$f" || true
done < "$OUT_DIR/js/js-urls.txt"

rg -n --no-heading -e 'api|oauth|token|authorization|bearer|secret|apikey|x-api-key|wss?://' "$OUT_DIR/js" \
  > "$OUT_DIR/js/js-interesting-patterns.txt" || true

printf '[*] Step 6/8: archived URL parameter attack-surface list\n'
awk '{print $0}' archive/archive-interesting-urls-korbit.co.kr.txt \
  | awk -F'?' 'NF>1{print $0}' \
  | sort -u > "$OUT_DIR/http/archive-param-urls.txt"

printf '[*] Step 7/8: nuclei targeted checks (if nuclei installed)\n'
if command -v nuclei >/dev/null 2>&1; then
  nuclei -l "$OUT_DIR/http/live-hosts.txt" -silent -severity low,medium,high,critical \
    -tags cors,misconfig,takeover,exposure,auth,cloud \
    -o "$OUT_DIR/nuclei/nuclei-targeted.txt" || true
else
  echo 'nuclei not found' > "$OUT_DIR/nuclei/nuclei-targeted.txt"
fi

printf '[*] Step 8/8: websocket handshake capture\n'
curl -skI https://ws.korbit.co.kr \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: SGVsbG9Xb3JsZDEyMzQ=' \
  > "$OUT_DIR/ws/ws-handshake.txt" || true

printf '\n[+] Done. Key outputs:\n'
printf ' - %s\n' \
  "$OUT_DIR/http/method-matrix.csv" \
  "$OUT_DIR/http/host-header-probe.txt" \
  "$OUT_DIR/js/js-urls.txt" \
  "$OUT_DIR/js/js-interesting-patterns.txt" \
  "$OUT_DIR/http/archive-param-urls.txt" \
  "$OUT_DIR/nuclei/nuclei-targeted.txt" \
  "$OUT_DIR/ws/ws-handshake.txt"
