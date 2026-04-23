# Phase3 Output Summary (2026-04-23)

## Observed from local run
- Method matrix produced `000` codes across hosts for TRACE/PUT/PATCH/DELETE/OPTIONS in this environment.
- Host-header probe returned `HTTP/1.1 403 Forbidden` for all probed hosts.
- WebSocket handshake also returned `403 Forbidden` from `server: envoy`.
- JS extraction yielded only two JS assets from `api.korbit.co.kr` snapshot (`bootstrap.min.js`, `jquery.min.js`).
- `nuclei` binary is not present in current environment (`nuclei not found`).

## Interpretation
Current node is blocked/challenged at edge (likely IP reputation / WAF policy), so additional direct probing from this source has low signal.

## Immediate next move
Run the same `analysis/korbit-phase3-command-pack.sh` from:
1. a clean residential/static ISP IP,
2. a second cloud region/provider,
3. (optional) authenticated browser session proxy.

Then diff the outputs file-by-file against `analysis/phase3-output/*` from this run.
