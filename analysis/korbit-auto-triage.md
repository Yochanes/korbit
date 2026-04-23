# Korbit Auto Triage (generated)

## Snapshot
- Subdomains: **48**
- DNS-confirmed hosts: **40**
- Live HTTP endpoints: **31**
- FFUF high-signal hosts: **10**

## High-signal hosts
| Host | Count | Key signals |
|---|---:|---|
| biz.korbit.co.kr | 3 | 200 /asp~.tar; 200 /404; 200 /auth/signin |
| marketing.korbit.co.kr | 3 | 200 /.well-known/apple-app-site-association; 302 //show_image_NpAdvCatPG.php?cache=false&cat=1&filename=; 204 /favicon.ico |
| developers.korbit.co.kr | 2 | 200 /.aws/credentials; 403 /confluence/plugins/servlet/oauth/service-providers/add |
| exchange.korbit.co.kr | 2 | 403 /.env.development.sample; 200 /404 |
| ablink.info.korbit.co.kr | 1 | 403 /__index.asp |
| ajax.korbit.co.kr | 1 | 500 /.babelrc.js |
| api.korbit.co.kr | 1 | 200 /dashboard |
| apidocs.korbit.co.kr | 1 | 301 /.codeship.yaml |
| cdn.korbit.co.kr | 1 | 200 /favicon.ico |
| insights.korbit.co.kr | 1 | 403 /!.htaccess |

## Shadow hosts from archive
- appback.korbit.co.kr
- bapi.korbit.co.kr
- gateway.korbit.co.kr
- indra.korbit.co.kr
- kdata-api.korbit.co.kr
- studio-waiting-room.korbit.co.kr
- vc.korbit.co.kr
- waiting-room-api.korbit.co.kr

## Infra profile
- Status distribution: `{301: 10, 302: 2, 403: 10, 404: 11, 200: 26, 400: 2}`
- Top technologies: `[('Cloudflare', 51), ('Amazon CloudFront', 30), ('Amazon Web Services', 30), ('Cloudflare Browser Insights', 18), ('Envoy', 8), ('React', 6), ('Webpack', 6), ('Amazon S3', 6)]`

## Round-2 artifact check
Missing files:
- rest-route-audit.txt
- ws-handshake-check.txt
- shadow-hosts-tls-http.txt
- cdn-differential-cache.txt
- cname-map.txt

## Next actions (non-repeating)
1. API route audit from docs-derived route IDs.
2. WebSocket handshake + subscription probe.
3. TLS/SNI fingerprint for archive-only shadow hosts.
4. Differential cache drift tests on CDN targets.
5. CNAME provider mapping and takeover shortlist.
