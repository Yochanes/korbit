# Korbit Current Findings Matrix (from existing repo artifacts)

- Subdomains discovered: **48**
- DNS-confirmed hosts: **40**
- Live HTTP endpoints: **31**

## High-signal findings from filtered content discovery
| Host | Signals | Priority | Why it matters |
|---|---:|---|---|
| biz.korbit.co.kr | 200 /asp~.tar; 200 /404; 200 /auth/signin | P0 | backup/debug artifact |
| developers.korbit.co.kr | 200 /.aws/credentials; 403 /confluence/plugins/servlet/oauth/service-providers/add | P0 | auth/secrets surface |
| ajax.korbit.co.kr | 500 /.babelrc.js | P1 | edge/app anomaly |
| api.korbit.co.kr | 200 /dashboard | P1 | edge/app anomaly |
| exchange.korbit.co.kr | 403 /.env.development.sample; 200 /404 | P1 | edge/app anomaly |
| marketing.korbit.co.kr | 200 /.well-known/apple-app-site-association; 302 //show_image_NpAdvCatPG.php?cache=false&cat=1&filename=; 204 /favicon.ico | P1 | edge/app anomaly |
| ablink.info.korbit.co.kr | 403 /__index.asp | P2 | edge/app anomaly |
| apidocs.korbit.co.kr | 301 /.codeship.yaml | P2 | edge/app anomaly |
| cdn.korbit.co.kr | 200 /favicon.ico | P2 | edge/app anomaly |
| insights.korbit.co.kr | 403 /!.htaccess | P2 | edge/app anomaly |

## Shadow hosts from archive (not in subdomain list)
- appback.korbit.co.kr
- bapi.korbit.co.kr
- gateway.korbit.co.kr
- indra.korbit.co.kr
- kdata-api.korbit.co.kr
- studio-waiting-room.korbit.co.kr
- vc.korbit.co.kr
- waiting-room-api.korbit.co.kr

## Tech/status distribution
- Status top: {301: 10, 302: 2, 403: 10, 404: 11, 200: 26, 400: 2}
- Tech top 8: [('Cloudflare', 51), ('Amazon CloudFront', 30), ('Amazon Web Services', 30), ('Cloudflare Browser Insights', 18), ('Envoy', 8), ('React', 6), ('Webpack', 6), ('Amazon S3', 6)]

## Next actions (no-repeat focus)
1. API route audit from docs route-id extraction + OPTIONS/Allow matrix.
2. WebSocket handshake/subscription validation on ws.korbit.co.kr.
3. TLS/SNI + HTTP fingerprint for archive-only hosts.
4. Differential cache header drift tests on cdn/assets/docs/portal-cdn.
5. CNAME provider mapping -> takeover/misbinding shortlist.
