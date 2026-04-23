# Korbit Next Wave (без повтора прежних команд)

## 1) Что уже подтверждено по текущим данным
- Платформа в основном за Cloudflare/CloudFront; много edge-ответов (`403/404`) и достаточно живых `200`.
- В docs зафиксировано **32 REST route-id** и **6 WS route-id**.
- В archive присутствуют 8 shadow-hosts вне основного subdomain-листа.

## 2) Дальше копаем так (новые команды)

### P0 — API surface mining напрямую из docs (без ffuf-повтора)
```bash
# 1) Вытащить route-id из сохраненного ответа docs
python - <<'PY'
import re
p='screenshots/korbit.co.kr-screenshots/response/docs.korbit.co.kr/3280d3d56c7514220c8beff4dffdff780c2a34dc.txt'
s=open(p,encoding='utf-8',errors='ignore').read()
ids=sorted(set(re.findall(r'#REST-(?:get|post|delete)-[^"\s<]+',s)))
with open('analysis/rest-route-ids.txt','w') as f:
    f.write('\n'.join(ids))
print('saved',len(ids),'REST ids')
PY

# 2) Конвертировать route-id -> метод+путь
python - <<'PY'
out=[]
for ln in open('analysis/rest-route-ids.txt'):
    rid=ln.strip().replace('#REST-','')
    if not rid: continue
    m,p = rid.split('-',1)
    path='/' + p.replace('_','/')
    out.append(f"{m.upper()} {path}")
open('analysis/rest-routes-derived.txt','w').write('\n'.join(sorted(set(out))))
print('derived',len(set(out)),'routes')
PY
```

```bash
# 3) Массовый method/path audit (новый фокус: коды/длины/allow)
while read -r row; do
  m=$(echo "$row" | awk '{print $1}')
  p=$(echo "$row" | awk '{print $2}')
  url="https://api.korbit.co.kr${p}"
  printf "\n### %s %s\n" "$m" "$url"
  curl -sk -o /dev/null -w "code=%{http_code} len=%{size_download} ct=%{content_type}\n" -X "$m" "$url"
  curl -skI -X OPTIONS "$url" | awk '/^HTTP|^Allow:|^Access-Control-Allow-Origin:|^Access-Control-Allow-Methods:/{print}'
done < analysis/rest-routes-derived.txt | tee analysis/rest-route-audit.txt
```

### P0 — WebSocket attack surface (новый вектор)
```bash
# Собираем WS route-id
python - <<'PY'
import re
p='screenshots/korbit.co.kr-screenshots/response/docs.korbit.co.kr/3280d3d56c7514220c8beff4dffdff780c2a34dc.txt'
s=open(p,encoding='utf-8',errors='ignore').read()
ws=sorted(set(re.findall(r'#WS-[^"\s<]+',s)))
open('analysis/ws-route-ids.txt','w').write('\n'.join(ws))
print('saved',len(ws),'WS ids')
PY

# Проверка handshake + upgrade headers
curl -skI https://ws.korbit.co.kr \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: SGVsbG9Xb3JsZDEyMzQ=' \
| tee analysis/ws-handshake-check.txt
```

```bash
# Если есть websocat, делаем подписку на публичные каналы
websocat -n1 -v wss://ws.korbit.co.kr <<'EOF_WS' | tee analysis/ws-public-subscribe.txt
{"method":"subscribe","type":"ticker","symbols":["btc_krw"]}
EOF_WS
```

### P1 — Shadow hosts через TLS/SNI fingerprint (новый подход)
```bash
cat << 'EOF_HOSTS' > analysis/shadow-hosts.txt
appback.korbit.co.kr
bapi.korbit.co.kr
gateway.korbit.co.kr
indra.korbit.co.kr
kdata-api.korbit.co.kr
studio-waiting-room.korbit.co.kr
vc.korbit.co.kr
waiting-room-api.korbit.co.kr
EOF_HOSTS

# Проверка сертификатов/SAN и HTTP-ответа
while read -r h; do
  echo "### $h"
  echo | openssl s_client -servername "$h" -connect "$h:443" 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName | sed -n '1,8p'
  curl -skI "https://$h" | sed -n '1,12p'
  echo
done < analysis/shadow-hosts.txt | tee analysis/shadow-hosts-tls-http.txt
```

### P1 — Differential cache behavior (новый тест: vary/etag/age drift)
```bash
cat << 'EOF_CDN' > analysis/cdn-focus.txt
https://cdn.korbit.co.kr
https://assets.korbit.co.kr
https://docs.korbit.co.kr
https://portal-cdn.korbit.co.kr
EOF_CDN

while read -r u; do
  echo "### $u"
  curl -skI "$u" | awk '/^HTTP|^Date:|^ETag:|^Age:|^Cache-Control:|^Vary:|^CF-Cache-Status:|^X-Cache:/{print}'
  curl -skI "$u" -H 'Accept-Language: zz-ZZ' -H 'X-Forwarded-Host: poison.example' | awk '/^HTTP|^ETag:|^Age:|^Vary:|^CF-Cache-Status:|^X-Cache:/{print}'
  echo
done < analysis/cdn-focus.txt | tee analysis/cdn-differential-cache.txt
```

### P2 — Third-party exposure map (не takeover-check, а картография интеграций)
```bash
awk '/CNAME/{print $1" "$3}' probing/dns-korbit.co.kr.txt | tee analysis/cname-map.txt

# Сгруппировать по провайдерам
python - <<'PY'
from collections import defaultdict
m=defaultdict(list)
for ln in open('analysis/cname-map.txt'):
    h,c=ln.split()
    k='other'
    if 'cloudfront.net' in c: k='cloudfront'
    elif 'sendgrid' in c: k='sendgrid'
    elif 'airbridge' in c: k='airbridge'
    m[k].append((h,c))
for k,v in m.items():
    print('\n##',k,len(v))
    for h,c in v: print(h,c)
PY
```

## 3) Что мне вернуть после выполнения
```bash
wc -l analysis/rest-route-ids.txt analysis/rest-routes-derived.txt analysis/rest-route-audit.txt \
     analysis/ws-route-ids.txt analysis/ws-handshake-check.txt analysis/ws-public-subscribe.txt \
     analysis/shadow-hosts-tls-http.txt analysis/cdn-differential-cache.txt analysis/cname-map.txt

sed -n '1,120p' analysis/rest-route-audit.txt
sed -n '1,120p' analysis/ws-handshake-check.txt
sed -n '1,120p' analysis/shadow-hosts-tls-http.txt
sed -n '1,120p' analysis/cdn-differential-cache.txt
```
