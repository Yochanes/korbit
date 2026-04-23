# Korbit Follow-up Sprint (2026-04-23)

## 1) Текущее состояние после повторной загрузки результатов
- Запуск Osmedeus завершен успешно (`status=completed`), но в параметрах был исключен `scan-vuln`.
- В execution log есть критичные пробелы:
  - `dns-bruteforce` завершился с ошибкой `code 2`.
  - `probe-port` отработал только `1/7` шагов.
- По screenshot-индексу живые веб-поверхности есть (много `200`, `301`, `302`), но также значимый слой `403/404`, что указывает на edge/gateway фильтрацию.

## 2) Что делаем дальше (строго по приоритету)

### P0-A: Закрываем технические пробелы сбора
```bash
# A1. Реран DNS brute-force с стабильными резолверами
puredns bruteforce /path/wordlists/deep-dns.txt korbit.co.kr \
  -r /path/resolvers-trusted.txt \
  --write-massdns probing/puredns-massdns.txt \
  > probing/puredns-bruteforce-hosts.txt

# A2. Живость хостов после brute-force
cat probing/puredns-bruteforce-hosts.txt | httpx -silent -sc -title -td -server \
  > probing/puredns-bruteforce-http.txt

# A3. Полный порт-профиль (из-за неполного probe-port)
awk '/ A /{print $3}' probing/dns-korbit.co.kr.txt | sort -u > ipspace/live-ip.txt
naabu -list ipspace/live-ip.txt -top-ports 2000 -rate 3000 -silent > portscan/naabu-top2k.txt
nmap -sV -sC -iL ipspace/live-ip.txt -oA synscan/korbit-followup
```

### P0-B: Поднимаем shadow hosts из archive
В archive есть внешние к текущему subdomain-list хосты: `appback`, `bapi`, `gateway`, `indra`, `kdata-api`, `studio-waiting-room`, `vc`, `waiting-room-api`.
```bash
cat << 'EOF_HOSTS' > probing/archive-shadow-hosts.txt
appback.korbit.co.kr
bapi.korbit.co.kr
gateway.korbit.co.kr
indra.korbit.co.kr
kdata-api.korbit.co.kr
studio-waiting-room.korbit.co.kr
vc.korbit.co.kr
waiting-room-api.korbit.co.kr
EOF_HOSTS

cat probing/archive-shadow-hosts.txt | dnsx -a -cname -resp -silent > probing/archive-shadow-dns.txt
cat probing/archive-shadow-hosts.txt | httpx -silent -sc -cl -title -td -server > probing/archive-shadow-http.txt
```

### P0-C: API attack-surface (точечный удар)
`api.korbit.co.kr` сообщает, что Developer Console снят, и API ключи смещены в `exchange.korbit.co.kr/my/api`.
```bash
# C1. Harvest API/WebSocket роутов из docs
curl -ks https://docs.korbit.co.kr/ | tee recon/docs-index.html >/dev/null
rg -o '#REST-(get|post|delete)-[^" ]+' recon/docs-index.html | sort -u > recon/rest-route-ids.txt
rg -o '#WS-[^" ]+' recon/docs-index.html | sort -u > recon/ws-route-ids.txt

# C2. Базовая проверка auth/cors для ключевых API путей
cat << 'EOF_API' > recon/api-priority.txt
https://api.korbit.co.kr/v1/oauth2/access_token
https://api.korbit.co.kr/v1/ticker/detailed
https://api.korbit.co.kr/v2/tickers
https://api.korbit.co.kr/v2/orders
https://api.korbit.co.kr/v2/balance
EOF_API

while read -r u; do
  echo "### $u"
  curl -isk "$u" -X OPTIONS -H 'Origin:https://evil.example' -H 'Access-Control-Request-Method: POST' | sed -n '1,35p'
  curl -isk "$u" -X GET | sed -n '1,25p'
  echo
 done < recon/api-priority.txt > recon/api-auth-cors-followup.txt
```

### P1: Контент/edge/аномалии из ffuf
Текущий ffuf top-сигнал: `developers/.aws/credentials`, `biz/asp~.tar`, `ajax/.babelrc.js`, `marketing//show_image...`.
```bash
# P1.1 Повторная валидация с методами/хедерами
cat << 'EOF_URLS' > content-discovery/high-signal-paths.txt
https://developers.korbit.co.kr/.aws/credentials
https://biz.korbit.co.kr/asp~.tar
https://ajax.korbit.co.kr/.babelrc.js
https://marketing.korbit.co.kr//show_image_NpAdvCatPG.php?cache=false&cat=1&filename=
EOF_URLS

while read -r u; do
  echo "### $u"
  curl -isk "$u" | sed -n '1,40p'
  curl -isk "$u" -H 'X-Original-URL: /admin' -H 'X-Forwarded-Host: attacker.example' | sed -n '1,30p'
  echo
 done < content-discovery/high-signal-paths.txt > content-discovery/high-signal-recheck.txt
```

### P2: Third-party / takeover линия
DNS показывает CNAME на `sendgrid.net`, `cloudfront.net`, `airbridge.io`.
```bash
awk '/CNAME/{print $1" "$3}' probing/dns-korbit.co.kr.txt > recon/cname-inventory.txt
subzy run --targets recon/cname-inventory.txt --verify_ssl --hide_fails > recon/cname-takeover-check.txt
```

## 3) Критерии успеха спринта
- Есть валидный список новых хостов после brute-force + archive shadow.
- Есть закрытый порт-профиль (`naabu` + `nmap`) по живым IP.
- Есть таблица API CORS/Auth статусов по `api-priority.txt`.
- Есть подтверждение/опровержение high-signal ffuf аномалий с одинаковым ответом на повторе.
- Есть short-list takeover кандидатов по CNAME.

## 4) Таймбокс
- 0–2ч: P0-A
- 2–4ч: P0-B
- 4–7ч: P0-C
- 7–9ч: P1
- 9–10ч: P2
