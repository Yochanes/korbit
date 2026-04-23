# Korbit Round-2: Verification + Next Ops

## 1) Что вижу в репозитории прямо сейчас
Промежуточные файлы от round-2 команд отсутствуют (нет `recon/`, `portscan/naabu-top2k.txt`, `synscan/korbit-followup.*`, `content-discovery/high-signal-recheck.txt`, `recon/cname-takeover-check.txt`).

Это значит: либо команды запускались в другой директории/воркспейсе, либо результаты не закоммичены.

## 2) Быстрый контроль (выполни и сразу проверь)

```bash
# 2.1 Проверка, где ты запускаешься
pwd
git rev-parse --show-toplevel

# 2.2 Создай рабочие папки под результаты
mkdir -p recon portscan synscan

# 2.3 Подтверди, что выходные файлы появятся именно здесь
ls -la recon portscan synscan
```

## 3) Что запускаем дальше (приоритет)

### P0 — восстановление пропусков из первого run
```bash
# DNS brute-force (устойчиво)
puredns bruteforce /path/wordlists/deep-dns.txt korbit.co.kr \
  -r /path/resolvers-trusted.txt \
  --write-massdns probing/puredns-massdns.txt \
  > probing/puredns-bruteforce-hosts.txt

cat probing/puredns-bruteforce-hosts.txt | httpx -silent -sc -title -td -server \
  > probing/puredns-bruteforce-http.txt

# Порты
awk '/ A /{print $3}' probing/dns-korbit.co.kr.txt | sort -u > ipspace/live-ip.txt
naabu -list ipspace/live-ip.txt -top-ports 2000 -rate 3000 -silent > portscan/naabu-top2k.txt
nmap -sV -sC -iL ipspace/live-ip.txt -oA synscan/korbit-followup
```

### P0 — shadow hosts из archive
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

### P1 — API/Auth/CORS по приоритетным endpoint
```bash
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

### P1 — recheck аномалий из ffuf
```bash
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

### P2 — takeover линия
```bash
awk '/CNAME/{print $1" "$3}' probing/dns-korbit.co.kr.txt > recon/cname-inventory.txt
subzy run --targets recon/cname-inventory.txt --verify_ssl --hide_fails > recon/cname-takeover-check.txt
```

## 4) Что прислать мне после этого
```bash
wc -l probing/puredns-bruteforce-hosts.txt probing/puredns-bruteforce-http.txt \
     probing/archive-shadow-dns.txt probing/archive-shadow-http.txt \
     portscan/naabu-top2k.txt recon/api-auth-cors-followup.txt \
     content-discovery/high-signal-recheck.txt recon/cname-takeover-check.txt

sed -n '1,120p' probing/archive-shadow-http.txt
sed -n '1,120p' recon/api-auth-cors-followup.txt
sed -n '1,120p' content-discovery/high-signal-recheck.txt
sed -n '1,120p' recon/cname-takeover-check.txt
```

С этими файлами я соберу точную exploit-очередь (P0/P1/P2) уже без догадок.
