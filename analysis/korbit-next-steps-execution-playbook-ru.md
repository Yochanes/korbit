# Korbit — что делать дальше (пошаговый playbook, RU)

Дата фиксации: 2026-04-19.

## 0) Что уже подтверждено по результатам
- Общий прогон Osmedeus завершен, workflow `general`, `scan-vuln` был исключен.
- Есть ошибки/пропуски в самом прогоне:
  - `dns-bruteforce` упал (`dnsx ... exited with code 2`).
  - `probe-port` модуль фактически не отработал (completed 1/7 шагов).
- Значит у нас «слепые зоны» по новым поддоменам и портам — закрываем их в первую очередь.

## 1) P0 — закрываем слепые зоны скана

### Шаг 1.1 — дочинить DNS brute-force
```bash
# В отдельный файл, чтобы не трогать исходные артефакты
dnsx -d korbit.co.kr \
  -w /path/to/wordlists/dns/deep-subdomains-top50000.txt \
  -r /path/to/resolvers-trusted.txt \
  -a -cname -resp -retry 3 -silent -json \
  > probing/dns-bruteforce-rerun-korbit.co.kr.jsonl

jq -r '.host' probing/dns-bruteforce-rerun-korbit.co.kr.jsonl | sort -u > probing/dns-bruteforce-hosts.txt
```

### Шаг 1.2 — поднять пропущенные хосты из archive
Из archive уже видно 8 хостов вне текущего subdomain-листа: `appback`, `bapi`, `gateway`, `indra`, `kdata-api`, `studio-waiting-room`, `vc`, `waiting-room-api`.
```bash
cat << 'EOF_HOSTS' > probing/archive-extra-hosts.txt
appback.korbit.co.kr
bapi.korbit.co.kr
gateway.korbit.co.kr
indra.korbit.co.kr
kdata-api.korbit.co.kr
studio-waiting-room.korbit.co.kr
vc.korbit.co.kr
waiting-room-api.korbit.co.kr
EOF_HOSTS

# DNS + HTTP recheck
cat probing/archive-extra-hosts.txt | dnsx -a -cname -resp -silent > probing/archive-extra-dns.txt
cat probing/archive-extra-hosts.txt | httpx -silent -sc -cl -title -server -td > probing/archive-extra-http.txt
```

### Шаг 1.3 — полноценный порт-профиль (модуль Osmedeus был неполный)
```bash
# Берем актуальные A-record IP
awk '/ A /{print $3}' probing/dns-korbit.co.kr.txt | sort -u > ipspace/live-a-records.txt

# Быстрый массовый профиль TCP
naabu -silent -list ipspace/live-a-records.txt -top-ports 2000 -rate 3000 -o portscan/naabu-top2000.txt

# Сервисная идентификация
nmap -sV -sC -iL ipspace/live-a-records.txt -oA synscan/korbit-svc-enum
```

## 2) P0 — API и auth-поверхность

### Шаг 2.1 — собрать все API/JS/Swagger пути
```bash
printf '%s\n' \
  https://api.korbit.co.kr \
  https://developers.korbit.co.kr \
  https://docs.korbit.co.kr \
  https://apidocs.korbit.co.kr \
| katana -silent -d 4 -jc -jsl -aff -xhr \
| tee recon/api-katana-2026.txt

# Отдельно вытащить вероятные API-роуты
rg -i '/(v1|v2|api|oauth|auth|token|ws|socket)' recon/api-katana-2026.txt > recon/api-priority-routes.txt
```

### Шаг 2.2 — auth, CORS, preflight и метод-спуфинг
```bash
cat recon/api-priority-routes.txt | head -n 200 | while read -r u; do
  echo "### $u"
  curl -isk "$u" -X OPTIONS -H 'Origin:https://evil.example' -H 'Access-Control-Request-Method: POST' | sed -n '1,25p'
  curl -isk "$u" -X POST -H 'Content-Type: application/json' --data '{}' | sed -n '1,25p'
  echo
 done > recon/api-cors-auth-check.txt
```

## 3) P0 — edge/cache/CDN misconfig

### Шаг 3.1 — cache-key poisoning sanity check
```bash
cat << 'EOF_URLS' > recon/cdn-targets.txt
https://cdn.korbit.co.kr
https://assets.korbit.co.kr
https://docs.korbit.co.kr
https://portal-cdn.korbit.co.kr
EOF_URLS

while read -r u; do
  echo "### $u"
  curl -isk "$u" -H 'X-Forwarded-Host: attacker.example' -H 'X-Original-URL: /admin' -H 'Cache-Control: no-cache' | sed -n '1,30p'
  echo
 done < recon/cdn-targets.txt > recon/cdn-cache-misconfig-check.txt
```

### Шаг 3.2 — subdomain takeover/dangling CNAME
```bash
awk '/CNAME/{print $1" "$3}' probing/dns-korbit.co.kr.txt > recon/cname-candidates.txt
subzy run --targets recon/cname-candidates.txt --hide_fails --verify_ssl > recon/subzy-candidates.txt
```

## 4) P1 — контент и бизнес-логика

### Шаг 4.1 — повторный ffuf по high-value хостам
```bash
cat << 'EOF_HV' > content-discovery/high-value-hosts.txt
https://api.korbit.co.kr
https://developers.korbit.co.kr
https://exchange.korbit.co.kr
https://biz.korbit.co.kr
https://portal.korbit.co.kr
https://portal-prod.korbit.co.kr
EOF_HV

while read -r t; do
  ffuf -u "$t/FUZZ" -w /path/to/wordlists/content/raft-medium-directories.txt \
    -mc all -fc 404,400,429 -ac -rate 150 -t 40 -o "content-discovery/ffuf-$(echo $t | tr '/:' '_').json" -of json
 done < content-discovery/high-value-hosts.txt
```

### Шаг 4.2 — JS secret hunting
```bash
# Собираем JS ссылки из katana
rg -o 'https?://[^"'"'"' ]+\.js[^"'"'"' ]*' recon/api-katana-2026.txt | sort -u > recon/js-urls.txt

# Секреты/токены
cat recon/js-urls.txt | xargs -n 1 -P 8 -I{} sh -c 'curl -ks "{}" | trufflehog filesystem --json /dev/stdin' > recon/js-secrets-trufflehog.jsonl
```

## 5) P2 — cloud & supply-chain

### Шаг 5.1 — cloud buckets / object storage exposure
```bash
cat << 'EOF_BUCKET' > recon/cloud-bucket-keywords.txt
korbit
korbit-assets
korbit-docs
portal-cdn
EOF_BUCKET

# Проверка публичности (минимальный шум)
while read -r k; do
  for d in s3.amazonaws.com storage.googleapis.com blob.core.windows.net; do
    curl -skI "https://$k.$d" | sed -n '1,5p'
  done
 done < recon/cloud-bucket-keywords.txt > recon/cloud-bucket-probe.txt
```

## 6) Что считаем успехом на следующей итерации
- Найдены и подтверждены новые живые хосты из archive-extra.
- Закрыт пробел по портам (есть `naabu` + `nmap` результаты).
- Для API есть таблица: endpoint → auth required? → CORS policy → risk.
- Для CDN есть конкретные кейсы «кешируется / не кешируется» с диффом заголовков.
- Для CNAME есть short-list takeover-кандидатов с валидацией.

## 7) Мини-таймлайн
- T+0–2ч: DNS brute-force rerun + archive-extra + naabu.
- T+2–6ч: katana API mapping + CORS/auth checks + CDN tests.
- T+6–10ч: ffuf high-value + JS secret hunting.
- T+10–12ч: triage, корреляция, формирование exploit-chain shortlist.
