#!/usr/bin/env bash
# Dohvacaju se SJAVNO javni podaci: CISA KEV popis i NVD (nist.gov) za zadnjih WINDOW_DAYS dana.
# Nista se salje van, nema naloga, nema placenih servisa. Pokreni:  bash fetch.sh
set -u
cd "$(dirname "$0")"
mkdir -p data/raw

WINDOW_DAYS=20
TODAY=$(date -u +%Y-%m-%d)
START=$(date -u -d "$TODAY -${WINDOW_DAYS} days" +%Y-%m-%d)
echo "prozor: $START .. $TODAY"

# search <-> datoteka
KEYS=$(cat <<'EOF'
linux kernel|kernel
openssl|openssl
glibc|glibc
sudo|sudo
openssh|openssh
curl|curl
systemd|systemd
bash|bash
zlib|zlib
kubernetes|kubernetes
etcd|etcd
containerd|containerd
runc|runc
openstack|openstack
ingress-nginx|ingress-nginx
helm|helm
grafana|grafana
prometheus|prometheus
loki|loki
jenkins|jenkins
gitlab|gitlab
ansible|ansible
vault|vault
argocd|argocd
EOF
)

echo "--- CISA KEV ---"
curl -sS -m 120 -o data/kev.json \
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  && echo "kev.json ok $(wc -c < data/kev.json) B"

n=0
while IFS='|' read -r label file; do
  [ -z "$label" ] && continue
  out="data/raw/$file.json"
  code=$(curl -sS -m 120 -G "https://services.nvd.nist.gov/rest/json/cves/2.0" \
    --data-urlencode "pubStartDate=${START}T00:00:00.000" \
    --data-urlencode "pubEndDate=${TODAY}T23:59:59.999" \
    --data-urlencode "keywordSearch=$label" \
    --data-urlencode "resultsPerPage=2000" \
    -o "$out" -w "%{http_code}")
  total=$(grep -o '"totalResults":[0-9]*' "$out" | head -1 | cut -d: -f2)
  echo "$label -> HTTP $code, ukupno $total, $(wc -c < "$out") B"
  n=$((n + 1))
  # NVD bez API kljuca dopusta 5 zahtjeva u 30 sekundi
  if [ $((n % 4)) -eq 0 ]; then echo "  ... pricekaj 32 s (NVD limit)"; sleep 32; fi
done <<EOF
$KEYS
EOF

# --- EPSS (FIRST): kolika je vjerojatnost da ce netko ovaj propust doista pokusati iskoristiti ---
# Jedan danasnji snimak sadrzi sve CVE-ove, pa nema batchanja. Prvi dan koji je gotov.
echo "--- EPSS ---"
EPSS_DATE=""
for back in 0 1 2 3; do
  d=$(date -u -d "today -${back} days" +%Y-%m-%d)
  code=$(curl -sSL -m 180 -o data/epss.gz -w "%{http_code}" "https://epss.cyentia.com/epss_scores-${d}.csv.gz")
  if [ "$code" = "200" ] && gunzip -t data/epss.gz 2>/dev/null; then EPSS_DATE=$d; break; fi
  echo "  snimak $d nije bio dostupan (HTTP $code)"
done
if [ -z "$EPSS_DATE" ]; then
  rm -f data/epss.gz
  echo "EPSS: nema snimka; epss stupce ostavljam prazne"
else
  grep -ho 'CVE-[0-9]\{4\}-[0-9]\{4,\}' data/raw/*.json | sort -u > data/.epss-want.txt
  want=$(wc -l < data/.epss-want.txt)
  { echo "# score_date:$EPSS_DATE"
    echo "cve,epss,percentile"
    gunzip -c data/epss.gz | awk -F, 'NR==FNR { want[$1] = 1; next } FNR > 2 && ($1 in want) { print $1 "," $2 "," $3 }' \
      data/.epss-want.txt -
  } > data/epss.csv
  got=$(($(wc -l < data/epss.csv) - 2))
  rm -f data/epss.gz data/.epss-want.txt
  echo "EPSS snimak $EPSS_DATE: ocjena za $got od $want trazenih CVE-ova"
fi
echo "gotovo"
