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
echo "gotovo"
