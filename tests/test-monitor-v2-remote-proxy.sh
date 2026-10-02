#!/usr/bin/env bash
# Real nginx parser gate. No service is installed, started or contacted.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
[ "$(uname -s)" = Linux ] || { echo 'FAIL nginx gate requires Linux (no skip)'; exit 1; }
command -v nginx >/dev/null
command -v openssl >/dev/null
nginx -v 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=probes.example.com' \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" >/dev/null 2>&1
mkdir -p "$TMP/body" "$TMP/proxy"
sed -e "s|/etc/ssl/probes.example.com.fullchain.pem|$TMP/cert.pem|" \
    -e "s|/etc/ssl/probes.example.com.key|$TMP/key.pem|" \
    "$ROOT/monitor-v2/deploy/remote-probes-proxy.conf.example" > "$TMP/ingress.conf"
cat > "$TMP/nginx.conf" <<EOF
pid $TMP/nginx.pid;
error_log stderr;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $TMP/body;
    proxy_temp_path $TMP/proxy;
    include $TMP/ingress.conf;
}
EOF
nginx -t -p "$TMP/" -c "$TMP/nginx.conf"
echo 'PASS nginx/production_example_validates_in_http_context'
# Move the two zones back into server{} to reproduce Blocker 7. The real
# parser must reject this mutation; directive grep cannot satisfy this gate.
awk '
    /^limit_req_zone|^limit_conn_zone/ { zones=zones $0 "\n"; next }
    /^server \{/ { print; printf "%s", zones; next }
    { print }
' "$TMP/ingress.conf" > "$TMP/invalid.conf"
sed "s|$TMP/ingress.conf|$TMP/invalid.conf|" "$TMP/nginx.conf" > "$TMP/invalid-nginx.conf"
if nginx -t -p "$TMP/" -c "$TMP/invalid-nginx.conf" > "$TMP/invalid.log" 2>&1; then
    echo 'FAIL nginx/invalid_server_context_was_accepted'
    exit 1
fi
grep -q 'directive is not allowed here' "$TMP/invalid.log"
echo 'PASS nginx/original_invalid_zone_context_rejected'
echo 'nginx parser checks: 2 passed, 0 failed'
