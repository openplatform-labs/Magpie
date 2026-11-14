#!/bin/sh
# Locally generated certificate and isolated Compose project; no external calls.
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d /tmp/magpie-tls.XXXXXX)
test_project="magpietls$(date +%s)$$"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$test_dir/key.pem" -out "$test_dir/cert.pem" >/dev/null 2>&1
cat > "$test_dir/env" <<ENV
POSTGRES_DB=magpie
POSTGRES_USER=magpie
POSTGRES_PASSWORD=test-password
DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/magpie
MAGPIE_ADMIN_TOKEN=test-token-012345678901234567890123456789
MAGPIE_ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
MAGPIE_TLS_CERT=$test_dir/cert.pem
MAGPIE_TLS_KEY=$test_dir/key.pem
MAGPIE_TLS_PORT=18443
ENV
cat > "$test_dir/override.yml" <<'YAML'
services:
  backend:
    image: magpie-backend:latest
  frontend:
    image: magpie-frontend:latest
YAML
compose_test() { docker compose -p "$test_project" --env-file "$test_dir/env" -f docker-compose.yml -f deploy/compose.tls.yml -f "$test_dir/override.yml" "$@"; }
cleanup() { compose_test down -v --remove-orphans >/dev/null 2>&1 || :; rm -rf "$test_dir"; }
trap cleanup EXIT HUP INT TERM
compose_test up -d --no-build >/dev/null
compose_test exec -T backend alembic upgrade head
compose_test exec -T frontend nginx -t >/dev/null
printf 'GET /api/catalog HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | openssl s_client -quiet -tls1_2 -connect localhost:18443 -servername localhost -CAfile "$test_dir/cert.pem" -verify_hostname localhost -verify_return_error 2>/dev/null | grep -q '^HTTP/1.1 200'
printf 'GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | openssl s_client -quiet -tls1_3 -connect localhost:18443 -servername localhost -CAfile "$test_dir/cert.pem" -verify_hostname localhost -verify_return_error 2>/dev/null | grep -q '^HTTP/1.1 200'
if openssl s_client -quiet -tls1_1 -connect localhost:18443 -servername localhost -CAfile "$test_dir/cert.pem" -verify_return_error </dev/null > /dev/null 2>&1; then
  printf '%s\n' 'TLS 1.1 unexpectedly accepted' >&2
  exit 1
fi
curl --cacert "$test_dir/cert.pem" -fsS -D "$test_dir/headers" 'https://localhost:18443/oidc/callback?code=mock-code' -o /dev/null
grep -qi '^cache-control: no-store' "$test_dir/headers"
grep -qi '^x-content-type-options: nosniff' "$test_dir/headers"
grep -qi '^x-frame-options: DENY' "$test_dir/headers"
grep -qi '^referrer-policy: no-referrer' "$test_dir/headers"
grep -qi '^content-security-policy:' "$test_dir/headers"
curl --cacert "$test_dir/cert.pem" -fsS -D "$test_dir/admin-headers" -H 'Authorization: Bearer test-token-012345678901234567890123456789' https://localhost:18443/admin/providers > /dev/null
grep -qi '^cache-control: no-store' "$test_dir/admin-headers"
status=$(curl --cacert "$test_dir/cert.pem" -sS -o /dev/null -D "$test_dir/api-headers" -w '%{http_code}' https://localhost:18443/v1/models)
[ "$status" = 401 ]
grep -qi '^cache-control: no-store' "$test_dir/api-headers"
frontend_id=$(compose_test ps -q frontend)
if docker logs "$frontend_id" 2>&1 | grep -q 'mock-code'; then
  printf '%s\n' 'Callback query leaked into access logs' >&2
  exit 1
fi
backend_id=$(compose_test ps -q backend)
[ -z "$(docker port "$backend_id")" ]
python3 backend/tests/proxy_idle_check.py "$test_dir/cert.pem"
printf '%s\n' 'TLS 1.2/1.3, security headers, callback log protection, and private backend passed.'
