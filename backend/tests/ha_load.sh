#!/bin/sh
# Starts and removes only this test's isolated Docker Compose project and volume.
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d /tmp/magpie-ha-load.XXXXXX)
test_project="magpieload$(date +%s)$$"
cat > "$test_dir/env" <<'ENV'
POSTGRES_DB=magpie
POSTGRES_USER=magpie
POSTGRES_PASSWORD=test-password
DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/magpie
MAGPIE_ADMIN_TOKEN=test-token-012345678901234567890123456789
MAGPIE_ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
ENV
cat > "$test_dir/override.yml" <<YAML
services:
  backend:
    image: magpie-backend:latest
    command: ["uvicorn", "mock_gateway:app", "--host", "0.0.0.0", "--port", "8000"]
    environment:
      MAGPIE_OIDC_ISSUER: https://identity.example
      MAGPIE_OIDC_AUTHORIZATION_URL: https://identity.example/authorize
      MAGPIE_OIDC_TOKEN_URL: https://identity.example/token
      MAGPIE_OIDC_JWKS_URL: https://identity.example/jwks
      MAGPIE_OIDC_CLIENT_ID: magpie-test
      MAGPIE_OIDC_REDIRECT_URI: https://magpie.example/oidc/callback
    volumes:
      - "$(pwd)/backend/tests/mock_gateway.py:/app/mock_gateway.py:ro"
  frontend:
    image: magpie-frontend:latest
    ports: !override ["127.0.0.1:18082:80"]
YAML
compose_test() { docker compose -p "$test_project" --env-file "$test_dir/env" -f docker-compose.yml -f deploy/compose.ha.yml -f "$test_dir/override.yml" "$@"; }
cleanup() { compose_test down -v --remove-orphans >/dev/null 2>&1 || :; rm -rf "$test_dir"; }
trap cleanup EXIT HUP INT TERM
compose_test up -d --no-build >/dev/null
compose_test exec -T backend alembic upgrade head
python3 backend/tests/ha_load_client.py
backend_ids=$(compose_test ps -q backend)
[ "$(printf '%s\n' "$backend_ids" | wc -l | tr -d ' ')" = 2 ]
exchanges=0
for id in $backend_ids; do
  for endpoint in embeddings chat/completions decisions; do
    docker logs "$id" 2>&1 | grep -q "POST /v1/$endpoint"
  done
  docker logs "$id" 2>&1 | grep -q 'POST /auth/oidc/callback'
  count=$(docker logs "$id" 2>&1 | grep -c 'MOCK_OIDC_EXCHANGE_EXECUTED' || :)
  exchanges=$((exchanges + count))
done
[ "$exchanges" -eq 1 ]
printf '%s\n' 'Both backend instances served mocked embedding, generation and decision requests.'
printf '%s\n' 'Both backend instances received OIDC callbacks; exactly one mock exchange occurred.'
python3 backend/tests/proxy_idle_check.py --http
