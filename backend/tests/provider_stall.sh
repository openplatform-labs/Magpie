#!/bin/sh
# Local mock providers only; remove only this test's temporary Compose project.
set -eu
unset POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD DATABASE_URL MAGPIE_ADMIN_TOKEN MAGPIE_ENCRYPTION_KEY
unset MAGPIE_OIDC_ISSUER MAGPIE_OIDC_AUTHORIZATION_URL MAGPIE_OIDC_TOKEN_URL MAGPIE_OIDC_JWKS_URL MAGPIE_OIDC_CLIENT_ID MAGPIE_OIDC_CLIENT_SECRET MAGPIE_OIDC_REDIRECT_URI MAGPIE_ALLOWED_PROVIDER_BASES MAGPIE_PROVIDER_TIMEOUT_SECONDS
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d /tmp/magpie-stall.XXXXXX)
test_project="magpiestall$(date +%s)$$"
cat > "$test_dir/env" <<'ENV'
POSTGRES_DB=magpie
POSTGRES_USER=magpie
POSTGRES_PASSWORD=test-password
DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/magpie
MAGPIE_ADMIN_TOKEN=test-token-012345678901234567890123456789
MAGPIE_ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
MAGPIE_PROVIDER_TIMEOUT_SECONDS=1
ENV
cat > "$test_dir/override.yml" <<YAML
services:
  backend:
    image: magpie-backend:latest
    command: ["uvicorn", "mock_gateway:app", "--host", "0.0.0.0", "--port", "8000"]
    volumes:
      - "$(pwd)/backend/tests/mock_gateway.py:/app/mock_gateway.py:ro"
  frontend:
    image: magpie-frontend:latest
    ports: !override ["127.0.0.1:18085:80"]
YAML
compose_test() { docker compose -p "$test_project" --env-file "$test_dir/env" -f docker-compose.yml -f deploy/compose.ha.yml -f "$test_dir/override.yml" "$@"; }
cleanup() { compose_test down -v --remove-orphans >/dev/null 2>&1 || :; rm -rf "$test_dir"; }
trap cleanup EXIT HUP INT TERM
compose_test up -d --no-build >/dev/null
compose_test exec -T backend alembic upgrade head
python3 backend/tests/provider_stall_client.py
backend_ids=$(compose_test ps -q backend)
closed=0
for id in $backend_ids; do
    if docker logs "$id" 2>&1 | grep -q 'MOCK_STREAM_CLOSED'; then closed=1; fi
    docker logs "$id" 2>&1 | grep -q 'POST /admin/api-keys'
done
[ "$closed" = 1 ]
printf '%s\n' 'Timed-out mocked provider stream was closed.'
printf '%s\n' 'Both test workers handled key issuance requests.'
