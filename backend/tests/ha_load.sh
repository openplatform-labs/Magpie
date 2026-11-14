#!/bin/sh
# Starts and removes only this test's isolated Docker Compose project and volume.
set -eu
unset POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD DATABASE_URL MAGPIE_ADMIN_TOKEN MAGPIE_ENCRYPTION_KEY
unset MAGPIE_ALLOWED_PROVIDER_BASES MAGPIE_PROVIDER_TIMEOUT_SECONDS
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
if ! python3 backend/tests/ha_load_client.py; then
  # This isolated stack contains synthetic credentials and provider responses.
  # Preserve access/error logs before teardown so 502s can be attributed.
  compose_test logs --no-color --tail=200 backend frontend >&2 || :
  exit 1
fi
backend_ids=$(compose_test ps -q backend)
[ "$(printf '%s\n' "$backend_ids" | wc -l | tr -d ' ')" = 2 ]
for id in $backend_ids; do
  for endpoint in embeddings chat/completions decisions; do
    docker logs "$id" 2>&1 | grep -q "POST /v1/$endpoint"
  done
done
printf '%s\n' 'Both backend instances served mocked embedding, generation and decision requests.'
python3 backend/tests/proxy_idle_check.py --http
