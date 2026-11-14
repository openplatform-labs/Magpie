#!/bin/sh
# Isolated multi-instance smoke test. Creates and removes only its own temporary Compose project.
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d /tmp/magpie-ha-test.XXXXXX)
test_project="magpieha$(date +%s)$$"
cat > "$test_dir/env" <<'ENV'
POSTGRES_DB=magpie
POSTGRES_USER=magpie
POSTGRES_PASSWORD=test-password
DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/magpie
MAGPIE_ADMIN_TOKEN=test-token-012345678901234567890123456789
MAGPIE_ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
ENV
cat > "$test_dir/override.yml" <<'YAML'
services:
  backend:
    image: magpie-backend:latest
  frontend:
    image: magpie-frontend:latest
    ports: !override ["127.0.0.1:18081:80"]
YAML
compose_test() { docker compose -p "$test_project" --env-file "$test_dir/env" -f docker-compose.yml -f deploy/compose.ha.yml -f "$test_dir/override.yml" "$@"; }
cleanup() { compose_test down -v --remove-orphans >/dev/null 2>&1 || :; rm -rf "$test_dir"; }
trap cleanup EXIT HUP INT TERM
compose_test up -d --no-build >/dev/null
compose_test exec -T backend alembic upgrade head
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do curl -fsS http://127.0.0.1:18081/api/catalog >/dev/null; done
backend_ids=$(compose_test ps -q backend)
[ "$(printf '%s\n' "$backend_ids" | wc -l | tr -d ' ')" = 2 ]
for id in $backend_ids; do docker logs "$id" 2>&1 | grep -q 'GET /api/catalog'; done
printf '%s\n' 'Two backend instances served API requests against the same PostgreSQL database.'
