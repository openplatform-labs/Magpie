#!/bin/sh
# Uses a disposable database and test-only credentials; no provider calls.
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d /tmp/magpie-bootstrap.XXXXXX)
test_project="magpiebootstrap$(date +%s)$$"
cat > "$test_dir/env" <<'ENV'
POSTGRES_DB=magpie
POSTGRES_USER=magpie
POSTGRES_PASSWORD=test-password
DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/magpie
MAGPIE_ADMIN_TOKEN=
MAGPIE_ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
ENV
cat > "$test_dir/override.yml" <<'YAML'
services:
  backend:
    image: magpie-backend:latest
    ports: !override []
YAML
compose_test() { docker compose -p "$test_project" --env-file "$test_dir/env" -f docker-compose.yml -f "$test_dir/override.yml" "$@"; }
cleanup() { compose_test down -v --remove-orphans >/dev/null 2>&1 || :; rm -rf "$test_dir"; }
trap cleanup EXIT HUP INT TERM
wait_live() {
  for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if compose_test exec -T backend python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}
compose_test up -d db >/dev/null
compose_test run -T --rm backend alembic upgrade head
compose_test up -d --no-build backend >/dev/null
wait_live
compose_test exec -T backend python - absent < backend/tests/bootstrap_retire.py
printf '%s\n' 'MAGPIE_ADMIN_TOKEN=replace-with-a-random-token-at-least-32-characters' >> "$test_dir/env"
compose_test up -d --no-build backend >/dev/null
wait_live
compose_test exec -T backend python - placeholder < backend/tests/bootstrap_retire.py
printf '%s\n' 'MAGPIE_ADMIN_TOKEN=test-bootstrap-token-012345678901234567890123456789' >> "$test_dir/env"
compose_test up -d --no-build backend >/dev/null
wait_live
compose_test exec -T backend python - create < backend/tests/bootstrap_retire.py
printf '%s\n' 'MAGPIE_ADMIN_TOKEN=' >> "$test_dir/env"
compose_test up -d --no-build backend >/dev/null
wait_live
compose_test exec -T backend python - retired < backend/tests/bootstrap_retire.py
