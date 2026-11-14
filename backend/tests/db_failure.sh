#!/bin/sh
# Uses only this script's isolated project; never touches the user's running DB.
set -eu
unset POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD DATABASE_URL MAGPIE_ADMIN_TOKEN MAGPIE_ENCRYPTION_KEY
unset MAGPIE_ALLOWED_PROVIDER_BASES MAGPIE_PROVIDER_TIMEOUT_SECONDS
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d /tmp/magpie-db-failure.XXXXXX)
test_project="magpiedbtest$(date +%s)$$"
cat > "$test_dir/env" <<'ENV'
POSTGRES_DB=magpie
POSTGRES_USER=magpie
POSTGRES_PASSWORD=test-password
DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/magpie
MAGPIE_ADMIN_TOKEN=test-token-012345678901234567890123456789
MAGPIE_ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
MAGPIE_PROVIDER_TIMEOUT_SECONDS=75
ENV
cat > "$test_dir/override.yml" <<YAML
services:
  backend:
    image: magpie-backend:latest
    environment:
      MAGPIE_TEST_DELAY_SECONDS: ${MAGPIE_TEST_DELAY_SECONDS:-1}
    command: ["uvicorn", "mock_gateway:app", "--host", "0.0.0.0", "--port", "8000"]
    volumes:
      - "$(pwd)/backend/tests/mock_gateway.py:/app/mock_gateway.py:ro"
  frontend:
    image: magpie-frontend:latest
    ports: !override ["127.0.0.1:18084:80"]
YAML
compose_test() { docker compose -p "$test_project" --env-file "$test_dir/env" -f docker-compose.yml -f deploy/compose.ha.yml -f "$test_dir/override.yml" "$@"; }
cleanup() { compose_test down -v --remove-orphans >/dev/null 2>&1 || :; rm -rf "$test_dir"; }
trap cleanup EXIT HUP INT TERM
compose_test up -d --no-build >/dev/null
compose_test exec -T backend alembic upgrade head
python3 backend/tests/db_failure_client.py setup "$test_dir/key"
python3 backend/tests/db_failure_client.py inflight "$test_dir/key" > "$test_dir/inflight.log" 2>&1 &
inflight_pid=$!
backend_ids=$(compose_test ps -q backend)
waiting=0
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    for id in $backend_ids; do
        if docker logs "$id" 2>&1 | grep -q 'MOCK_EMBEDDING_WAITING'; then waiting=1; break; fi
    done
    [ "$waiting" = 0 ] || break
    sleep 0.2
done
[ "$waiting" = 1 ]
db_id=$(compose_test ps -q db)
docker stop --time 2 "$db_id" >/dev/null
wait "$inflight_pid"
python3 backend/tests/db_failure_client.py down "$test_dir/key"
docker start "$db_id" >/dev/null
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if curl --max-time 4 -fsS http://127.0.0.1:18084/health/ready >/dev/null 2>&1; then ready=1; break; fi
    sleep 1
done
[ "$ready" = 1 ]
python3 backend/tests/db_failure_client.py recovered "$test_dir/key"
backend_ids=$(compose_test ps -q backend)
count=0
for id in $backend_ids; do
    observed=$(docker logs "$id" 2>&1 | grep -c 'MOCK_EMBEDDING_EXECUTED' || :)
    count=$((count + observed))
done
[ "$count" = 3 ]
printf '%s\n' 'No new provider calls started while PostgreSQL was unavailable.'

# Kill only the test worker handling an in-flight request. Nginx must not
# replay that request to the other worker; the committed usage record remains.
python3 backend/tests/db_failure_client.py crash_inflight "$test_dir/key" > "$test_dir/crash.log" 2>&1 &
inflight_pid=$!
crashed_id=''
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    for id in $backend_ids; do
        if docker logs "$id" 2>&1 | grep -q 'MOCK_CRASH_WAITING'; then crashed_id=$id; break; fi
    done
    [ -z "$crashed_id" ] || break
    sleep 0.2
done
[ -n "$crashed_id" ]
docker kill "$crashed_id" >/dev/null
wait "$inflight_pid"
docker start "$crashed_id" >/dev/null
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ "$(docker inspect --format '{{.State.Health.Status}}' "$crashed_id")" = healthy ]; then ready=1; break; fi
    sleep 1
done
[ "$ready" = 1 ]
python3 backend/tests/db_failure_client.py crash_recovered "$test_dir/key"
count=0
for id in $backend_ids; do
    observed=$(docker logs "$id" 2>&1 | grep -c 'MOCK_EMBEDDING_EXECUTED' || :)
    count=$((count + observed))
done
[ "$count" = 5 ]
python3 backend/tests/db_failure_client.py slow_proxy "$test_dir/key"
