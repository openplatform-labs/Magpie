#!/bin/sh
# Verify dump/restore across two isolated PostgreSQL images. Never uses the
# user's running database or calls external model providers.
set -eu
cd "$(dirname "$0")/../.."
if [ "$#" -ne 2 ]; then
    printf '%s\n' 'Usage: sh backend/tests/postgres_upgrade.sh SOURCE_IMAGE TARGET_IMAGE' >&2
    exit 2
fi
source_image=$1
target_image=$2
test_dir=$(mktemp -d /tmp/magpie-upgrade-test.XXXXXX)
cp backend/tests/backup_fixture.py "$test_dir/fixture.py"
test_id="$(date +%s)$$"
source_project="magpieupgradefrom$test_id"
target_project="magpieupgradeto$test_id"
export POSTGRES_DB=magpie POSTGRES_USER=magpie POSTGRES_PASSWORD=test-password
export DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/magpie
export MAGPIE_ADMIN_TOKEN=test-token-012345678901234567890123456789
export MAGPIE_ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
cat > "$test_dir/override.yml" <<'YAML'
services:
  db:
    image: ${MAGPIE_TEST_POSTGRES_IMAGE:?Test image required}
  backend:
    image: magpie-backend:latest
    ports: !override []
  frontend:
    image: magpie-frontend:latest
    ports: !override []
YAML
export COMPOSE_FILE="$(pwd)/docker-compose.yml:$test_dir/override.yml"
cleanup() {
    COMPOSE_PROJECT_NAME="$source_project" MAGPIE_TEST_POSTGRES_IMAGE="$source_image" docker compose down -v --remove-orphans >/dev/null 2>&1 || :
    COMPOSE_PROJECT_NAME="$target_project" MAGPIE_TEST_POSTGRES_IMAGE="$target_image" docker compose down -v --remove-orphans >/dev/null 2>&1 || :
    rm -rf "$test_dir"
}
trap cleanup EXIT HUP INT TERM
export COMPOSE_PROJECT_NAME="$source_project" MAGPIE_TEST_POSTGRES_IMAGE="$source_image"
docker compose up -d --wait db >/dev/null
docker compose run -T --rm --no-deps backend alembic upgrade head
docker compose run -T --rm --no-deps backend python - seed < "$test_dir/fixture.py"
sh deploy/backup.sh "$test_dir/source.dump"
export COMPOSE_PROJECT_NAME="$target_project" MAGPIE_TEST_POSTGRES_IMAGE="$target_image"
docker compose up -d --wait db >/dev/null
sh deploy/restore-new.sh "$test_dir/source.dump" restored_db
docker compose run -T --rm --no-deps -e DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/restored_db backend python - verify < "$test_dir/fixture.py"
printf 'Verified isolated backup restore from %s to %s.\n' "$source_image" "$target_image"
