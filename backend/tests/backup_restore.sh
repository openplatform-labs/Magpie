#!/bin/sh
# All databases and credentials belong to a unique isolated Compose project.
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d /tmp/magpie-backup-test.XXXXXX)
cp backend/tests/backup_fixture.py "$test_dir/fixture.py"
export COMPOSE_PROJECT_NAME="magpiebackup$(date +%s)$$"
export POSTGRES_DB=magpie POSTGRES_USER=magpie POSTGRES_PASSWORD=test-password
export DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/magpie
export MAGPIE_ADMIN_TOKEN=test-token-012345678901234567890123456789
export MAGPIE_ENCRYPTION_KEY=MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=
cat > "$test_dir/override.yml" <<'YAML'
services:
  backend:
    image: magpie-backend:latest
    ports: !override []
  frontend:
    image: magpie-frontend:latest
    ports: !override []
YAML
export COMPOSE_FILE="$(pwd)/docker-compose.yml:$test_dir/override.yml"
cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || :; rm -rf "$test_dir"; }
trap cleanup EXIT HUP INT TERM
docker compose up -d --wait db >/dev/null
docker compose run -T --rm --no-deps backend alembic upgrade head
docker compose run -T --rm --no-deps backend python - seed < "$test_dir/fixture.py"
sh deploy/backup.sh "$test_dir/backup.dump"
python3 -c 'import os,sys; assert os.stat(sys.argv[1]).st_mode & 0o077 == 0' "$test_dir/backup.dump"
cp "$test_dir/backup.dump" "$test_dir/original.dump"
if sh deploy/backup.sh "$test_dir/backup.dump" >/dev/null 2>&1; then
    printf '%s\n' 'Backup overwrote an existing file' >&2; exit 1
fi
cmp "$test_dir/backup.dump" "$test_dir/original.dump"
sh deploy/restore-new.sh "$test_dir/backup.dump" restored_db
docker compose run -T --rm --no-deps -e DATABASE_URL=postgresql+psycopg://magpie:test-password@db:5432/restored_db backend python - verify < "$test_dir/fixture.py"
if sh deploy/restore-new.sh "$test_dir/backup.dump" restored_db >/dev/null 2>&1; then
    printf '%s\n' 'Restore overwrote an existing database' >&2; exit 1
fi
if sh deploy/restore-new.sh "$test_dir/backup.dump" 'invalid-name' >/dev/null 2>&1; then
    printf '%s\n' 'Restore accepted an invalid database name' >&2; exit 1
fi
printf '%s\n' 'invalid archive' > "$test_dir/broken.dump"
if sh deploy/restore-new.sh "$test_dir/broken.dump" failed_restore >/dev/null 2>&1; then
    printf '%s\n' 'Restore accepted an invalid archive' >&2; exit 1
fi
docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d postgres -Atc "SELECT datname FROM pg_database WHERE datname = '\''failed_restore'\''"' | grep -qx failed_restore
docker compose run -T --rm --no-deps backend python - verify < "$test_dir/fixture.py"
printf '%s\n' 'Backup and isolated restore passed; existing file/database were preserved.'
