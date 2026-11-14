#!/bin/sh
# Restore to a newly created database only. Never drops or overwrites an existing database.
set -eu
if [ "$#" -ne 2 ]; then
    printf '%s\n' 'Usage: deploy/restore-new.sh BACKUP_FILE NEW_DATABASE_NAME' >&2
    exit 2
fi
backup_path=$1
new_database=$2
case "$new_database" in
    ''|*[!a-z0-9_]*) printf '%s\n' 'Database name must contain lowercase letters, digits, or underscores.' >&2; exit 2 ;;
esac
if [ ! -f "$backup_path" ]; then printf '%s\n' 'Backup file not found.' >&2; exit 2; fi
docker compose exec -T db sh -c 'exec createdb -U "$POSTGRES_USER" "$1"' sh "$new_database"
if ! docker compose exec -T db sh -c 'exec pg_restore -U "$POSTGRES_USER" --exit-on-error --no-owner -d "$1"' sh "$new_database" < "$backup_path"; then
    printf '%s\n' 'Restore failed. The new database was left in place for inspection.' >&2
    exit 1
fi
printf '%s\n' 'Restore completed to the new database.'
