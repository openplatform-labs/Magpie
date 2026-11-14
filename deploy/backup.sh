#!/bin/sh
# Create a PostgreSQL custom-format backup without overwriting an existing file.
set -eu
if [ "$#" -ne 1 ]; then
    printf '%s\n' 'Usage: deploy/backup.sh BACKUP_FILE' >&2
    exit 2
fi
backup_path=$1
umask 077
# noclobber makes accidental replacement of a backup fail.
set -C
if ! (docker compose exec -T db sh -c 'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$backup_path"); then
    printf '%s\n' 'Backup failed; any newly created output file may be incomplete.' >&2
    exit 1
fi
printf '%s\n' 'Backup completed.'
