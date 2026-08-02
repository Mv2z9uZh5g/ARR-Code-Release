#!/bin/bash
set -euo pipefail

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-dataplatform}"
BACKUP_DIR="${HOME}/backups/postgres"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="${DB_NAME}_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[$(date)] Starting backup of ${DB_NAME}..."

pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${PGUSER}" -d "${DB_NAME}" \
    --format=plain \
    --no-owner \
    --no-privileges \
    | gzip > "${BACKUP_DIR}/${FILENAME}"

echo "[$(date)] Backup complete: ${BACKUP_DIR}/${FILENAME}"
echo "[$(date)] Size: $(du -h "${BACKUP_DIR}/${FILENAME}" | cut -f1)"

# Remove backups older than 7 days
find "${BACKUP_DIR}" -name "*.sql.gz" -mtime +7 -delete
echo "[$(date)] Cleaned up old backups"
