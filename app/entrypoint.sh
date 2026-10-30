#!/bin/sh
set -e

if [ "${USE_SQLITE:-0}" != "1" ]; then
  echo "Waiting for PostgreSQL at ${POSTGRES_HOST:-localhost}:${POSTGRES_PORT:-5432}..."
  python - <<'EOF'
import os
import sys
import time

import psycopg

params = dict(
    dbname=os.environ.get("POSTGRES_DB", "packetnest"),
    user=os.environ.get("POSTGRES_USER", "packetnest"),
    password=os.environ.get("POSTGRES_PASSWORD", ""),
    host=os.environ.get("POSTGRES_HOST", "localhost"),
    port=os.environ.get("POSTGRES_PORT", "5432"),
    connect_timeout=3,
)
for attempt in range(60):
    try:
        psycopg.connect(**params).close()
        print("PostgreSQL is up.")
        sys.exit(0)
    except psycopg.OperationalError:
        time.sleep(1)
print("PostgreSQL did not become available in time.", file=sys.stderr)
sys.exit(1)
EOF
fi

python manage.py migrate --noinput
python manage.py collectstatic --noinput

exec gunicorn packetnest.wsgi:application \
  --bind 0.0.0.0:8000 \
  --workers "${GUNICORN_WORKERS:-3}" \
  --timeout "${GUNICORN_TIMEOUT:-120}" \
  --access-logfile - \
  --error-logfile -
