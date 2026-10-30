# PacketNest

PacketNest is a small multi-tenant SaaS for network teams in small companies. A team uploads packet captures (PCAP / PCAPNG), gets an automatic analysis, and shares read-only reports with colleagues.

Each company is an **organisation**. Every logged-in page and API call only sees the data of the user's own organisation.

## Features

1. **Accounts**: company sign-up (creates the organisation and its first user as `org_admin`), log in, log out, change password. Uses Django's auth views and default password validators.
2. **Captures**: upload a `.pcap` / `.pcapng` up to 10 MB. The file is stored (local disk or S3) and analysed right away with Scapy:
   packet count, duration, protocol breakdown (TCP, UDP, ICMP, ARP, DNS, HTTP, TLS, other), top 10 source IPs, top 10 conversations, up to 50 DNS query names, and **cleartext findings** (FTP `USER`/`PASS`, Telnet, HTTP `Authorization: Basic`). Findings say that credentials were seen; password values are never stored. Analysis stops after 200,000 packets.
3. **Import from URL**: paste an http(s) link, the server downloads the file (10 s timeout, 10 MB max) and processes it like an upload.
4. **Reports**: capture list (dashboard) and a detail page with pure HTML/CSS bar charts. **Share** creates a public read-only link `/s/<token>/` that can be revoked.
5. **REST API**: personal API token page (show / regenerate), `GET`/`POST /api/captures/`, `GET /api/captures/<id>/`, with token or session authentication.
6. **Organisation admin** (`org_admin` only): list and remove members, create invitations. The invitation link is shown on screen (no email is sent); `/invite/<token>/` lets the invitee create an account in that organisation.
7. **Staff admin**: Django admin at `/admin/` for platform staff.

## Architecture

```
            port 80
 browser ──────────► nginx (nginx:1.27-alpine)
                       │  proxy_pass, client_max_body_size 12m
                       ▼
                     web (python:3.12-slim, gunicorn + Django 5.1, whitenoise for /static)
                       │                     │
                       ▼                     ▼
                 db (postgres:16)     capture files: S3 bucket (CAPTURES_BUCKET)
                                       or media volume /app/media/captures/
```

- `app/packetnest/` – Django project (settings read everything from environment variables).
- `app/core/` – the application: models, views, API (`api.py`), Scapy analysis (`analysis.py`), storage (`storage.py`), synthetic PCAP generator (`synthetic.py`), `seed_demo` management command, tests.
- `app/templates/`, `app/core/templates/` – server-rendered templates; `app/core/static/core/style.css` – the only stylesheet (no CDN).
- `nginx/default.conf` – reverse proxy config.

Capture objects are stored under the key `<org_id>/<uuid>.pcap` (also for pcapng files).

### Data model

| Model | Fields |
|---|---|
| Organisation | name, slug, created_at |
| Profile | user (1:1), organisation, role (`member` / `org_admin`) |
| Capture | organisation, uploaded_by, name, storage_key, size_bytes, sha256, source_url, status (`pending` / `done` / `failed`), summary (JSON), error, created_at |
| ShareLink | capture, token, created_by, created_at, revoked |
| Invitation | organisation, email, role, token, created_at, accepted |

## Run locally (Docker)

Requirements: Docker with Compose v2, port 80 free.

```bash
cp .env.example .env
```

Edit `.env` and at least set `DJANGO_SECRET_KEY` and `POSTGRES_PASSWORD` to random values, then:

```bash
docker compose up -d --build
```

```bash
docker compose exec web python manage.py seed_demo
```

Open http://localhost/. The `web` container waits for PostgreSQL, runs migrations and `collectstatic`, then starts gunicorn.

Create a platform staff account for `/admin/`:

```bash
docker compose exec web python manage.py createsuperuser
```

Stop everything with `docker compose down` (add `-v` to also delete the database and capture volumes).

### Demo data

`seed_demo` creates three fictional companies with three users each and 8 synthetic captures per company (24 in total), plus one share link per company. It is idempotent: running it again creates nothing new.

| Company | Users (first one is `org_admin`) |
|---|---|
| Atlas Logistics | `atlas.admin`, `atlas.analyst`, `atlas.noc` |
| Medina Clinic | `medina.admin`, `medina.analyst`, `medina.noc` |
| Orion Microfinance | `orion.admin`, `orion.analyst`, `orion.noc` |

The password comes from `SEED_PASSWORD`; if it is empty, a random one is generated and printed once. To choose it at seed time:

```bash
docker compose exec -e SEED_PASSWORD='choose-a-password' web python manage.py seed_demo
```

All captures are generated in memory by `core/synthetic.py` (fictional `.example` domains, RFC 1918 / RFC 5737 addresses, fake FTP login `demo_user`). One capture per company for Medina and Orion is a deliberately corrupted file, to show the "failed" state.

## Run tests

Tests use SQLite and local storage, no Docker needed:

```bash
cd app
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
USE_SQLITE=1 python manage.py test
```

They cover sign-up, login and password change, upload and analysis (protocols, FTP / Telnet / Basic-auth findings, pcapng, failed parse, size and packet limits), cross-organisation isolation on web pages and API (404), share links and revocation, API token list/upload, URL import (mocked `requests.get`), member removal permissions, the invitation flow and `seed_demo` idempotence.

To run the dev server without Docker: `USE_SQLITE=1 DJANGO_DEBUG=True python manage.py migrate && USE_SQLITE=1 DJANGO_DEBUG=True python manage.py runserver`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_SECRET_KEY` | – (required unless `DJANGO_DEBUG` or `USE_SQLITE`) | Django secret key |
| `DJANGO_DEBUG` | `False` | Debug mode |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated host names the site answers to |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | empty | Comma-separated origins, e.g. `https://packetnest.example.com` |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | `packetnest` / `packetnest` / – | Database credentials (also used by the `db` container) |
| `POSTGRES_HOST` / `POSTGRES_PORT` | `localhost` / `5432` | Database address (forced to `db:5432` in compose) |
| `CAPTURES_BUCKET` | empty | S3 bucket for captures; empty = local `MEDIA_ROOT/captures/` |
| `AWS_REGION` | empty | Region for the S3 client |
| `USE_SQLITE` | `0` | `1` = use `app/db.sqlite3` instead of PostgreSQL |
| `SEED_PASSWORD` | empty | Password for demo users created by `seed_demo` |
| `MEDIA_ROOT` | `app/media` | Local capture storage root |
| `GUNICORN_WORKERS` / `GUNICORN_TIMEOUT` | `3` / `120` | gunicorn tuning (entrypoint) |

## API

Get your token on the **API** page, then:

```bash
curl -H "Authorization: Token <token>" http://localhost/api/captures/
```

```bash
curl -H "Authorization: Token <token>" -F "file=@capture.pcap" -F "name=core-switch" http://localhost/api/captures/
```

```bash
curl -H "Authorization: Token <token>" http://localhost/api/captures/1/
```

The list is paginated (50 per page) and only contains the caller's organisation; another organisation's capture returns 404.

## Running on AWS

Planned target setup:

- **EC2** instance (Amazon Linux 2023 or Ubuntu) with Docker and the Compose plugin, running this same `docker-compose.yml`.
- **IAM instance role** attached to the instance, allowing `s3:PutObject` / `s3:GetObject` on the captures bucket and `secretsmanager:GetSecretValue` on the database secret. The app never reads AWS keys from settings: boto3 uses the default credential chain, which on EC2 gets temporary credentials from the instance metadata service.
- **S3 bucket** for captures, set as `CAPTURES_BUCKET` (with `AWS_REGION`). Block all public access on it.
- **Secrets Manager** holds the PostgreSQL password (and the Django secret key). A boot script (user data or a systemd unit) fetches them with the AWS CLI and writes `.env` before `docker compose up -d`, for example:

  ```bash
  DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id packetnest/db --query SecretString --output text)
  ```

  then writes `POSTGRES_PASSWORD=$DB_PASSWORD` and the other variables into `/opt/packetnest/.env` (mode 600).
- `DJANGO_ALLOWED_HOSTS` set to the instance's public DNS name / domain; security group open on 80 (and 443 once TLS is added), SSH restricted.
- **Monitoring**: the Wazuh agent on the instance can collect the Docker container logs (nginx access/error logs, gunicorn access log, and the app's `packetnest.*` log lines for logins, failed logins, sign-ups, uploads, imports, share links, invitations and member removals).

## Design choices

- Each packet counts once in the protocol breakdown, under its most specific category: ARP, DNS, then HTTP / TLS (detected from the TCP payload), ICMP, then plain TCP / UDP, else "other". The bars therefore add up to the packet count.
- FTP findings keep the username but only a `password_seen` flag; HTTP Basic findings keep the client, server and `Host`, never the header value.
- Analysis runs synchronously in the request (no task queue), as the spec asks; gunicorn's timeout is 120 s.
- Any member can create a share link; the link's creator or an `org_admin` can revoke it.
- Removing a member deletes that user account. Their captures stay in the organisation (shown as "removed user"). An `org_admin` cannot remove themselves.
- Invitations are single-use; the invitee chooses a username and password, and the account email is the invited address.
- Users without a profile (e.g. a superuser created with `createsuperuser`) only use `/admin/`; organisation pages tell them they are not attached to an organisation.
- A capture detail page has a **Download** button for the original file.
- Local tests were run with Python 3.13; the Docker image uses Python 3.12 as specified. Dependencies are pinned in `app/requirements.txt`.
