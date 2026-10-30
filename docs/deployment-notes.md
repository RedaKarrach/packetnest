# PacketNest – deployment notes

> **Shared with the pentester on purpose.** PacketNest is a fictional application built for a PFA project: one of us secures and monitors it (Wazuh), the other attacks it. This file is the starting point for both sides.
> It lists every shortcut and known risk in this first version. Nothing here was planted on purpose: these are the normal gaps of an MVP built with framework defaults and no extra hardening. Use it to plan the attacks, to know what to watch in Wazuh, and to compare detections with the pentest report afterwards.

## Highest-impact risks

### 1. Server-side request forgery in "Import from URL" (critical on AWS)
- `core/services.py::download_capture` calls `requests.get(url)` on any http(s) URL the user types. There is no check of the destination host: internal addresses (`127.0.0.1`, `10.x`, the `db` container, other VPC hosts) and the **EC2 metadata service `169.254.169.254`** are reachable.
- Redirects are followed (requests default), so even an external URL can bounce to an internal one.
- The downloaded body is **stored as-is** before parsing, and the capture page has a **Download** button. So the response of any internal URL can be read back in full, even though the analysis fails (status "failed").
- On EC2 with IMDSv1 enabled, `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns the instance role's temporary AWS keys → access to the S3 bucket and the Secrets Manager secret (DB password).
- Error messages from `requests` (connection refused, timeouts, HTTP status) are shown to the user, which also allows internal port scanning.
- The 10 s timeout is per socket operation, not a total deadline; a slow server can keep a gunicorn worker busy much longer.
- Mitigation if wanted later: require **IMDSv2** with hop limit 1 on the instance (blocks containers from getting a token), restrict the instance role to the minimum, resolve and block private / link-local ranges, disable redirects.
- **Wazuh**: watch `packetnest.captures ... source_url=` log lines with internal IPs or `169.254.169.254`; CloudTrail for use of the role's credentials from outside the instance.

### 2. No brute-force protection
- No rate limiting, lockout or CAPTCHA on `/login/`, `/admin/login/`, `/signup/`, `/invite/<token>/` or the API. Only Django's password validators apply.
- Failed logins are logged as `packetnest.auth login failed user=... ip=...` (good Wazuh rule target), but the IP is taken from the first `X-Forwarded-For` value, which the client can forge (nginx appends to an existing header). nginx's own access log has the real address.

### 3. Public share links
- `/s/<token>/` needs no login. Tokens are 128-bit random (`token_urlsafe(16)`), never expire, and stay valid until revoked. Anyone who gets the URL (forwarded email, browser history, proxy logs, `Referer`) can read the report.
- Shared reports expose internal IP addresses, DNS names, the organisation name and FTP **usernames** from cleartext findings.
- Share links created by a member who is later removed stay active.

### 4. Invitations
- Invitation tokens never expire and are not tied to the email address: whoever has the link joins the organisation with the role chosen by the admin (which can be `org_admin`).
- Pending invitation links are displayed on the organisation page.
- No way to cancel an invitation from the UI (only via `/admin/`).

### 5. Synchronous analysis of untrusted files (availability)
- Every upload / import is parsed by Scapy inside the gunicorn worker (3 sync workers, 120 s timeout). A few concurrent 10 MB uploads (or very slow imports) can make the site unresponsive.
- Scapy is a large parser processing attacker-controlled input; a parser bug would run inside the web process.
- File type is checked only by extension (`.pcap` / `.pcapng`); any content is stored and kept even when the parse fails.

## Authentication, sessions and tokens

- Open self-service sign-up, no email verification, no CAPTCHA: anyone can create an organisation.
- Username enumeration is possible through the sign-up and invitation forms ("A user with that username already exists").
- DRF tokens (`rest_framework.authtoken`) are stored in **plaintext** in the database, never expire, are shown in full on the API page, and are not rotated on password change.
- Changing the password logs out the user's other browser sessions (Django default), but the API token keeps working.
- Session cookie lifetime is Django's default (2 weeks).
- Removing a member deletes the user account; an `org_admin` can remove another `org_admin`. There is no audit trail in the UI (only log lines).
- Django admin is at the default path `/admin/`, reachable from the internet, protected only by username/password. Staff accounts are created manually with `createsuperuser`.
- DRF's browsable API is enabled (default), which reveals the API structure to logged-in users.

## Transport and configuration

- **No HTTPS** in the compose setup: nginx listens on port 80 only. Passwords, session cookies and API tokens travel in cleartext until TLS is added (ALB + ACM, or certbot on the instance).
- `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, HSTS, `SECURE_PROXY_SSL_HEADER` and a Content-Security-Policy are **not** set (Django defaults). Clickjacking protection (`X-Frame-Options: DENY`) and `X-Content-Type-Options: nosniff` are on by default.
- nginx default `server_tokens on` shows the nginx version in error pages and headers.
- If `DJANGO_DEBUG=True` is ever set in production, full tracebacks and settings are shown on errors.
- When `DJANGO_DEBUG` or `USE_SQLITE` is on and `DJANGO_SECRET_KEY` is empty, a hard-coded development secret key is used. In production (`DEBUG=False`, PostgreSQL) the app refuses to start without the variable — make sure `USE_SQLITE` is not set to `1` there.
- `.env` on the host contains the DB password and Django secret key in cleartext (written at boot from Secrets Manager). Keep it `chmod 600`, owned by root.
- `seed_demo` prints the generated demo password to stdout when `SEED_PASSWORD` is empty; if run from user data, it ends up in `/var/log/cloud-init-output.log`. Demo users all share one password, and the demo admins are `atlas.admin`, `medina.admin`, `orion.admin`.
- The `web` container runs as a non-root user; PostgreSQL is not published on the host. The `db` container trusts the compose network with password auth.

## Storage

- S3: the app uses whatever permissions the instance role has. Scope the role to `s3:GetObject`/`s3:PutObject` on `arn:aws:s3:::<bucket>/*` and enable Block Public Access + default encryption on the bucket.
- Captures are never deleted (no delete feature, no lifecycle rule). They may contain real customer traffic and credentials once real users upload files.
- Local storage mode keeps files in the `media` Docker volume, unencrypted.
- Object keys are `<org_id>/<uuid>.pcap`; access control is enforced only by the Django views (organisation check before reading the key).

## Data exposure in the app

- Capture names, DNS names and other values from PCAPs are rendered in templates with Django autoescaping (no `|safe`), but they are attacker-controlled strings shown to other users and on public share pages.
- Exception messages from the parser are stored in `Capture.error` and shown on the capture page and share page.
- Organisation members see every capture of their organisation (no per-capture permissions).

## Logging / monitoring hints for Wazuh

- `docker compose logs nginx`: access log with real client IPs, status codes, request sizes (uploads up to 12 MB).
- `docker compose logs web`: gunicorn access log (client seen as the nginx container IP) and app log lines prefixed `packetnest.auth`, `packetnest.web`, `packetnest.captures`.
- Interesting patterns: bursts of `login failed`, `/admin/login/` POSTs, `source_url=` pointing at private / link-local addresses, many `share link created`, `invitation created` with role `org_admin`, `member removed`, 404 bursts on `/captures/<id>/` or `/api/captures/<id>/` (ID enumeration), large numbers of uploads.
- Docker's json-file logs live under `/var/lib/docker/containers/*/*-json.log` on the host; mount nginx logs to a host directory if you prefer plain files for the agent.
