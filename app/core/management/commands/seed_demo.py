import os
import secrets

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db import transaction

from core.models import Capture, Organisation, Profile, ShareLink
from core.services import create_capture
from core.synthetic import synthetic_pcap_bytes

COMPANIES = [
    {
        "name": "Atlas Logistics",
        "slug": "atlas-logistics",
        "prefix": "atlas",
        "domain": "atlas-logistics.example",
    },
    {
        "name": "Medina Clinic",
        "slug": "medina-clinic",
        "prefix": "medina",
        "domain": "medina-clinic.example",
    },
    {
        "name": "Orion Microfinance",
        "slug": "orion-microfinance",
        "prefix": "orion",
        "domain": "orion-microfinance.example",
    },
]

# (username suffix, role)
USERS = [
    ("admin", Profile.ROLE_ORG_ADMIN),
    ("analyst", Profile.ROLE_MEMBER),
    ("noc", Profile.ROLE_MEMBER),
]

# (capture name, synthetic kind or None for a deliberately broken file)
CAPTURES = [
    ("office-lan-morning.pcap", "mixed"),
    ("dns-troubleshooting.pcap", "dns"),
    ("web-proxy-sample.pcap", "web"),
    ("tls-uplink-check.pcap", "tls"),
    ("legacy-ftp-backup.pcap", "ftp"),
    ("ping-sweep-gateway.pcap", "icmp"),
    ("switch-mgmt-telnet.pcap", "telnet"),
    ("intranet-basic-auth.pcap", "basic_auth"),
]
BROKEN_CAPTURE = "export-truncated.pcap"


class Command(BaseCommand):
    help = "Create demo organisations, users and synthetic captures (idempotent)."

    def handle(self, *args, **options):
        password = os.environ.get("SEED_PASSWORD", "")
        generated = False
        if not password:
            password = secrets.token_urlsafe(12)
            generated = True

        created_users = []
        for index, company in enumerate(COMPANIES):
            with transaction.atomic():
                org, _ = Organisation.objects.get_or_create(slug=company["slug"], defaults={"name": company["name"]})
                users = []
                for suffix, role in USERS:
                    username = f"{company['prefix']}.{suffix}"
                    user = User.objects.filter(username=username).first()
                    if user is None:
                        user = User.objects.create_user(
                            username=username,
                            email=f"{suffix}@{company['domain']}",
                            password=password,
                        )
                        created_users.append(username)
                    Profile.objects.get_or_create(user=user, defaults={"organisation": org, "role": role})
                    users.append(user)

                for n, (name, kind) in enumerate(CAPTURES):
                    if kind == "basic_auth" and index != 0:
                        # Only one company has the Basic-auth sample; others get a broken export instead.
                        name, kind = BROKEN_CAPTURE, None
                    if Capture.objects.filter(organisation=org, name=name).exists():
                        continue
                    if kind is None:
                        data = b"\x0a\x0d\x0d\x0a" + secrets.token_bytes(64)
                    else:
                        data = synthetic_pcap_bytes(kind, seed=index * 100 + n)
                    create_capture(org, users[n % len(users)], name, data)

                first = Capture.objects.filter(organisation=org, name=CAPTURES[0][0]).first()
                if first and not first.share_links.exists():
                    ShareLink.objects.create(capture=first, created_by=users[0])

            self.stdout.write(f"{org.name}: {org.captures.count()} captures, {org.profiles.count()} users")

        if created_users:
            self.stdout.write(self.style.SUCCESS(f"Created users: {', '.join(created_users)}"))
            if generated:
                self.stdout.write(self.style.WARNING(f"Generated password for the new demo users (shown once): {password}"))
            else:
                self.stdout.write("Demo users use the password from SEED_PASSWORD.")
        else:
            self.stdout.write("Demo data already present, nothing to create.")
