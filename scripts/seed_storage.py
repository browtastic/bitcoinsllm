"""
Seeds the storage directory with bait files for the CloudAIWallet honeypot.
All credential values are obviously fake placeholders.

Usage:
    STORAGE_ROOT=./storage python scripts/seed_storage.py
"""
import os

STORAGE_ROOT = os.environ.get("STORAGE_ROOT", "./storage")

FILES = {
    "config/env/.env": """# CloudAIWallet platform configuration — HONEYPOT BAIT FILE
# All values below are placeholder bait — not real credentials.

# Database
DATABASE_URL=postgresql://bait:bait@db.example-honeypot.local:5432/bait
REDIS_URL=redis://:bait@cache.example-honeypot.local:6379/0

# Auth
JWT_SECRET=HONEYPOT_BAIT_JWT_SECRET
ADMIN_PASSWORD=HONEYPOT_BAIT_ADMIN_PASSWORD

# AWS
AWS_ACCESS_KEY_ID=HONEYPOT_BAIT_AWS_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=HONEYPOT_BAIT_AWS_SECRET_KEY

# Crypto
HOT_WALLET_PRIVATE_KEY=HONEYPOT_BAIT_PRIVATE_KEY
COLD_WALLET_ADDRESS=0xBAITADDRESS000000000000000000000000000099

# Third-party APIs
OPENAI_API_KEY=HONEYPOT_BAIT_OPENAI_KEY
ANTHROPIC_API_KEY=HONEYPOT_BAIT_ANTHROPIC_KEY
STRIPE_SECRET=HONEYPOT_BAIT_STRIPE_KEY
""",

    "config/aws/credentials": """# AWS credentials — HONEYPOT BAIT FILE
# All values are obvious fake placeholders.

[default]
aws_access_key_id = HONEYPOT_BAIT_AWS_ACCESS_KEY
aws_secret_access_key = HONEYPOT_BAIT_AWS_SECRET_KEY
region = us-east-1

[admin]
aws_access_key_id = HONEYPOT_BAIT_AWS_ACCESS_KEY_ADMIN
aws_secret_access_key = HONEYPOT_BAIT_AWS_SECRET_KEY_ADMIN
region = us-east-1
""",

    "config/ssh/id_ed25519_admin": """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx
OQAAACCtyxAciOxWHm8FshhLdU6BN20tmRocSE1G1V3Ejuj0vQAAAIgZuoE3GbqBNwAAAAtzc2gt
ZWQyNTUxOQAAACCtyxAciOxWHm8FshhLdU6BN20tmRocSE1G1V3Ejuj0vQAAAECSf8NX0tn3GY/E
QuFKCl/hIFZYSwEaFyPVyt8mgQbtoK3LEByI7FYebwWyGEt1ToE3bS2ZGhxITUbVXcSO6PS9AAAA
AAECAwQF
-----END OPENSSH PRIVATE KEY-----
""",

    "backups/keys/mnemonic_backup.txt": """CloudAIWallet wallet recovery — HONEYPOT BAIT FILE
This is bait data. The mnemonic phrase below is a placeholder.

Mnemonic (12 words):
HONEYPOT BAIT SEED PHRASE TWELVE WORDS PLACEHOLDER VALUE FOR DEMO ONLY DO NOT USE

Derivation path: m/44'/60'/0'/0/0
""",

    "README.md": """# CloudAIWallet storage root

This directory holds the CloudAIWallet platform's persistent files.
All contents are honeypot bait — placeholder data for security research.

Subdirectories:
- config/    — service configuration files (env, AWS, SSH)
- backups/   — wallet backups and key archives
""",
}


def seed():
    for relpath, content in FILES.items():
        full = os.path.join(STORAGE_ROOT, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        # Restrictive perms on credential-style files
        if relpath.endswith(("credentials", "id_ed25519_admin", ".env")) or "mnemonic" in relpath:
            try:
                os.chmod(full, 0o600)
            except Exception:
                pass
        print(f"  Created: {full}")
    print("\nDone seeding bait storage.")


if __name__ == "__main__":
    seed()
