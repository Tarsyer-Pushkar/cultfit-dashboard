#!/usr/bin/env python3
"""
Standalone admin bootstrap script for the cultfit-dashboard.

Run once manually:  python create_admin.py

1. Connects to MongoDB using the same env vars as app.py (_get_db).
2. Creates username/email indexes on the users collection.
3. Idempotently migrates the existing cultfit@tarsyer.com user.
4. Idempotently creates an admin user via interactive prompts.

Does NOT import app.py — uses its own minimal Mongo connection to avoid
triggering Flask/GCS init side effects.
"""

import os, sys, getpass, re
from datetime import datetime, timedelta
from dotenv import load_dotenv
import pymongo
import bcrypt

load_dotenv()

PASSWORD_EXPIRY_DAYS = 30

# ─── Minimal password policy (duplicated from app.py on purpose) ──────────────
_COMMON_PASSWORDS = {
    'password1234', 'password123!', 'changeme1234', 'admin1234567',
    'letmein12345', 'welcome12345', '123456789012', 'qwerty123456',
    'iloveyou1234', 'password!234',
}

def validate_password_policy(pw):
    if not pw or len(pw) < 12:
        return 'Password must be at least 12 characters.'
    if len(pw) > 256:
        return 'Password must be at most 256 characters.'
    if pw.lower() in _COMMON_PASSWORDS:
        return 'That password is too common. Choose something more unique.'
    return None

# ─── Connect ──────────────────────────────────────────────────────────────────
def connect():
    try:
        client = pymongo.MongoClient(
            host=os.environ.get('DB_HOST', '11.0.0.12'),
            port=int(os.environ.get('DB_PORT', 27018)),
            username=os.environ.get('DB_USER', 'tarsyer_admin'),
            password=os.environ.get('DB_PASS', ''),
            authSource='admin',
            directConnection=True,
            serverSelectionTimeoutMS=5000,
        )
        client.admin.command('ping')
        db = client[os.environ.get('DB_NAME', 'cultfitServer')]
        print(f"[OK] Connected to MongoDB at {os.environ.get('DB_HOST')}:{os.environ.get('DB_PORT')}")
        return db
    except Exception as exc:
        print(f"[ERROR] MongoDB connection failed: {exc}")
        sys.exit(1)

def main():
    db = connect()
    col = db['users']

    # ── Indexes ───────────────────────────────────────────────────────────────
    print("\n── Creating indexes ──")
    col.create_index('username', unique=True, name='uq_username')
    col.create_index(
        'email', unique=True, name='uq_email_partial',
        partialFilterExpression={'email': {'$exists': True, '$gt': ''}},
    )
    print("[OK] Indexes created")

    # ── Migrate existing user ────────────────────────────────────────────────
    print("\n── Migrating existing user ──")
    existing_username = 'cultfit@tarsyer.com'
    existing_hash = '$2b$12$05O2Is25xTkix2429U8s/OklA/is/xfqEBjuffFx5UjPqrgbcmr8q'

    if col.find_one({'username': existing_username}):
        print(f"[SKIP] User '{existing_username}' already exists in the users collection.")
    else:
        now = datetime.utcnow()
        col.insert_one({
            'username':              existing_username,
            'email':                 existing_username,
            'password_hash':         existing_hash,
            'role':                  'user',
            'is_active':             True,
            'force_password_change': False,
            'password_changed_at':   now,
            'password_expires_at':   now + timedelta(days=PASSWORD_EXPIRY_DAYS),
            'created_at':            now,
            'updated_at':            now,
        })
        print(f"[OK] Migrated '{existing_username}' as role=user")

    # ── Create admin ─────────────────────────────────────────────────────────
    print("\n── Admin account setup ──")
    existing_admin = col.find_one({'role': 'admin'})
    if existing_admin:
        print(f"[SKIP] An admin already exists: '{existing_admin['username']}'. Skipping.")
        return

    print("No admin user found. Let's create one.\n")
    admin_username = input("  Admin username: ").strip()
    if not admin_username:
        print("[ERROR] Username cannot be empty.")
        sys.exit(1)

    if col.find_one({'username': admin_username}):
        print(f"[ERROR] Username '{admin_username}' already exists.")
        sys.exit(1)

    admin_email = input("  Admin email (optional, press Enter to skip): ").strip() or None

    while True:
        pw = getpass.getpass("  Admin password (min 12 chars): ")
        err = validate_password_policy(pw)
        if err:
            print(f"  [!] {err}")
            continue
        pw2 = getpass.getpass("  Confirm password: ")
        if pw != pw2:
            print("  [!] Passwords do not match.")
            continue
        break

    now = datetime.utcnow()
    pw_hash = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    col.insert_one({
        'username':              admin_username,
        'email':                 admin_email,
        'password_hash':         pw_hash,
        'role':                  'admin',
        'is_active':             True,
        'force_password_change': False,
        'password_changed_at':   now,
        'password_expires_at':   now + timedelta(days=PASSWORD_EXPIRY_DAYS),
        'created_at':            now,
        'updated_at':            now,
    })
    print(f"\n[OK] Admin '{admin_username}' created successfully.")

if __name__ == '__main__':
    main()
