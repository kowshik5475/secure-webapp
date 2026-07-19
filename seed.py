"""
seed.py — Create initial database and seed demo accounts.

Run once after cloning:
    python seed.py

Creates:
    admin@example.com  / Admin1234!  (role: admin)
    user@example.com   / User1234!   (role: user)

Never use these credentials in production. Change them or delete this file.
"""
import sys
import os

# Make sure we can import the app package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.models import create_user, get_user_by_email, write_audit_log
from config import DevelopmentConfig

app = create_app(DevelopmentConfig)

SEED_USERS = [
    {
        "email": "admin@example.com",
        "password": "Admin1234!",
        "role": "admin",
    },
    {
        "email": "user@example.com",
        "password": "User1234!",
        "role": "user",
    },
]

with app.app_context():
    print("🌱 Seeding database...")
    for u in SEED_USERS:
        if get_user_by_email(u["email"]):
            print(f"   ⏭  {u['email']} already exists — skipped")
            continue
        create_user(
            email=u["email"],
            password=u["password"],
            role=u["role"],
            rounds=app.config["BCRYPT_ROUNDS"],
        )
        user = get_user_by_email(u["email"])
        write_audit_log(
            event_type="register",
            user_id=user["id"],
            ip_address="seed-script",
            details=f"Seeded {u['role']} account: {u['email']}",
        )
        print(f"   ✅  Created {u['role']}: {u['email']}")

    print("\n✅ Seed complete!")
    print()
    print("Demo credentials:")
    print("  Admin: admin@example.com / Admin1234!")
    print("  User:  user@example.com  / User1234!")
    print()
    print("⚠️  Change these passwords before deploying to production.")
