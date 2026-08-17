import sys

from sqlalchemy import inspect

from app.database import get_db_context, engine
from app.models import User, Case, Evidence, AuditLog
from app.services.audit import verify_audit_chain
from app.config import settings
from app.storage import storage


def cmd_check() -> int:
    db_url = settings.DATABASE_URL
    engine_name = "postgresql" if db_url.startswith("postgres") else "sqlite"
    storage_name = "s3" if settings.STORAGE_BACKEND == "s3" else "local-disk"

    print("=" * 52)
    print("Evidentia environment check")
    print("=" * 52)
    print(f"  Database engine : {engine_name:<14} ({db_url.split('@')[-1]})")
    print(f"  Storage backend : {storage_name:<14} ({type(storage).__name__})")
    print(f"  Demo mode       : {'ON' if settings.DEMO_MODE else 'OFF'}")
    print(f"  Debug           : {settings.DEBUG}")
    print(f"  Cookie secure   : {settings.SESSION_COOKIE_SECURE}")

    with get_db_context() as db:
        inspector = inspect(engine)
        tables = sorted(inspector.get_table_names())
        counts = {
            "users": db.query(User).count(),
            "cases": db.query(Case).count(),
            "evidence": db.query(Evidence).count(),
            "audit_logs": db.query(AuditLog).count(),
        }
    chain = verify_audit_chain()
    print(f"  Tables          : {', '.join(tables)}")
    print(f"  Rows            : users={counts['users']} cases={counts['cases']} "
          f"evidence={counts['evidence']} audit={counts['audit_logs']}")
    print(f"  Audit chain     : {'VALID' if chain['valid'] else 'TAMPERED'} "
          f"({chain['total_records']} records)")
    return 0


def cmd_seed() -> int:
    if not settings.DEMO_MODE:
        print("error: seeding requires DEMO_MODE=true")
        return 1
    from app.services.demo import reset_demo_data

    actor = None
    with get_db_context() as db:
        actor = db.query(User).order_by(User.id.asc()).first()
    actor_id = actor.id if actor else 1

    result = reset_demo_data(actor_id)
    print(f"demo data rebuilt: user={result['username']} (password: DemoPass123!) "
          f"case={result['case_id']} evidence={result['evidence_id']}")
    print(f"evidence sha256 = {result['sha256_hash']}")
    return 0


def cmd_make_admin() -> int:
    args = sys.argv[2:]
    if not args:
        print("usage: python -m app.cli make-admin <username>")
        return 1
    username = args[0]
    from app.models import UserRole

    with get_db_context() as db:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            print(f"error: user '{username}' not found")
            return 1
        user.role = UserRole.ADMIN
        db.commit()
        print(f"{username} is now an admin")
    from app.services.audit import record_audit
    record_audit(user.id, "USER_ROLE_CHANGED", "User", user.id, {"role": "admin", "via": "cli"})
    return 0


def cmd_verify() -> int:
    chain = verify_audit_chain()
    print(f"chain valid: {chain['valid']} | records: {chain['total_records']}")
    if not chain["valid"]:
        print(f"{chain['message']}")
        return 1
    return 0


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    command = args[0]
    if command == "check":
        return cmd_check()
    if command == "seed":
        return cmd_seed()
    if command == "make-admin":
        return cmd_make_admin()
    if command == "verify":
        return cmd_verify()
    print(f"unknown command: {command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())