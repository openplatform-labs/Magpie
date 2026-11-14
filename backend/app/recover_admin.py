"""Offline administrator recovery; stop all gateways before running this module."""
import argparse
import getpass
import sys

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .database import engine
from .models import AdminSession, AdminUser, BootstrapLock
from .observability import audit
from .security import password_hash


def recover(db: Session, username: str, password: str) -> int:
    if not 12 <= len(password) <= 256:
        raise ValueError('Password must be between 12 and 256 characters')
    hashed = password_hash(password)
    try:
        # The bootstrap lock also serializes administrator activation changes.
        db.execute(select(BootstrapLock).where(BootstrapLock.id == 1).with_for_update()).first()
        user = db.scalar(select(AdminUser).where(AdminUser.username == username).with_for_update())
        if user is None:
            raise ValueError('Administrator not found')
        user.password_hash = hashed
        user.active = True
        db.execute(update(AdminSession).where(AdminSession.user_id == user.id).values(revoked=True))
        audit(db, 'admin.recover', 'admin_user', user.id, actor='operator')
        db.commit()
        return user.id
    except Exception:
        db.rollback()
        raise


def main():
    parser = argparse.ArgumentParser(description='Recover an existing administrator while gateways are stopped')
    parser.add_argument('username', help='Existing administrator username')
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.error('An interactive terminal is required for password input')
    password = getpass.getpass('New administrator password: ')
    if password != getpass.getpass('Confirm password: '):
        parser.error('Passwords do not match')
    try:
        with Session(engine()) as db:
            user_id = recover(db, args.username, password)
    except ValueError as exc:
        parser.error(str(exc))
    print(f'Administrator {user_id} recovered; existing sessions were revoked.')


if __name__ == '__main__':
    main()
