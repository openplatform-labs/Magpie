"""Offline provider secret rotation. Stop all gateways before running this module."""
import os
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .database import engine
from .models import OIDCTransaction, ProviderConnection
from .observability import audit


def rotate(db: Session, old_key: str, new_key: str) -> int:
    if old_key == new_key:
        raise ValueError('New encryption key must differ from the old key')
    old, new = Fernet(old_key.encode()), Fernet(new_key.encode())
    rows = db.scalars(select(ProviderConnection).where(ProviderConnection.encrypted_api_key.is_not(None)).with_for_update()).all()
    pending = db.scalars(select(OIDCTransaction).where(OIDCTransaction.used.is_(False), OIDCTransaction.expires_at > func.now()).with_for_update()).all()
    try:
        # Decrypt all before modifying rows so invalid old keys leave every secret intact.
        plaintexts = [old.decrypt(row.encrypted_api_key.encode()) for row in rows]
        verifiers = [old.decrypt(row.encrypted_verifier.encode()) for row in pending]
    except InvalidToken:
        db.rollback()
        raise ValueError('A provider secret or pending SSO verifier could not be decrypted; no changes made') from None
    for row, plaintext in zip(rows, plaintexts, strict=True):
        row.encrypted_api_key = new.encrypt(plaintext).decode()
    for row, verifier in zip(pending, verifiers, strict=True):
        row.encrypted_verifier = new.encrypt(verifier).decode()
    audit(db, 'encryption_key.rotate', 'providers', 'all', actor='operator')
    db.commit()
    return len(rows)


def main():
    old_key = os.environ['MAGPIE_OLD_ENCRYPTION_KEY']
    new_key = os.environ['MAGPIE_NEW_ENCRYPTION_KEY']
    with Session(engine()) as db:
        count = rotate(db, old_key, new_key)
    print(f'Rotated {count} provider secrets and pending SSO verifiers. Update the deployment key before restarting.')


if __name__ == '__main__':
    main()
