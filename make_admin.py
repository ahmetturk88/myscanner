"""Explicit host-side admin promotion; never runs during web app import."""
import argparse
from sqlalchemy import func
from extensions import db
from models import User
from services.permissions import DAILY_LIMITS


def promote_existing_user(email):
    """Caller must supply an application context and a verified existing email."""
    email = email.strip().lower()
    if not email:
        raise ValueError('An existing account email is required.')
    user = User.query.filter(func.lower(User.email) == email).one_or_none()
    if user is None:
        raise ValueError('Account not found; no permissions changed.')
    if not user.is_verified:
        raise ValueError('Verify the account email before granting administrator permissions.')
    if user.is_admin and user.role == 'admin':
        return user.id, False
    user.is_admin = True
    user.role = 'admin'
    user.remaining_scans = 999999
    for service, limit in DAILY_LIMITS['admin'].items():
        field = 'sandbox_remaining' if service == 'sandbox_analysis' else service + '_remaining'
        if hasattr(User, field):
            setattr(user, field, limit)
    db.session.commit()
    db.session.refresh(user)
    return user.id, True


def main(argv=None):
    parser = argparse.ArgumentParser(description='Grant admin permissions to one existing verified account.')
    parser.add_argument('--email', required=True, help='Email of the account to promote.')
    args = parser.parse_args(argv)
    # Parse before importing the application. A missing argument must never
    # mutate the database or grant permissions to a hardcoded username.
    from app import app
    with app.app_context():
        try:
            user_id, changed = promote_existing_user(args.email)
        except Exception:
            db.session.rollback()
            raise
        action = 'granted' if changed else 'already present'
        app.logger.info('Administrator permissions %s for user ID %s', action, user_id)
        print(f'Administrator permissions {action}. User ID: {user_id}; is_admin=True; role=admin.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
