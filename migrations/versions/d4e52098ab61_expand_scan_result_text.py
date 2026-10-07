"""Expand scan result storage without dropping existing reports."""
from alembic import op
import sqlalchemy as sa
revision = 'd4e52098ab61'
down_revision = 'c291ed857a40'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table('scan'):
        raise RuntimeError('scan table is missing; establish the application schema before this migration')
    column = next(c for c in inspector.get_columns('scan') if c['name'] == 'result')
    if isinstance(column['type'], sa.Text):
        return
    with op.batch_alter_table('scan') as batch:
        batch.alter_column('result', existing_type=column['type'], type_=sa.Text(), existing_nullable=column['nullable'])


def downgrade():
    # Widening is intentionally retained: shrinking to VARCHAR(1000) would
    # reject or truncate large reports created after upgrade.
    pass
