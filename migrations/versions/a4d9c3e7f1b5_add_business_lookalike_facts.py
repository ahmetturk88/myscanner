"""MyScanner Business: ownership hints and registration facts for look-alike names."""
from alembic import op
import sqlalchemy as sa

revision = 'a4d9c3e7f1b5'
down_revision = 'f2c6e9a4b7d1'
branch_labels = None
depends_on = None

COLUMNS = (('hint', sa.String(8)), ('hint_value', sa.String(255)), ('registered', sa.Date()),
           ('registrar', sa.String(120)), ('facts_at', sa.DateTime()))


def upgrade():
    existing = {c['name'] for c in sa.inspect(op.get_bind()).get_columns('business_lookalike')}
    with op.batch_alter_table('business_lookalike') as batch:
        for name, kind in COLUMNS:
            if name not in existing:
                batch.add_column(sa.Column(name, kind, nullable=True))


def downgrade():
    with op.batch_alter_table('business_lookalike') as batch:
        for name, _ in reversed(COLUMNS):
            batch.drop_column(name)
