"""MyScanner Business: takedown facts (abuse contacts, host) and the report date on look-alike names."""
from alembic import op
import sqlalchemy as sa

revision = 'e9b2d7c4a1f3'
down_revision = 'd3a8f6b1c9e2'
branch_labels = None
depends_on = None

COLUMNS = (('host_ip', sa.String(45)), ('host_org', sa.String(120)), ('abuse_registrar', sa.String(254)),
           ('abuse_host', sa.String(254)), ('abuse_at', sa.DateTime()), ('reported_at', sa.DateTime()))


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
