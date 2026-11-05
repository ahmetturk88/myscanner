"""MyScanner Business: uptime state on business_domain and daily uptime counts."""
from alembic import op
import sqlalchemy as sa

revision = 'c7e1f4a8b2d6'
down_revision = 'a4d9c3e7f1b5'
branch_labels = None
depends_on = None

COLUMNS = (('up_state', sa.String(5), None), ('up_checked_at', sa.DateTime(), None),
           ('up_fails', sa.Integer(), '0'), ('down_since', sa.DateTime(), None), ('up_ms', sa.Integer(), None))


def upgrade():
    inspector = sa.inspect(op.get_bind())
    existing = {c['name'] for c in inspector.get_columns('business_domain')}
    with op.batch_alter_table('business_domain') as batch:
        for name, kind, default in COLUMNS:
            if name not in existing:
                batch.add_column(sa.Column(name, kind, nullable=default is None, server_default=default))
    if not inspector.has_table('business_uptime_day'):
        op.create_table('business_uptime_day',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('domain_id', sa.Integer, sa.ForeignKey('business_domain.id', ondelete='CASCADE'), nullable=False),
            sa.Column('day', sa.Date, nullable=False),
            sa.Column('checks', sa.Integer, nullable=False, server_default='0'),
            sa.Column('ups', sa.Integer, nullable=False, server_default='0'),
            sa.Column('total_ms', sa.Integer, nullable=False, server_default='0'),
            sa.UniqueConstraint('domain_id', 'day', name='uq_business_uptime_day'))
        op.create_index('ix_business_uptime_day_domain_id', 'business_uptime_day', ['domain_id'])


def downgrade():
    op.drop_index('ix_business_uptime_day_domain_id', table_name='business_uptime_day')
    op.drop_table('business_uptime_day')
    with op.batch_alter_table('business_domain') as batch:
        for name, _, _ in reversed(COLUMNS):
            batch.drop_column(name)
