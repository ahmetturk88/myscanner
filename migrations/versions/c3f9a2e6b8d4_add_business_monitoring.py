"""MyScanner Business stage 2: monitoring snapshots, change events, and per-domain run times."""
from alembic import op
import sqlalchemy as sa

revision = 'c3f9a2e6b8d4'
down_revision = 'b7e2c4a9d1f6'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    columns = {c['name'] for c in inspector.get_columns('business_domain')}
    with op.batch_alter_table('business_domain') as batch:
        if 'monitored_at' not in columns:
            batch.add_column(sa.Column('monitored_at', sa.DateTime, nullable=True))
        if 'weekly_at' not in columns:
            batch.add_column(sa.Column('weekly_at', sa.DateTime, nullable=True))
        if 'proof_misses' not in columns:
            batch.add_column(sa.Column('proof_misses', sa.Integer, nullable=False, server_default='0'))
    if not inspector.has_table('business_snapshot'):
        op.create_table('business_snapshot',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('domain_id', sa.Integer, sa.ForeignKey('business_domain.id', ondelete='CASCADE'), nullable=False),
            sa.Column('kind', sa.String(10), nullable=False),
            sa.Column('created_at', sa.DateTime, nullable=False),
            sa.Column('score', sa.Integer, nullable=True),
            sa.Column('results', sa.Text, nullable=False))
        op.create_index('ix_business_snapshot_domain_id', 'business_snapshot', ['domain_id'])
        op.create_index('ix_business_snapshot_created_at', 'business_snapshot', ['created_at'])
    if not inspector.has_table('business_event'):
        op.create_table('business_event',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('domain_id', sa.Integer, sa.ForeignKey('business_domain.id', ondelete='CASCADE'), nullable=False),
            sa.Column('snapshot_id', sa.Integer, sa.ForeignKey('business_snapshot.id', ondelete='CASCADE'), nullable=True),
            sa.Column('created_at', sa.DateTime, nullable=False),
            sa.Column('code', sa.String(40), nullable=False),
            sa.Column('severity', sa.String(8), nullable=False),
            sa.Column('params', sa.Text, nullable=False),
            sa.Column('notified_at', sa.DateTime, nullable=True))
        op.create_index('ix_business_event_domain_id', 'business_event', ['domain_id'])
        op.create_index('ix_business_event_created_at', 'business_event', ['created_at'])


def downgrade():
    op.drop_index('ix_business_event_created_at', table_name='business_event')
    op.drop_index('ix_business_event_domain_id', table_name='business_event')
    op.drop_table('business_event')
    op.drop_index('ix_business_snapshot_created_at', table_name='business_snapshot')
    op.drop_index('ix_business_snapshot_domain_id', table_name='business_snapshot')
    op.drop_table('business_snapshot')
    with op.batch_alter_table('business_domain') as batch:
        batch.drop_column('proof_misses')
        batch.drop_column('weekly_at')
        batch.drop_column('monitored_at')
