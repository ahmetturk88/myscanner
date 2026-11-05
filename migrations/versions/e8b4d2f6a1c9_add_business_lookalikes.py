"""MyScanner Business stage 4: look-alike domains and the watch cursor."""
from alembic import op
import sqlalchemy as sa

revision = 'e8b4d2f6a1c9'
down_revision = 'd5a1c7e3f9b2'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    columns = {c['name'] for c in inspector.get_columns('business_domain')}
    with op.batch_alter_table('business_domain') as batch:
        if 'lookalike_at' not in columns:
            batch.add_column(sa.Column('lookalike_at', sa.DateTime, nullable=True))
        if 'lookalike_cursor' not in columns:
            batch.add_column(sa.Column('lookalike_cursor', sa.Integer, nullable=False, server_default='0'))
    if not inspector.has_table('business_lookalike'):
        op.create_table('business_lookalike',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('domain_id', sa.Integer, sa.ForeignKey('business_domain.id', ondelete='CASCADE'), nullable=False),
            sa.Column('name', sa.String(253), nullable=False),
            sa.Column('source', sa.String(8), nullable=False),
            sa.Column('first_seen', sa.DateTime, nullable=False),
            sa.Column('last_seen', sa.DateTime, nullable=False),
            sa.Column('resolves', sa.Boolean, nullable=False),
            sa.Column('live', sa.Boolean, nullable=False),
            sa.Column('risk', sa.String(8), nullable=False),
            sa.Column('title', sa.String(200), nullable=True),
            sa.Column('status', sa.String(10), nullable=False),
            sa.UniqueConstraint('domain_id', 'name', name='uq_business_lookalike_domain_name'))
        op.create_index('ix_business_lookalike_domain_id', 'business_lookalike', ['domain_id'])


def downgrade():
    op.drop_index('ix_business_lookalike_domain_id', table_name='business_lookalike')
    op.drop_table('business_lookalike')
    with op.batch_alter_table('business_domain') as batch:
        batch.drop_column('lookalike_cursor')
        batch.drop_column('lookalike_at')
