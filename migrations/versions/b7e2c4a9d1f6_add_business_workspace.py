"""MyScanner Business: workspaces, monitored domains with DNS proof, and pre-registrations."""
from alembic import op
import sqlalchemy as sa

revision = 'b7e2c4a9d1f6'
down_revision = 'f7c1e8a9b2d3'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table('business_workspace'):
        op.create_table('business_workspace',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('owner_id', sa.Integer, sa.ForeignKey('user.id', ondelete='CASCADE'), nullable=False),
            sa.Column('name', sa.String(80), nullable=False),
            sa.Column('status', sa.String(12), nullable=False),
            sa.Column('created_at', sa.DateTime, nullable=False))
        op.create_index('ix_business_workspace_owner_id', 'business_workspace', ['owner_id'], unique=True)
    if not inspector.has_table('business_domain'):
        op.create_table('business_domain',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('workspace_id', sa.Integer, sa.ForeignKey('business_workspace.id', ondelete='CASCADE'), nullable=False),
            sa.Column('domain', sa.String(253), nullable=False),
            sa.Column('token', sa.String(64), nullable=False),
            sa.Column('created_at', sa.DateTime, nullable=False),
            sa.Column('verified_at', sa.DateTime, nullable=True),
            sa.Column('last_checked_at', sa.DateTime, nullable=True),
            sa.UniqueConstraint('workspace_id', 'domain', name='uq_business_domain_workspace_domain'))
        op.create_index('ix_business_domain_workspace_id', 'business_domain', ['workspace_id'])
    if not inspector.has_table('business_lead'):
        op.create_table('business_lead',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('created_at', sa.DateTime, nullable=False),
            sa.Column('email', sa.String(254), nullable=False),
            sa.Column('website', sa.String(253), nullable=True),
            sa.Column('sector', sa.String(20), nullable=False),
            sa.Column('lang', sa.String(2), nullable=False),
            sa.Column('source', sa.String(40), nullable=False),
            sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id', ondelete='SET NULL'), nullable=True),
            sa.UniqueConstraint('email'))
        op.create_index('ix_business_lead_created_at', 'business_lead', ['created_at'])


def downgrade():
    op.drop_index('ix_business_lead_created_at', table_name='business_lead')
    op.drop_table('business_lead')
    op.drop_index('ix_business_domain_workspace_id', table_name='business_domain')
    op.drop_table('business_domain')
    op.drop_index('ix_business_workspace_owner_id', table_name='business_workspace')
    op.drop_table('business_workspace')
