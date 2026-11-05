"""MyScanner Business stage 5: team members and the monthly report marker."""
from alembic import op
import sqlalchemy as sa

revision = 'f2c6e9a4b7d1'
down_revision = 'e8b4d2f6a1c9'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    columns = {c['name'] for c in inspector.get_columns('business_workspace')}
    if 'last_report_month' not in columns:
        with op.batch_alter_table('business_workspace') as batch:
            batch.add_column(sa.Column('last_report_month', sa.String(7), nullable=True))
    if not inspector.has_table('business_member'):
        op.create_table('business_member',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('workspace_id', sa.Integer, sa.ForeignKey('business_workspace.id', ondelete='CASCADE'), nullable=False),
            sa.Column('email', sa.String(254), nullable=False),
            sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id', ondelete='CASCADE'), nullable=True),
            sa.Column('token', sa.String(64), nullable=False),
            sa.Column('alerts', sa.Boolean, nullable=False),
            sa.Column('created_at', sa.DateTime, nullable=False),
            sa.Column('accepted_at', sa.DateTime, nullable=True),
            sa.UniqueConstraint('workspace_id', 'email', name='uq_business_member_workspace_email'),
            sa.UniqueConstraint('token'))
        op.create_index('ix_business_member_workspace_id', 'business_member', ['workspace_id'])
        op.create_index('ix_business_member_user_id', 'business_member', ['user_id'])


def downgrade():
    op.drop_index('ix_business_member_user_id', table_name='business_member')
    op.drop_index('ix_business_member_workspace_id', table_name='business_member')
    op.drop_table('business_member')
    with op.batch_alter_table('business_workspace') as batch:
        batch.drop_column('last_report_month')
