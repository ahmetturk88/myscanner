"""Shared authentication rate-limit counters."""
from alembic import op
import sqlalchemy as sa
revision = 'a6b738de2104'
down_revision = '7c4e29a1b603'
branch_labels = None
depends_on = None


def upgrade():
    if not sa.inspect(op.get_bind()).has_table('auth_rate_limit'):
        op.create_table('auth_rate_limit',
                        sa.Column('key', sa.String(64), primary_key=True),
                        sa.Column('hits', sa.Integer(), nullable=False),
                        sa.Column('expires_at', sa.Float(), nullable=False))
        op.create_index('ix_auth_rate_limit_expires_at', 'auth_rate_limit', ['expires_at'])


def downgrade():
    op.drop_index('ix_auth_rate_limit_expires_at', table_name='auth_rate_limit')
    op.drop_table('auth_rate_limit')
