"""Mobile app: hashed sign-in tokens."""
from alembic import op
import sqlalchemy as sa
revision = 'f3b8d1a6c2e4'
down_revision = 'e7a1c4b2d9f0'
branch_labels = None
depends_on = None


def upgrade():
    if not sa.inspect(op.get_bind()).has_table('api_token'):
        op.create_table('api_token',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
            sa.Column('token_hash', sa.String(64), nullable=False),
            sa.Column('device', sa.String(80), nullable=False),
            sa.Column('created_at', sa.DateTime, nullable=False),
            sa.Column('last_used_at', sa.DateTime, nullable=False),
            sa.Column('expires_at', sa.DateTime, nullable=False),
            sa.UniqueConstraint('token_hash', name='uq_api_token_token_hash'))
        op.create_index('ix_api_token_user_id', 'api_token', ['user_id'])
        op.create_index('ix_api_token_expires_at', 'api_token', ['expires_at'])


def downgrade():
    op.drop_index('ix_api_token_expires_at', table_name='api_token')
    op.drop_index('ix_api_token_user_id', table_name='api_token')
    op.drop_table('api_token')
