"""Exact-origin, account-bound target DNS proofs."""
from alembic import op
import sqlalchemy as sa
revision = 'c291ed857a40'
down_revision = 'a6b738de2104'
branch_labels = None
depends_on = None

def upgrade():
    if not sa.inspect(op.get_bind()).has_table('verified_target'):
        op.create_table('verified_target',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
            sa.Column('origin', sa.String(300), nullable=False),
            sa.Column('hostname', sa.String(253), nullable=False),
            sa.Column('token', sa.String(64), nullable=False),
            sa.Column('challenge_expires_at', sa.Float, nullable=False),
            sa.Column('verified_until', sa.Float, nullable=True),
            sa.Column('revoked', sa.Boolean, nullable=False),
            sa.UniqueConstraint('user_id', 'origin', name='uq_verified_target_owner_origin'))
        op.create_index('ix_verified_target_user_id', 'verified_target', ['user_id'])

def downgrade():
    op.drop_index('ix_verified_target_user_id', table_name='verified_target')
    op.drop_table('verified_target')
