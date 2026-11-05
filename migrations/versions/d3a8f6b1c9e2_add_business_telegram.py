"""MyScanner Business: Telegram chats for instant alerts, and a small settings table."""
from alembic import op
import sqlalchemy as sa

revision = 'd3a8f6b1c9e2'
down_revision = 'c7e1f4a8b2d6'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table('business_chat'):
        op.create_table('business_chat',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id', ondelete='CASCADE'), nullable=False),
            sa.Column('chat_id', sa.BigInteger, nullable=True),
            sa.Column('code', sa.String(40), nullable=True),
            sa.Column('code_expires', sa.DateTime, nullable=True),
            sa.Column('linked_at', sa.DateTime, nullable=True),
            sa.UniqueConstraint('user_id'), sa.UniqueConstraint('code'))
        op.create_index('ix_business_chat_chat_id', 'business_chat', ['chat_id'])
    if not inspector.has_table('business_setting'):
        op.create_table('business_setting',
            sa.Column('key', sa.String(40), primary_key=True),
            sa.Column('value', sa.String(255), nullable=False))


def downgrade():
    op.drop_table('business_setting')
    op.drop_index('ix_business_chat_chat_id', table_name='business_chat')
    op.drop_table('business_chat')
