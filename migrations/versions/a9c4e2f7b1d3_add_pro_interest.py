"""Pro waitlist: page visits by source and launch-notice sign-ups."""
from alembic import op
import sqlalchemy as sa
revision = 'a9c4e2f7b1d3'
down_revision = 'f3b8d1a6c2e4'
branch_labels = None
depends_on = None


def upgrade():
    if not sa.inspect(op.get_bind()).has_table('pro_interest'):
        op.create_table('pro_interest',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('created_at', sa.DateTime, nullable=False),
            sa.Column('kind', sa.String(10), nullable=False),
            sa.Column('source', sa.String(40), nullable=False),
            sa.Column('lang', sa.String(2), nullable=False),
            sa.Column('email', sa.String(254), nullable=True),
            sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id', ondelete='SET NULL'), nullable=True))
        op.create_index('ix_pro_interest_created_at', 'pro_interest', ['created_at'])
        op.create_index('ix_pro_interest_email', 'pro_interest', ['email'])


def downgrade():
    op.drop_index('ix_pro_interest_email', table_name='pro_interest')
    op.drop_index('ix_pro_interest_created_at', table_name='pro_interest')
    op.drop_table('pro_interest')
