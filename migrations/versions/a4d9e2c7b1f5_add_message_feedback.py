"""Message check: "this result is wrong" answers (verdict, answer and sign keys only)."""
from alembic import op
import sqlalchemy as sa

revision = 'a4d9e2c7b1f5'
down_revision = 'f1b8c3d6a2e4'
branch_labels = None
depends_on = None


def upgrade():
    if 'message_feedback' in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        'message_feedback',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('tone', sa.String(10), nullable=False),
        sa.Column('answer', sa.String(10), nullable=False),
        sa.Column('signals', sa.String(200), nullable=False, server_default=''),
    )
    op.create_index('ix_message_feedback_created_at', 'message_feedback', ['created_at'])


def downgrade():
    op.drop_index('ix_message_feedback_created_at', table_name='message_feedback')
    op.drop_table('message_feedback')
