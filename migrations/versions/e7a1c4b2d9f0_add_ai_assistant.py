"""AI assistant: per-user daily allowance and saved report contexts."""
from alembic import op
import sqlalchemy as sa
revision = 'e7a1c4b2d9f0'
down_revision = 'd4e52098ab61'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if 'ai_assistant_remaining' not in {c['name'] for c in inspector.get_columns('user')}:
        with op.batch_alter_table('user') as batch:
            batch.add_column(sa.Column('ai_assistant_remaining', sa.Integer(), nullable=True))
    if not inspector.has_table('ai_context'):
        op.create_table('ai_context',
            sa.Column('id', sa.String(36), primary_key=True),
            sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
            sa.Column('tool', sa.String(32), nullable=False),
            sa.Column('evidence', sa.Text, nullable=False),
            sa.Column('explanations', sa.Text, nullable=False),
            sa.Column('chat', sa.Text, nullable=False),
            sa.Column('created_at', sa.DateTime, nullable=False))
        op.create_index('ix_ai_context_user_id', 'ai_context', ['user_id'])
        op.create_index('ix_ai_context_created_at', 'ai_context', ['created_at'])


def downgrade():
    op.drop_index('ix_ai_context_created_at', table_name='ai_context')
    op.drop_index('ix_ai_context_user_id', table_name='ai_context')
    op.drop_table('ai_context')
    with op.batch_alter_table('user') as batch:
        batch.drop_column('ai_assistant_remaining')
