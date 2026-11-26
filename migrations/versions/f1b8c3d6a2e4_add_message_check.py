"""Message check: per-user daily allowance."""
from alembic import op
import sqlalchemy as sa

revision = 'f1b8c3d6a2e4'
down_revision = 'e9b2d7c4a1f3'
branch_labels = None
depends_on = None


def upgrade():
    if 'message_check_remaining' not in {c['name'] for c in sa.inspect(op.get_bind()).get_columns('user')}:
        with op.batch_alter_table('user') as batch:
            batch.add_column(sa.Column('message_check_remaining', sa.Integer(), nullable=True))


def downgrade():
    with op.batch_alter_table('user') as batch:
        batch.drop_column('message_check_remaining')
