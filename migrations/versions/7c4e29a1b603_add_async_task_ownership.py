"""Add durable ownership records for asynchronous scans.

Revision ID: 7c4e29a1b603
Revises: 5594693f7fdb
"""

from alembic import op
import sqlalchemy as sa

revision = '7c4e29a1b603'
down_revision = '5594693f7fdb'
branch_labels = None
depends_on = None


def upgrade():
    # app.py currently creates registered tables at startup. Do not recreate
    # this table if that legacy initialization has already run.
    if not sa.inspect(op.get_bind()).has_table('async_scan_task'):
        op.create_table(
            'async_scan_task',
            sa.Column('task_id', sa.String(36), primary_key=True),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id', ondelete='CASCADE'), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
        )
        op.create_index('ix_async_scan_task_user_id', 'async_scan_task', ['user_id'])


def downgrade():
    op.drop_index('ix_async_scan_task_user_id', table_name='async_scan_task')
    op.drop_table('async_scan_task')
