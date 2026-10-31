"""Bind AI contexts to server-side reports and enforce expiry metadata."""
from alembic import op
import sqlalchemy as sa
from datetime import timedelta

revision = 'f7c1e8a9b2d3'
down_revision = 'a9c4e2f7b1d3'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    columns = {c['name'] for c in inspector.get_columns('ai_context')}
    with op.batch_alter_table('ai_context') as batch:
        if 'source_kind' not in columns:
            batch.add_column(sa.Column('source_kind', sa.String(24), nullable=True))
        if 'source_report_id' not in columns:
            batch.add_column(sa.Column('source_report_id', sa.Integer(),
                                       sa.ForeignKey('scan.id', name='fk_ai_context_source_report_id_scan',
                                                      ondelete='CASCADE'), nullable=True))
        if 'evidence_hash' not in columns:
            batch.add_column(sa.Column('evidence_hash', sa.String(64), nullable=True))
        if 'expires_at' not in columns:
            batch.add_column(sa.Column('expires_at', sa.DateTime(), nullable=True))

    bind = op.get_bind()
    table = sa.table('ai_context', sa.column('id', sa.String()),
                     sa.column('created_at', sa.DateTime()),
                     sa.column('source_kind', sa.String(24)),
                     sa.column('expires_at', sa.DateTime()))
    rows = bind.execute(sa.select(table.c.id, table.c.created_at,
                                  table.c.source_kind, table.c.expires_at)).mappings()
    for row in rows:
        values = {}
        if row['source_kind'] is None:
            values['source_kind'] = 'client_unverified'
        if row['expires_at'] is None:
            values['expires_at'] = row['created_at'] + timedelta(days=30)
        if values:
            bind.execute(table.update().where(table.c.id == row['id']).values(**values))

    inspector = sa.inspect(bind)
    indexes = {idx['name'] for idx in inspector.get_indexes('ai_context')}
    with op.batch_alter_table('ai_context') as batch:
        if 'ix_ai_context_source_report_id' not in indexes:
            batch.create_index('ix_ai_context_source_report_id', ['source_report_id'])
        if 'ix_ai_context_expires_at' not in indexes:
            batch.create_index('ix_ai_context_expires_at', ['expires_at'])
        batch.alter_column('source_kind', existing_type=sa.String(24), nullable=False,
                           server_default='client_unverified')
        batch.alter_column('expires_at', existing_type=sa.DateTime(), nullable=False)


def downgrade():
    with op.batch_alter_table('ai_context') as batch:
        batch.drop_index('ix_ai_context_expires_at')
        batch.drop_index('ix_ai_context_source_report_id')
        batch.drop_column('expires_at')
        batch.drop_column('evidence_hash')
        batch.drop_column('source_report_id')
        batch.drop_column('source_kind')
