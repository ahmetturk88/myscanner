"""MyScanner Business stage 3: alert settings on the workspace."""
from alembic import op
import sqlalchemy as sa

revision = 'd5a1c7e3f9b2'
down_revision = 'c3f9a2e6b8d4'
branch_labels = None
depends_on = None


def upgrade():
    columns = {c['name'] for c in sa.inspect(op.get_bind()).get_columns('business_workspace')}
    with op.batch_alter_table('business_workspace') as batch:
        if 'alert_lang' not in columns:
            batch.add_column(sa.Column('alert_lang', sa.String(2), nullable=False, server_default='tr'))
        if 'instant_alerts' not in columns:
            batch.add_column(sa.Column('instant_alerts', sa.Boolean, nullable=False, server_default=sa.true()))
        if 'daily_digest' not in columns:
            batch.add_column(sa.Column('daily_digest', sa.Boolean, nullable=False, server_default=sa.true()))
        if 'last_digest_at' not in columns:
            batch.add_column(sa.Column('last_digest_at', sa.DateTime, nullable=True))


def downgrade():
    with op.batch_alter_table('business_workspace') as batch:
        batch.drop_column('last_digest_at')
        batch.drop_column('daily_digest')
        batch.drop_column('instant_alerts')
        batch.drop_column('alert_lang')
