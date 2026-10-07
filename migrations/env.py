"""One migration chain for Flask CLI and the explicit deployment runner."""
from alembic import context
from flask import current_app

config = context.config
connection = config.attributes.get('connection')
metadata = config.attributes.get('target_metadata')
if connection is None:
    database = current_app.extensions['migrate'].db
    metadata = database.metadata
    engine = database.engine

def migrate(bound_connection):
    context.configure(connection=bound_connection, target_metadata=metadata,
                      compare_type=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()

if context.is_offline_mode():
    raise RuntimeError('Offline adoption is unsupported; validate a restored database first.')
elif connection is not None:
    migrate(connection)
else:
    with engine.connect() as bound_connection:
        migrate(bound_connection)
