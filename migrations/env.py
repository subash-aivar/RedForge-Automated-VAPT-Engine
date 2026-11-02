import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from redforge_vapt.db import Base

config = context.config
if config.config_file_name:
    # No logging configuration is required for this minimal Alembic config.
    pass
config.set_main_option("sqlalchemy.url", os.environ.get("REDFORGE_DATABASE_URL", "sqlite:///./redforge.db"))
target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    engine = engine_from_config(config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
