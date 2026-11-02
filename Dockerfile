FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
RUN pip install --no-cache-dir .
RUN useradd -r -u 10001 redforge && mkdir -p /data && chown redforge:redforge /data
USER redforge
WORKDIR /data
EXPOSE 8000
CMD ["sh", "-c", "alembic -c /app/alembic.ini upgrade head && redforge-vapt serve --host 0.0.0.0"]
