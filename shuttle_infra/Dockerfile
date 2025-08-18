FROM python:3.12-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.7.19 /uv /uvx /bin/

WORKDIR /app

# Copy dependencies
COPY pyproject.toml pyproject.toml
COPY uv.lock uv.lock
# Needed for the tests, due to hatchling
RUN echo "# Dummy" > README.md
RUN uv sync --locked

# Copy application code
COPY . .

RUN useradd -m appuser
RUN chown -R appuser:appuser /app
USER appuser

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV SHUTTLE_RUNTIME=true

# Set the entrypoint
ENTRYPOINT ["uv", "run", "-m", "main"]
