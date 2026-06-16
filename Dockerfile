# Stage 1: build deps
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps for psycopg (v3) source fallback; the [binary] extra usually
# ships prebuilt wheels and skips these
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . ./

# Install with all optional extras
RUN pip install --no-cache-dir --prefix=/install \
    ".[api,redis,postgres]"

# Stage 2: runtime
FROM python:3.11-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY pramagent/ pramagent/
COPY pyproject.toml .

# Non-root user for security
RUN useradd -r -u 1001 -g root pramagent \
    && chown -R 1001:0 /app
USER 1001

# Default: run the FastAPI sidecar
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PRAMAGENT_HOST=0.0.0.0 \
    PRAMAGENT_PORT=8080 \
    PRAMAGENT_LOG_LEVEL=info

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-${PRAMAGENT_PORT}}/health || exit 1

# --timeout-graceful-shutdown drains in-flight requests on SIGTERM before
# the lifespan shutdown closes the stores (P2-15)
CMD ["sh", "-c", "python -m uvicorn pramagent.api.app:app --host ${PRAMAGENT_HOST} --port ${PORT:-${PRAMAGENT_PORT}} --log-level ${PRAMAGENT_LOG_LEVEL} --timeout-graceful-shutdown 30"]
