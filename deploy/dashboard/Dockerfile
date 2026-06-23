FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
# Pinned with upper caps so a future breaking major can never resolve
# silently; psycopg (v3) replaces psycopg2-binary, whose maintainers do not
# recommend it for production (P1-10/T2-9).
RUN pip install --no-cache-dir \
    "fastapi>=0.110,<1.0" \
    "uvicorn[standard]>=0.29,<0.35" \
    "httpx>=0.27,<0.29" \
    "jinja2>=3.1,<4" \
    "redis>=5.0,<6" \
    "python-multipart>=0.0.18,<0.1" \
    "bcrypt>=4.1,<5" \
    "psycopg[binary]>=3.1,<4"
COPY pramagent/ pramagent/
COPY deploy/dashboard/app.py .
COPY deploy/dashboard/templates/ templates/
COPY deploy/dashboard/static/ static/
# Non-root user for security
RUN useradd -r -u 1001 -g root dashboard \
    && chown -R 1001:0 /app
USER 1001
ENV DASHBOARD_PORT=8501
EXPOSE 8501
HEALTHCHECK --interval=15s --timeout=5s CMD curl -f http://localhost:${DASHBOARD_PORT}/health || exit 1
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${DASHBOARD_PORT}"]
