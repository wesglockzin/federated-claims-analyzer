# Dockerfile for Federated Identity & Claims Analyzer

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# System libraries required by python3-saml (xmlsec1)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Install the dependencies from pyproject.toml. Editable, so the templates and
# HOWTO.md next to app.py are found where they are.
COPY . .
RUN pip install --no-cache-dir -e .

# Some platforms (for example OpenShift) run an arbitrary UID in group 0, so
# group permissions mirror the owner's.
RUN chown -R appuser:appuser /app && chgrp -R 0 /app && chmod -R g=u /app

USER appuser

EXPOSE 8080

# Fails when /health answers anything other than 200 (urlopen raises on 4xx/5xx).
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '8080'), timeout=5)"]

# Shell form of exec so $PORT is expanded; gunicorn stays PID 1.
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --timeout 120 app:app"]
