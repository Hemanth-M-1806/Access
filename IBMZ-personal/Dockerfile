# syntax=docker/dockerfile:1

ARG BASE_IMAGE=python:3.11-slim-bookworm

# =============================================================================
# Stage 1: Build & Dependency Installation Stage
# Multi-arch compatible (x86_64, aarch64, s390x)
# =============================================================================
FROM ${BASE_IMAGE} AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

# Install compilation toolchain & headers genuinely required for native builds
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       build-essential \
       python3-dev \
       pkg-config \
       libssl-dev \
       gfortran \
       libopenblas-dev \
       liblapack-dev \
    && rm -rf /var/lib/apt/lists/*

# Create isolated virtual environment for production dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade packaging tools
RUN pip install --upgrade pip setuptools wheel

# Install dependencies into virtual environment
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install \
       --prefer-binary \
       -r /tmp/requirements.txt

# =============================================================================
# Stage 2: Minimal Hardened Production Runtime Stage
# =============================================================================
FROM ${BASE_IMAGE} AS runner

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Install runtime shared libraries required by extensions
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       curl \
       libopenblas0 \
       liblapack3 \
       libgfortran5 \
       libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-compiled virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create unprivileged application user
RUN groupadd --system --gid 10001 appgroup \
    && useradd --system \
       --uid 10001 \
       --gid appgroup \
       --home-dir /app \
       --no-create-home \
       --shell /usr/sbin/nologin \
       appuser

# Copy application source code
COPY --chown=appuser:appgroup backend/ /app/backend/
COPY --chown=appuser:appgroup frontend/ /app/frontend/

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s \
            --timeout=5s \
            --start-period=30s \
            --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/v1/system/health || exit 1

CMD ["python", "-m", "uvicorn", "backend.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--proxy-headers", \
     "--forwarded-allow-ips=*"]