# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    HOST=0.0.0.0

WORKDIR /app

# Install security updates & curl for healthcheck
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code & pre-trained model bundle
COPY app.py url_features.py xai_explainer.py ./
COPY model/ ./model/
COPY static/ ./static/
COPY templates/ ./templates/

# Create a non-privileged user for security compliance
RUN useradd -u 10001 -m appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://127.0.0.1:5000/api/health || exit 1

# Launch with Gunicorn production WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "2", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
