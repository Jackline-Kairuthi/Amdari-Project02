# CK-01 — Vulnerable base image. python:3.9-slim carries outdated system libraries
FROM python:3.12-slim

WORKDIR /app

# Install dependencies as root
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user (Debian syntax)
RUN addgroup --system app && adduser --system --ingroup app app

# Switch to non-root user
USER app

# Copy application code AFTER switching user
COPY . .

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:5001/health || exit 1
  
EXPOSE 5002

CMD ["python", "app.py"]

