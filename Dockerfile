FROM python:3.11-slim

# Create a non-root user for security
RUN useradd -m appuser

# Create working/app dirs owned by appuser
WORKDIR /app
RUN mkdir -p /app/result_log && chown -R appuser /app/result_log

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Env var for logging directory
ENV LOG_DIR="/app/result_log"

# Switch user
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import requests; requests.get('http://localhost:8000/', timeout=1)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
