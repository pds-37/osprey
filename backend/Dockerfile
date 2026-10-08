FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install the shared Osprey core consumed by the API and CLI.
COPY osprey/ /app/osprey/

# Copy backend code
COPY backend/ /app/backend/

ENV PYTHONPATH=/app/backend:/app/osprey/src

EXPOSE 8000

CMD ["uvicorn", "guardianos.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
