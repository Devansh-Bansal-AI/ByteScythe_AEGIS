FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (important for ML)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend
COPY backend/ ./backend/

# Create data dir
RUN mkdir -p data

# Expose port (optional but fine)
EXPOSE 10000

# Use Render dynamic port + production server
CMD ["sh", "-c", "python -m backend.db.seed_db && gunicorn -k uvicorn.workers.UvicornWorker backend.main:app --bind 0.0.0.0:$PORT"]
