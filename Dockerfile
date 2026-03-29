FROM python:3.11-slim

WORKDIR /app

# requirements.txt lives inside backend/ in your repo
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend as a package (imports use 'from backend.xxx')
COPY backend/ ./backend/

# Copy data files
COPY data/ ./data/

EXPOSE 10000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "10000"]
