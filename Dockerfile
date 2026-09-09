FROM python:3.11-slim

WORKDIR /app

# Install system utilities needed for process / network telemetry
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose CryptoVeil port
EXPOSE 8765

ENV PYTHONUNBUFFERED=1
ENV CRYPTOVEIL_HOST=0.0.0.0
ENV CRYPTOVEIL_PORT=8765

CMD ["python", "run.py", "--server"]
