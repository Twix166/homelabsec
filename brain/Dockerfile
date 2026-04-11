FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py init.sql migrate.py ./
COPY brainlib ./brainlib
COPY collectors ./collectors
COPY migrations ./migrations

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8088"]
