FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py init.sql migrate.py ./
COPY migrations ./migrations

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8088"]
