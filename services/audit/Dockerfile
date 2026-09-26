# Build context: raíz del repo (ver docker-compose.yml), para poder copiar common/.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PORT=5005

WORKDIR /app
COPY services/audit/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY common /app/common
COPY services/audit /app/service
WORKDIR /app/service

EXPOSE 5005
# Un solo worker: la clave, la caché de consentimiento y los tokens de servicio viven en memoria
# del proceso; varios workers darían resultados distintos por request. Los hilos dan concurrencia.
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --timeout 60 app:app"]
