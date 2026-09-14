FROM python:3.12-slim

WORKDIR /app

COPY range/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY range/service /app/service

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "service.server"]
