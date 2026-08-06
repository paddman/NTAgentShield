FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY rules ./rules
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 ntshield \
    && mkdir -p /app/data \
    && chown -R ntshield:ntshield /app
USER ntshield

EXPOSE 8080
CMD ["uvicorn", "ntshield.api:app", "--host", "0.0.0.0", "--port", "8080"]
