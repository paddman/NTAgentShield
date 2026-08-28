FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NTSHIELD_ENVIRONMENT=production

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY rules ./rules
RUN pip install --upgrade pip && pip install .

RUN useradd --system --uid 10001 --create-home ntshield \
    && mkdir -p /app/data \
    && chown -R ntshield:ntshield /app
USER ntshield

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/live', timeout=3)"

CMD ["uvicorn", "ntshield.production_app:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers"]
