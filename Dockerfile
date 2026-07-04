FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py access.py config.py log.py ./

RUN useradd --system --uid 1001 --home /app appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 4010

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request; \
    urllib.request.urlopen(os.environ.get('LITELLM_URL','http://localhost:4000').rstrip('/')+'/health/liveliness', timeout=3).read()" \
    || exit 1

CMD ["python", "main.py"]
