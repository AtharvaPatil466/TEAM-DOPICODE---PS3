FROM python:3.12-slim

# nmap: required by backend.scanner.nmap_scanner (python-nmap wraps the binary).
# tini: proper PID 1 signal handling for uvicorn.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY shared ./shared

# Non-root. nmap -sT -sV works unprivileged; -O is skipped at runtime by the scanner.
RUN useradd --system --uid 1001 --home /app shadowtrace \
 && mkdir -p /app/data \
 && chown -R shadowtrace:shadowtrace /app
USER shadowtrace

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATABASE_URL=sqlite:////app/data/shadowtrace.db

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
