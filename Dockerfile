FROM python:3.12-slim

# Scanner tools available to plugins out of the box. nuclei is a single Go
# binary; uncomment the block below to bake it in, or mount it at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap nikto ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Optional: install nuclei
# RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /tmp/n.zip \
#     && apt-get update && apt-get install -y unzip && unzip /tmp/n.zip -d /usr/local/bin \
#     && rm /tmp/n.zip && apt-get remove -y unzip && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend backend
COPY frontend frontend

ENV DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=8000
VOLUME ["/data"]
EXPOSE 8000

WORKDIR /app/backend
CMD ["sh", "-c", "uvicorn app:app --host ${HOST} --port ${PORT}"]
