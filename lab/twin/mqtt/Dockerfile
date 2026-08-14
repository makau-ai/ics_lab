FROM python:3.11-slim
# iproute2 for the entrypoint route-injection (default route -> zone-fw).
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
# default role is the IIoT telemetry gateway; compose overrides `command:` per service
CMD ["python", "publisher.py"]
