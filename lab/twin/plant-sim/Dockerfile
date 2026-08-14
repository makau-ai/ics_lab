FROM python:3.11-slim
# iproute2 lets entrypoint.sh repoint the default route at zone-fw (the conduit
# router). plant_sim.py + modbus_tcp.py are pure standard library -- no pip deps.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "plant_sim.py"]
