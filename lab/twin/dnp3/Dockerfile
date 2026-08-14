FROM python:3.11-slim
# iproute2 lets entrypoint.sh repoint the default route at zone-fw (the conduit
# router). The DNP3 code (dnp3lib/gateway/master/outstation) + modbus_tcp.py are
# pure standard library -- no pip deps.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
# default role is the outstation gateway; compose overrides `command:` per service
CMD ["python", "gateway.py", "--modbus-host", "openplc", "--listen", "0.0.0.0:20000", "--outstn-addr", "10"]
