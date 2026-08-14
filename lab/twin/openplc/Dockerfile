FROM thiagoralves/OpenPLC_v3
# The upstream image already contains the OpenPLC v3 runtime + web server on 8080
# and the Modbus server on 502. We only add the twin's seed material; we do NOT
# override the image's own start command, so OpenPLC boots normally.
#
# Bring-up (documented in README + load-program.sh):
#   1. add plant-sim as a Slave Device (remote I/O) using slave_devices.seed
#   2. upload + compile the selected ST program (naive_wetwell.st | hardened_wetwell.st)
#   3. under Settings, ENABLE Modbus, DISABLE the DNP3 + EtherNet/IP servers
#      (dnp3-gw provides the readable DNP3 on 20000, not OpenPLC's opendnp3).
COPY st/ /seed/st/
COPY slave_devices.seed /seed/slave_devices.seed
COPY load-program.sh /seed/load-program.sh
USER root
RUN chmod +x /seed/load-program.sh || true
