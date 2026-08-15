# IMPORTANT — OpenPLC v3 is NOT published to Docker Hub under any name (the old
# `thiagoralves/OpenPLC_v3` reference here was also invalid: image names must be
# lowercase, so modern BuildKit rejects it outright). Before `docker compose up` can
# build the twin you must PROVIDE an `openplc_v3` image — build it from the canonical
# source once:  git clone https://github.com/thiagoralves/OpenPLC_v3 &&
#   cd OpenPLC_v3 && docker build -t openplc_v3 .   (it self-installs; ~10 min).
# The naive-vs-hardened SPILL claim is proven headlessly WITHOUT OpenPLC by
# `lab/twin/test_twin.py` (the Python plant model); OpenPLC is the live-realism layer.
FROM openplc_v3
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
