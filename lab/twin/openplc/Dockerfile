# Build OpenPLC v3 from its canonical source. OpenPLC v3 is NOT published to Docker
# Hub under any name, so we clone + build the runtime here (mirroring upstream's own
# Dockerfile) and then layer the twin's seed material on top. This keeps
# `docker compose up` a single self-contained command. The compile is the slow part
# (~10 min on first build; Docker layer-caches it afterwards).
#
# The naive-vs-hardened SPILL claim does not depend on this container — it is proven
# headlessly by `lab/twin/test_twin.py` (the Python plant model). OpenPLC is the
# live-realism layer: a real soft-PLC running the ST control logic, pokeable at :8088.
FROM debian:trixie-20251020

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# --- canonical OpenPLC v3 build (mirrors github.com/thiagoralves/OpenPLC_v3 Dockerfile) ---
RUN git clone --depth 1 https://github.com/thiagoralves/OpenPLC_v3.git /workdir
WORKDIR /workdir
RUN mkdir /docker_persistent
RUN ./install.sh docker \
    && touch /docker_persistent/mbconfig.cfg \
    && touch /docker_persistent/persistent.file \
    && mkdir -p /docker_persistent/st_files \
    && cp /workdir/webserver/openplc.db /docker_persistent/openplc.db \
    && mv /workdir/webserver/openplc.db /workdir/webserver/openplc_default.db \
    && cp /workdir/webserver/dnp3.cfg /docker_persistent/dnp3.cfg \
    && mv /workdir/webserver/dnp3.cfg /workdir/webserver/dnp3_default.cfg \
    && cp -r /workdir/webserver/st_files/. /docker_persistent/st_files/ \
    && mv /workdir/webserver/st_files /workdir/webserver/st_files_default \
    && cp /workdir/webserver/active_program /docker_persistent/active_program \
    && mv /workdir/webserver/active_program /workdir/webserver/active_program_default \
    && ln -s /docker_persistent/mbconfig.cfg /workdir/webserver/mbconfig.cfg \
    && ln -s /docker_persistent/persistent.file /workdir/webserver/persistent.file \
    && ln -s /docker_persistent/openplc.db /workdir/webserver/openplc.db \
    && ln -s /docker_persistent/dnp3.cfg /workdir/webserver/dnp3.cfg \
    && ln -s /docker_persistent/st_files /workdir/webserver/st_files \
    && ln -s /docker_persistent/active_program /workdir/webserver/active_program

# --- twin seed material (consumed by auto-seed.sh on every boot) ---
# ST_DIR points at the canonical layout (a symlink into the /docker_persistent volume).
ENV ST_DIR=/workdir/webserver/st_files
COPY st/ /seed/st/
COPY slave_devices.seed /seed/slave_devices.seed

# auto-seed.sh wraps OpenPLC's start_openplc.sh so the soft-PLC boots already
# configured + RUNNING (slave device added, Modbus server on 502, selected ST
# compiled, runtime auto-started) — no manual clicks in the :8088 UI. It calls
# seed-openplc.py to seed the SQLite DB and rebuild mbconfig.cfg from it.
COPY auto-seed.sh    /workdir/auto-seed.sh
COPY seed-openplc.py /workdir/seed-openplc.py
RUN chmod +x /workdir/auto-seed.sh

ENTRYPOINT ["/workdir/auto-seed.sh"]
