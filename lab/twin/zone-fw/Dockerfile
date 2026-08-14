FROM debian:stable-slim
# nftables = the conduit firewall; iproute2 + procps for routing/sysctl.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# conduits.nft is bind-mounted at /etc/nftables/conduits.nft by compose, but also
# bake a copy so the image is self-contained if the mount is omitted.
COPY conduits.nft /etc/nftables/conduits.nft
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
