#!/bin/sh
# entrypoint.sh -- bring up the conduit router: ip_forward + nftables.
set -e
echo "[zone-fw] enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo "[zone-fw] WARN: could not set ip_forward (need NET_ADMIN / sysctl)"
echo "[zone-fw] loading conduits.nft (deny-by-default + C1..C4)"
nft -f /etc/nftables/conduits.nft
echo "[zone-fw] active ruleset:"
nft list ruleset || true
echo "[zone-fw] conduits up; CONDUIT-DROP hits are logged to the kernel ring buffer (dmesg)."
# Stay alive as the zones' router. tail keeps PID 1 without spinning the CPU.
exec tail -f /dev/null
