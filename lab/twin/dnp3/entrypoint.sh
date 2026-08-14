#!/bin/sh
# entrypoint.sh -- point this container's default route at the zone firewall.
#
# Docker drops inter-bridge forwarding, so cross-zone traffic must go through the
# multi-homed zone-fw router (its .1 in each zone). Setting the default route to
# zone-fw is what forces every cross-zone packet across the nftables conduits.
# No-op (with a warning) if NET_ADMIN is absent -- the service still starts.
if [ -n "$ZONE_GW" ]; then
  if ip route replace default via "$ZONE_GW" 2>/dev/null; then
    echo "[entrypoint] default route -> zone-fw ($ZONE_GW)" >&2
  else
    echo "[entrypoint] WARN: could not set default route via $ZONE_GW (need NET_ADMIN); continuing" >&2
  fi
fi
exec "$@"
