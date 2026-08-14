#!/usr/bin/env bash
# ============================================================================
#  gen-certs.sh -- self-signed CA + server certs for the optional MQTT 8883
#  mTLS listener (CIE W2 "after"). Run this ONCE before enabling the 8883 block
#  in mosquitto.secure.conf, then re-up the hardened stack.
#
#     ./mosquitto/gen-certs.sh
#     # then uncomment the "listener 8883" section in mosquitto.secure.conf
#
#  Teaching-grade certs only. DNP3/MQTT stay plaintext by default so ICSNPP can
#  parse the wire (CIE_HARDENING 7 documented trade-off); 8883 is the contrast.
# ============================================================================
set -e
CERTS="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$CERTS"
cd "$CERTS"

echo "[gen-certs] CA"
openssl req -new -x509 -days 3650 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/O=ICS-Twin-Lab/CN=twin-ca"

echo "[gen-certs] server key + CSR (CN=mqtt-broker)"
openssl req -new -nodes \
  -keyout server.key -out server.csr \
  -subj "/O=ICS-Twin-Lab/CN=mqtt-broker"

echo "[gen-certs] sign server cert"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -out server.crt

rm -f server.csr ca.srl
chmod 644 ./*.crt ./*.key
echo "[gen-certs] wrote: $CERTS/{ca.crt,server.crt,server.key}"
echo "[gen-certs] now uncomment the 'listener 8883' block in mosquitto.secure.conf"
