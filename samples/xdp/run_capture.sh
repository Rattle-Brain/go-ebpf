#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# A separate network namespace plays the role of another computer: it has its
# own interfaces and addresses, and reaches this machine through a veth pair
# (a virtual cable), exactly as a real remote host would through a real NIC.
NS=outside
HOST_IF=veth-host
HOST_IP=10.200.0.1
OUT_IP=10.200.0.2

cleanup() {
  echo "Cleaning up..."
  [ -n "$PROG_PID" ] && sudo kill -INT "$PROG_PID" 2>/dev/null && wait "$PROG_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && sudo kill "$SERVER_PID" 2>/dev/null
  sudo ip link del "$HOST_IF" 2>/dev/null || true
  sudo ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT

echo "Creating the '$NS' namespace ($OUT_IP) and linking it to this machine ($HOST_IP)..."
sudo ip netns add "$NS"
sudo ip link add "$HOST_IF" type veth peer name veth-out
sudo ip link set veth-out netns "$NS"
sudo ip addr add "$HOST_IP/24" dev "$HOST_IF"
sudo ip link set "$HOST_IF" up
sudo ip netns exec "$NS" ip addr add "$OUT_IP/24" dev veth-out
sudo ip netns exec "$NS" ip link set veth-out up

echo "Starting an HTTP server on port 80..."
sudo python3 -m http.server 80 --bind 0.0.0.0 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

echo "Starting XDP program on lo and $HOST_IF (needs sudo)..."
sudo ./xdp "$HOST_IF" &
PROG_PID=$!
sleep 1

echo
echo ">>> Request from this machine to 127.0.0.1:80"
if curl -s -o /dev/null -m 4 http://127.0.0.1/; then echo ">>> OK"; else echo ">>> FAILED"; fi
sleep 0.5

echo
echo ">>> Request from '$NS' to $HOST_IP:80"
if sudo ip netns exec "$NS" curl -s -o /dev/null -m 4 "http://$HOST_IP/"; then echo ">>> OK"; else echo ">>> TIMED OUT"; fi
sleep 0.5
echo
