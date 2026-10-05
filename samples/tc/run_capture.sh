#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# A separate network namespace plays the role of another network: it has its
# own interfaces and addresses, and reaches this machine through a veth pair
# (a virtual cable). It gets two addresses, standing for two remote servers,
# and only one of them is blocked.
NS=outside
HOST_IF=veth-host
HOST_IP=10.200.0.1
ALLOWED_IP=10.200.0.2
BLOCKED_IP=10.200.0.3

cleanup() {
  echo "Cleaning up..."
  [ -n "$PROG_PID" ] && sudo kill -INT "$PROG_PID" 2>/dev/null && wait "$PROG_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && sudo kill "$SERVER_PID" 2>/dev/null
  sudo ip link del "$HOST_IF" 2>/dev/null || true
  sudo ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT

echo "Creating the '$NS' namespace ($ALLOWED_IP, $BLOCKED_IP) and linking it to this machine ($HOST_IP)..."
sudo ip netns add "$NS"
sudo ip link add "$HOST_IF" type veth peer name veth-out
sudo ip link set veth-out netns "$NS"
sudo ip addr add "$HOST_IP/24" dev "$HOST_IF"
sudo ip link set "$HOST_IF" up
sudo ip netns exec "$NS" ip addr add "$ALLOWED_IP/24" dev veth-out
sudo ip netns exec "$NS" ip addr add "$BLOCKED_IP/24" dev veth-out
sudo ip netns exec "$NS" ip link set veth-out up
sudo ip netns exec "$NS" ip link set lo up

SERVER_LOG=$(mktemp)
echo "Starting an HTTP server on port 80 inside '$NS'..."
# Not "python3 -m http.server": its HTTPServer binds the socket and then does a
# reverse DNS lookup of the address (socket.getfqdn) before listening, which
# hangs inside a namespace with no DNS. A plain TCPServer skips that lookup.
sudo ip netns exec "$NS" python3 -u -c '
import http.server, socketserver
socketserver.TCPServer(("0.0.0.0", 80), http.server.SimpleHTTPRequestHandler).serve_forever()
' >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
# Wait until the server is really listening, instead of guessing a delay.
for _ in $(seq 50); do
  sudo ip netns exec "$NS" ss -ltn | grep -q ':80 ' && break
  sleep 0.1
done
if ! sudo ip netns exec "$NS" ss -ltn | grep -q ':80 '; then
  echo "HTTP server did not start. Server log:"
  cat "$SERVER_LOG"
  echo "Server process:"
  ps -eo pid,stat,cmd | grep "[h]ttp.server\|[s]ocketserver" || echo "(none running)"
  echo "Sockets inside '$NS':"
  sudo ip netns exec "$NS" ss -ltnp
  exit 1
fi

echo "Starting TC program on $HOST_IF (needs sudo)..."
sudo ./tc "$HOST_IF" "$BLOCKED_IP" &
PROG_PID=$!
sleep 1

echo
echo ">>> Request from this machine to $ALLOWED_IP:80"
if curl -sS -o /dev/null -m 4 "http://$ALLOWED_IP/"; then echo ">>> OK"; else echo ">>> FAILED (exit code $?)"; fi
sleep 0.5

echo
echo ">>> Request from this machine to $BLOCKED_IP:80"
if curl -s -o /dev/null -m 4 "http://$BLOCKED_IP/"; then echo ">>> OK"; else echo ">>> FAILED (exit code $?)"; fi
sleep 0.5
echo
