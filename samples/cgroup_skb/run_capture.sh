#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# Same setup as the TC sample: a separate network namespace plays the role of
# another network, reached from this machine through a veth pair.
NS=outside
HOST_IF=veth-host
HOST_IP=10.200.0.1
REMOTE_IP=10.200.0.2
LOCAL_PORT=8080
CGROUP=ebpf-sandbox

cleanup() {
  echo "Cleaning up..."
  [ -n "$PROG_PID" ] && sudo kill -INT "$PROG_PID" 2>/dev/null && wait "$PROG_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && sudo kill "$SERVER_PID" 2>/dev/null
  [ -n "$LOCAL_PID" ] && kill "$LOCAL_PID" 2>/dev/null
  sudo ip link del "$HOST_IF" 2>/dev/null || true
  sudo ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT

wait_listening() { # <command prefix...> <port>
  local port=${*: -1}
  for _ in $(seq 50); do
    "${@:1:$#-1}" ss -ltn | grep -q ":$port " && return 0
    sleep 0.1
  done
  echo "Nothing listening on port $port"; exit 1
}

echo "Creating the '$NS' namespace ($REMOTE_IP) and linking it to this machine ($HOST_IP)..."
sudo ip netns add "$NS"
sudo ip link add "$HOST_IF" type veth peer name veth-out
sudo ip link set veth-out netns "$NS"
sudo ip addr add "$HOST_IP/24" dev "$HOST_IF"
sudo ip link set "$HOST_IF" up
sudo ip netns exec "$NS" ip addr add "$REMOTE_IP/24" dev veth-out
sudo ip netns exec "$NS" ip link set veth-out up
sudo ip netns exec "$NS" ip link set lo up

# Plain TCPServer, not "python3 -m http.server": the latter does a reverse DNS
# lookup before listening, which hangs inside a namespace with no DNS.
SERVER='
import http.server, socketserver, sys
socketserver.TCPServer((sys.argv[1], int(sys.argv[2])), http.server.SimpleHTTPRequestHandler).serve_forever()
'
echo "Starting an HTTP server on port 80 inside '$NS'..."
sudo ip netns exec "$NS" python3 -c "$SERVER" 0.0.0.0 80 >/dev/null 2>&1 &
SERVER_PID=$!
wait_listening sudo ip netns exec "$NS" 80

echo "Starting an HTTP server on 127.0.0.1:$LOCAL_PORT on this machine..."
python3 -c "$SERVER" 127.0.0.1 "$LOCAL_PORT" >/dev/null 2>&1 &
LOCAL_PID=$!
wait_listening "$LOCAL_PORT"

echo "Starting cgroup_skb program on cgroup '$CGROUP' (needs sudo)..."
sudo ./cgroup_skb "$CGROUP" &
PROG_PID=$!
sleep 1

# Runs curl inside the sandbox: the shell moves itself into the cgroup by
# writing its PID to cgroup.procs, and curl, started from it, inherits it.
sandboxed() {
  sudo sh -c "echo \$\$ > /sys/fs/cgroup/$CGROUP/cgroup.procs && exec \"\$@\"" sh "$@"
}

request() { # <label> <url> [sandboxed]
  echo
  echo ">>> $1"
  if ${3:+sandboxed} curl -sS -o /dev/null -m 4 "$2" 2>/dev/null; then echo ">>> OK"; else echo ">>> FAILED (exit code $?)"; fi
  sleep 0.5
}

request "Request from outside the sandbox to $REMOTE_IP:80" "http://$REMOTE_IP/"
request "Request from inside the sandbox to $REMOTE_IP:80" "http://$REMOTE_IP/" sandboxed
request "Request from inside the sandbox to 127.0.0.1:$LOCAL_PORT" "http://127.0.0.1:$LOCAL_PORT/" sandboxed
echo
