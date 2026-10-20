#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

PORT=9000

cleanup() {
  echo "Cleaning up..."
  [ -n "$PROG_PID" ] && sudo kill -INT "$PROG_PID" 2>/dev/null && wait "$PROG_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
}
trap cleanup EXIT

# Reads each connection until the client closes it, and reports what arrived.
SERVER='
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen()
while True:
    c, _ = s.accept()
    data = b""
    while chunk := c.recv(4096):
        data += chunk
    print(f">>> Server received {len(data)} bytes in {data.count(10)} messages", flush=True)
    c.close()
'

# Sends five short messages, then keeps the connection open for a while so
# that ss can inspect it.
CLIENT='
import socket, sys, time
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
for i in range(5):
    c.sendall(f"message {i}\n".encode())
    time.sleep(0.1)
time.sleep(1.5)
c.close()
'

echo "Starting a TCP server on 127.0.0.1:$PORT..."
python3 -c "$SERVER" "$PORT" &
SERVER_PID=$!
for _ in $(seq 50); do
  ss -ltn | grep -q ":$PORT " && break
  sleep 0.1
done
ss -ltn | grep -q ":$PORT " || { echo "Nothing listening on port $PORT"; exit 1; }

# Runs the client and shows how many bytes and data segments its socket
# handed to TCP, as reported by ss.
connect() { # <label>
  echo
  echo ">>> $1"
  python3 -c "$CLIENT" "$PORT" &
  local client=$!
  sleep 1
  local info
  info=$(ss -tin state established "( dport = :$PORT )" | tail -n 1)
  local sent segs
  sent=$(grep -o 'bytes_sent:[0-9]*' <<<"$info" | cut -d: -f2)
  segs=$(grep -o 'data_segs_out:[0-9]*' <<<"$info" | cut -d: -f2)
  # ss omits the fields that are zero.
  echo ">>> Client socket: bytes_sent=${sent:-0} data_segs_out=${segs:-0}"
  wait "$client"
  sleep 0.3
}

connect "Connection without the eBPF programs"

echo
echo "Starting sockmap program (needs sudo)..."
sudo ./sockmap &
PROG_PID=$!
sleep 1

connect "Connection with the eBPF programs"
echo
