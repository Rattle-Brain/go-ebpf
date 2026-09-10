#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "Clearing trace buffer..."
sudo sh -c 'echo > /sys/kernel/tracing/trace'

echo "Starting fentry/fexit program (needs sudo)..."
sudo ./fentry &
PROG_PID=$!
sleep 2

echo "Triggering do_unlinkat via unlink(2)..."
touch /tmp/fentry_demo_file
rm /tmp/fentry_demo_file
sleep 1

echo "Captured trace_pipe output:"
sudo timeout 1 cat /sys/kernel/tracing/trace_pipe || true

echo "Stopping program..."
sudo kill "$PROG_PID"
wait "$PROG_PID" 2>/dev/null || true
