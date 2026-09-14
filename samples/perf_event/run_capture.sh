#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "Clearing trace buffer..."
sudo sh -c 'echo > /sys/kernel/tracing/trace'

echo "Starting perf_event program (needs sudo)..."
sudo ./perf_event &
PROG_PID=$!
sleep 1

echo "Pinning a busy loop to CPU 0 so it gets sampled..."
taskset -c 0 sh -c 'yes > /dev/null' &
BUSY_PID=$!
sleep 1

echo "Captured trace_pipe output:"
sudo timeout 1 cat /sys/kernel/tracing/trace_pipe || true

echo "Stopping busy loop and program..."
kill "$BUSY_PID" 2>/dev/null || true
sudo kill "$PROG_PID"
wait "$PROG_PID" 2>/dev/null || true
