package main

import (
	probe_openat "example.com/sra-monitor/internal/probe/sys_openat"
)

func main() {

	probe_openat.Run()
}
