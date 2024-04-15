# Go eBPF
<div style="position: relative;">
  <img src="https://ebpf-go.dev/ebpf-go.png" alt="Image" style="position: absolute; top: 0; right: 0;">
</div>

     
This repository is a test project designed to get familiar with eBPF (Extended Berkeley Packet Filter) technology using the Go programming language.

## Description

eBPF technology has gained popularity in recent years due to its ability to provide a secure and efficient framework for programming in the Linux kernel. It allows developers to write small programs that run in the kernel and can intercept and modify system events in real-time, such as network traffic or system events.

This project aims to provide a starting point for those who want to explore eBPF with Go. It provides simple examples of how to write eBPF programs using Go and how to load and execute them in the kernel.

Additionally, the program included in this repository demonstrates a practical use case of eBPF technology. It activates a filter that captures network packets using both TCP and UDP protocols. Each captured packet is printed to the standard output in different colors to differentiate between TCP (displayed in yellow) and UDP (displayed in cyan) packets.

## Features

- Examples of eBPF programs written in Go.
- Utilities for loading and managing eBPF programs in the kernel from Go.

## Prerequisites

- Go installed on your system.
- Access to the Linux kernel source code (to compile and install BPF modules).

## Usage

1. **Clone the repository:**

```bash
git clone https://github.com/Rattle-Brain/go-ebpf.git
```

2. **Compile the code:**

Navigate to the root directory of the cloned repository and run the following command to compile the code:

```bash

go build -ldflags "-s -w" -o interceptor cmd/interceptor.go
```

This command compiles the Go code and generates an executable binary named interceptor in the current directory.

3. **Execute the generated binary:**

Once the compilation is successful, run the following command to execute the generated binary:


```bash

sudo ./interceptor
```

By default will choose a Network Interface named *eth0*. To manually select another name, use the following flag:

```bash
sudo ./interceptor -i enp0s3
```

Also, you can dump all the intercepted data to a CSV file in case you need it to process that information.

```bash
sudo ./interceptor -i enp0s3 -f dump.csv
```

### Experimental

Alternatively, you could run the Docker Image by executing the following commands in the prompt. This feature is still a work in progress, so don't expect
it to be fully functional
```bash
sudo docker build -t goebpf .
sudo docker run --privileged goebpf
```

**Since we are using eBPF at kernel level, we need to grant the program root privileges, if not run with sudo, it will not work.**

---
## Disclaimer

*This README.md was generated with the assistance of artificial intelligence.*
