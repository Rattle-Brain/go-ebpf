# eBPF Network Interceptor

This is a Network Interceptor that allows you to see incoming and outgoing traffic with minimal performance overhead

## Description

Leveraging the power of eBPF (Extended Berkeley Packet Filter), this Network Interceptor offers efficient and high-performance packet capture and analysis capabilities. With color-coded output for TCP and UDP packets, Interceptor simplifies packet visualization and enables users to gain valuable insights into network traffic patterns.

This allows you to know the source and destination IP and Port of each packet that comes and leaves your machine, as well as its protocol (TCP displayed in yellow and UDP displayed in cyan) in a very efficient way.

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
