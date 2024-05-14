# Go eBPF

This repository contains several completely functional and well documented KernelSpace eBPF programs and its UserSpace counterpart written in Golang.

Initially this repository was meant for personal use to get familiar with the eBPF technology, and still is. Most of the programs and tools here are incredibly simple and don't aim for professional use however, it's come a long way since the beginning and thought some more people might find it useful.

## Description

<img src="https://ebpf-go.dev/ebpf-go.png" align=right>

eBPF technology has gained popularity in recent years due to its ability to provide a secure and efficient framework for programming in the Linux kernel. It allows developers to write small programs that run in the kernel and can intercept and modify system events in real-time, such as network traffic or system events.

This project aims to provide a starting point for those who want to explore eBPF with Go. It provides some not-so-simple examples of how to write eBPF programs using Go and how to load and execute them in the kernel.

To load the eBPF objects into Go, transforming eBPF bytecode into something Golang is capable of understaiding we use Cilium's [eBPF2Go](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go)

## Features

- Examples of eBPF programs written in Go.
- The utilities needed to load eBPF programs in go come from [Cilium](https://github.com/cilium/ebpf).

## Prerequisites

- Go installed on your system.
- bpf libs installed
- Access to Kernel headers, helpers and code

## Usage

1. **Clone the repository:**

```bash
git clone https://github.com/Rattle-Brain/go-ebpf.git
```

2. **Compile the code:**

Navigate to the directory of the program you want to compile and build the code. As an example:

```bash
cd interceptor_ebpf
go build -ldflags "-s -w" -o interceptor cmd/interceptor.go
```

This command compiles the Go code and generates an executable binary named interceptor in the current directory.

3. **Execute the generated binary:**

Once the compilation is successful, run the following command to execute the generated binary:

```bash

sudo ./interceptor
```

Further instructions and details are provided in the README of each program.

### Experimental

Alternatively, you could run the Docker Image by executing the following commands in the prompt. This feature is still a work in progress, so don't expect
it to be fully functional
```bash
sudo docker build -t goebpf .
sudo docker run --privileged goebpf
```

This option is not available in all directories, since not all of them contain a Dockerfile. However, the idea is the same. You build the Dockerfile
and run it as privileged.

**Since we are using eBPF at kernel level, we need to grant the program root privileges, if not run with sudo, it will not work.**

---
## Disclaimer

*This README.md was generated with the assistance of artificial intelligence.*
