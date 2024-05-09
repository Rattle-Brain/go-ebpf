# EXECVE Analyzer

This program allows you to see what process creates a new process showing the name of both.

## Description

Utilizing eBPF technology, this tool provides insightful visibility into the process execution flow by capturing details such as the calling process name during execve invocation and the resulting spawned processes. Additionally, it offers valuable insights into the CPU core on which the calling process was executing.

Moreover, ExecveAnalyzer seamlessly integrates with Kafka Provider for enhanced functionality, facilitating efficient filtering and transmission of captured data to a Kafka topic. By default, it streams the essential information to a UDP socket (port 3040), ensuring seamless retrieval and processing by the Kafka Producer component.


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
cd execv_ebpf
go build -o execve ./cmd/main.go ./cmd/execve_bpfel.go 
```

This command compiles the Go code and generates an executable binary named interceptor in the current directory.

3. **Execute the generated binary:**

Once the compilation is successful, run the following command to execute the generated binary:


```bash

sudo ./execve
```

By default will send information to ```localhost:3040```. This can be changed with the following flags:

```bash
sudo ./execve -a xxx.xxx.xxx.xxx -p xxxx
```

**Since we are using eBPF at kernel level, we need to grant the program root privileges, if not run with sudo, it will not work.**

---
## Disclaimer

*This README.md was generated with the assistance of artificial intelligence.*
