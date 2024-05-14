# eBPF Sensitive Resource Access (SRA) Monitoring

## Overview

The eBPF Sensitive Resource Access Monitoring project is a system monitoring tool designed to track access to sensitive system resources in real-time. Leveraging eBPF (extended Berkeley Packet Filter) technology, this project provides deep visibility into file accesses, system calls, and other critical system activities, allowing administrators to detect potential security threats and unauthorized actions.

## Features

- **Real-time Monitoring**: Capture access events to sensitive resources as they occur, providing instant visibility into system activities.
- **Granular Visibility**: Monitor file accesses, system calls, process IDs, user IDs, access types, timestamps, and more, enabling detailed forensic analysis.
- **Low Overhead**: Utilize lightweight eBPF programs with minimal impact on system performance and resource utilization.
- **Customizable Policies**: Define custom policies to enforce access controls and detect suspicious behaviors based on captured events.
- **Scalable Architecture**: Deploy monitoring agents across distributed systems and clusters, aggregating data for centralized analysis and management.

## Getting Started

### Prerequisites

- Linux kernel version 4.9 or later with eBPF support enabled
- Go v1.22.2 installed on your system.
- Necessary permissions to load and attach eBPF programs to kernel tracepoints or probes

---

## Usage

1. **Clone the repository:**

```bash
git clone https://github.com/Rattle-Brain/go-ebpf.git
```

2. **Compile the code:**

Navigate to the directory of the program you want to compile and build the code. As an example:

```bash
cd execv_ebpf
go build -o sra-monitor ./cmd/main.go ./cmd/monitor_bpfel.go 
```

This command compiles the Go code and generates an executable binary named interceptor in the current directory.

3. **Execute the generated binary:**

Once the compilation is successful, run the following command to execute the generated binary:


```bash

sudo ./sra-monitor
```

## Contributing

Contributions to the eBPF Sensitive Resource Access Monitoring project are welcome! To contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit them (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a new Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
## Disclaimer

*This README.md was generated with the assistance of artificial intelligence.*