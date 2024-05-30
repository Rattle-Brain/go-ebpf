# eBPF Sensitive Resource Access (SRA) Monitoring

## Overview

The eBPF Sensitive Resource Access Monitoring project is a system monitoring tool designed to track access to sensitive system resources in real-time. Leveraging eBPF (extended Berkeley Packet Filter) technology, this project provides deep visibility into file accesses, system calls, and other critical system activities, allowing administrators to detect potential security threats and unauthorized actions.

This tool loads a slice of files to observe from the `LINUX-SENSITIVE-FILES.txt` file that can be found in this directory. This can be updated without having to stop and rerun the program. **All files must start from root (`/`) and have a full path**.

## Features

- **Real-time Monitoring**: Capture access events to sensitive resources as they occur, providing instant visibility into system activities.
- **Granular Visibility**: Monitor file accesses, system calls, process IDs, user IDs, access types, timestamps, and more, enabling detailed forensic analysis.
- **Low Overhead**: Utilize lightweight eBPF programs with minimal impact on system performance and resource utilization.
- **Customizable Policies**: Define custom policies to enforce access controls and detect suspicious behaviors based on captured events.
- **Scalable Architecture**: Deploy monitoring agents across distributed systems and clusters, aggregating data for centralized analysis and management.

## Getting Started

### Prerequisites

- Linux kernel version 6.5.0 or later with eBPF support enabled
- Go v1.22.2 installed on your system.
- bpftool installed (just in case you need it, but it's not mandatory to run the program)
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
cd sra-monitor_ebpf
go build -ldflags "-s -w" -o monitor ./cmd/monitor.go
```

This command compiles the Go code and generates a release version executable binary named interceptor in the current directory.

3. **Execute the generated binary:**

Once the compilation is successful, run the following command to execute the generated binary:


```bash
sudo ./monitor
```

This shows no information. If you want to see the events that are being traced, enable verbose mode by typing the following

```bash
sudo ./monitor -v
```

For extra verbose mode, that also shows debug information use the following command

```bash
sudo ./monitor -vv
```

By default SRA Monitor will dump the events in a log file called ```monitor.log``` that can be found in the same directory as the executable. If you want to change the name or the directory of the output file, do so with the `-L` tag

```bash
sudo ./monitor -L path/to/new/logfile.log
```

Finally, there's an option to change the input file's name or location by running the following command.
```bash
sudo ./monitor -F path/to/new/input/file.txt
```

You can run several flags at once and refer to the documentation by using `-h`.

### Note:

You may need to regenerate the vmlinux.h header file. For that, run the following command (make sure you have `bpftool` installed on your system)
**while in the `sra-monitor_ebpf` directory**

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./bpf/vmlinux.h                                                 
```

## Contributing

Contributions to the eBPF Sensitive Resource Access Monitoring project are welcome! To contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Make your changes and commit them (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a new Pull Request.

## License

This project is licensed under the [MIT License](../LICENSE).

---
## Disclaimer

*This README.md was generated with the assistance of artificial intelligence.*