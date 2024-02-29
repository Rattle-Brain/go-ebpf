# Use the official golang image (with version 1.21.7 as it was the one used to develop the program)
FROM golang:1.21.7 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go application
RUN go build -ldflags "-s -w" -o interceptor cmd/interceptor

# Use a base image with the necessary eBPF development tools
FROM ubuntu:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install required packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    libbpfcc-dev \
    bpfcc-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the built binary from the builder stage to the final image
COPY --from=builder /app/interceptor .

# Run the binary when the container starts
CMD ["./interceptor"]