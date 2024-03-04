# Use the official golang image (with version 1.21.7 as it was the one used to develop the program)
FROM golang:1.21.7 AS builder

# Set the working directory inside the container
WORKDIR /app/

# Copy the Go module files and download dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go application
RUN go build -ldflags "-s -w" -o interceptor cmd/interceptor

# Update package lists and install required packages
RUN sudo apt install linux-headers-$(uname -r) \
                 libbpfcc-dev \
                 libbpf-dev \
                 llvm \
                 clang \
                 gcc-multilib \
                 build-essential \
                 linux-tools-$(uname -r) \
                 linux-tools-common \
                 linux-tools-generic

# Set the working directory inside the container
WORKDIR /app

# Copy the built binary from the builder stage to the final image
COPY --from=builder /app/interceptor .

# Run the binary when the container starts
CMD ["./interceptor"]