# Use the official golang image (with version 1.21.7 as it was the one used to develop the program)
FROM golang:1.21.7-bookworm

# Set the working directory inside the container
WORKDIR /app/

# Copy the Go module files and download dependencies
COPY go.mod .
COPY go.sum .
RUN go mod tidy
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the Go application
RUN go build -ldflags "-s -w" -o interceptor ./cmd/interceptor.go

# Update package lists and install required packages
RUN apt update && apt upgrade


# Run the binary when the container starts
CMD ["./interceptor"]