# Docker support for go-ldap-proxy-cache

FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install ca-certificates for HTTPS downloads
RUN apk --no-cache add ca-certificates git

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ldap-proxy .

# Create final minimal image
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/ldap-proxy .

# Expose the proxy port
EXPOSE 3389

# Run the proxy
ENTRYPOINT ["./ldap-proxy"]

# Default command-line arguments can be overridden
CMD ["-proxy-addr", ":3389", "-ldap-server", "ldap:389", "-cache-ttl", "15m"]
