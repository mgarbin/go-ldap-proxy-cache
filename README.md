# go-ldap-proxy-cache

A Go-based LDAP proxy with integrated caching to offload OpenLDAP servers.

## Features

- **LDAP Protocol Proxy**: Acts as a transparent proxy for LDAP client connections (no HTTP protocol)
- **15-Minute Cache**: Caches LDAP search results with a configurable TTL (default: 15 minutes)
- **Paginated Results Handling**: Automatically handles paginated LDAP responses with offsets, fetching all results from the backend server
- **Connection Pooling**: Efficiently manages connections to the backend LDAP server

## Installation

### From source

```bash
# Clone the repository
git clone https://github.com/mgarbin/go-ldap-proxy-cache.git
cd go-ldap-proxy-cache

# Build using Make
make build

# Or build directly with Go
go build -o ldap-proxy
```

### Using Docker

```bash
# Build the Docker image
docker build -t ldap-proxy .

# Run with Docker
docker run -p 3389:3389 ldap-proxy -ldap-server ldap.example.com:389
```

## Usage

### Command Line

```bash
./ldap-proxy [options]
```

### Options

- `-config`: Path to YAML configuration file (optional)
- `-proxy-addr`: Proxy listen address (default: `:3389`)
- `-ldap-server`: Backend LDAP server address (default: `localhost:389`)
- `-cache-ttl`: Cache TTL duration (default: `15m`)
- `-connection-timeout`: Backend connection timeout (default: `10s`)
- `-client-timeout`: Client connection timeout (default: `30s`)

### Configuration File

You can use a YAML configuration file instead of command-line flags:

```yaml
# config.yaml
proxy_addr: ":3389"
ldap_server: "localhost:389"
cache_ttl: 15m
connection_timeout: 10s
client_timeout: 30s
```

Then run:

```bash
./ldap-proxy -config config.yaml
```

**Note:** When using a YAML config file, all command-line flags are optional. CLI flags will override values from the YAML file if both are specified.

### Example

Start the proxy using CLI flags:

```bash
./ldap-proxy -proxy-addr :3389 -ldap-server ldap.example.com:389 -cache-ttl 15m
```

Or using a YAML config file:

```bash
./ldap-proxy -config config.yaml
```

Or mix both (CLI flags override YAML):

```bash
./ldap-proxy -config config.yaml -proxy-addr :3390
```

### Testing with ldapsearch

Once the proxy is running, you can test it with standard LDAP tools like `ldapsearch`:

```bash
# Search through the proxy
ldapsearch -H ldap://localhost:3389 -x -D "cn=admin,dc=example,dc=com" -w password \
  -b "dc=example,dc=com" "(objectClass=*)"

# Second identical search will be served from cache (much faster)
ldapsearch -H ldap://localhost:3389 -x -D "cn=admin,dc=example,dc=com" -w password \
  -b "dc=example,dc=com" "(objectClass=*)"
```

## How It Works

1. The proxy listens for LDAP client connections on the specified port
2. When a search request is received, it checks the cache first
3. If cached data is found and not expired, it returns the cached results
4. If not cached or expired, it queries the backend LDAP server
5. For paginated results, the proxy automatically fetches all pages from the backend
6. Results are cached for future requests with the same parameters
7. Cache entries automatically expire after the configured TTL

## Cache Key

The cache key is generated based on:
- Base DN
- Search filter
- Requested attributes
- Search scope

This ensures that identical queries return cached results while different queries are handled separately.

## Requirements

- Go 1.23 or higher
- Access to an LDAP server

## Dependencies

- [github.com/go-ldap/ldap/v3](https://github.com/go-ldap/ldap) - LDAP client library
- [github.com/go-asn1-ber/asn1-ber](https://github.com/go-asn1-ber/asn1-ber) - ASN.1 BER encoding/decoding

## License

This project is open source and available under the MIT License.

