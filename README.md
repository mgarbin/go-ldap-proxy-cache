# go-ldap-proxy-cache

A Go-based LDAP proxy with integrated caching to offload OpenLDAP servers.

## Features

- **LDAP Protocol Proxy**: Acts as a transparent proxy for LDAP client connections (no HTTP protocol)
- **Flexible Caching**: Supports both in-memory cache and Redis cache with configurable TTL (default: 15 minutes)
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
  - Supports both unencrypted LDAP and LDAPS (LDAP over TLS)
  - Can be specified as `host:port` (defaults to `ldap://`) or with protocol prefix:
    - `ldap://host:port` - unencrypted LDAP (typically port 389)
    - `ldaps://host:port` - LDAP over TLS/SSL (typically port 636)
- `-cache-enabled`: Enable cache system (default: `true`)
  - When set to `false`, the cache system is completely disabled and all requests are forwarded directly to the backend LDAP server
- `-cache-ttl`: Cache TTL duration (default: `15m`)
- `-connection-timeout`: Backend connection timeout (default: `10s`)
- `-client-timeout`: Client connection timeout (default: `30s`)
- `-redis-enabled`: Enable Redis cache instead of in-memory cache (default: `false`)
- `-redis-addr`: Redis server address (default: `localhost:6379`, only used when Redis is enabled)
- `-redis-password`: Redis password (default: empty, only used when Redis is enabled)
- `-redis-db`: Redis database number (default: `0`, only used when Redis is enabled)
- `-log-json`: Enable JSON logging format (default: `false`)
  - When set to `true`, logs are output in JSON format for easier parsing and integration with log aggregation systems
  - When set to `false` (default), logs are output in human-readable console format

### Cache Options

The proxy supports three caching modes:

1. **Cache Disabled**: Completely disables caching. All requests are forwarded directly to the backend LDAP server with no caching. Use this when you need real-time data or want to minimize memory usage.
2. **In-Memory Cache (Default)**: Stores cache entries in the application's memory. Simple and fast, but cache is lost on restart.
3. **Redis Cache**: Stores cache entries in Redis. Allows cache to persist across restarts and can be shared across multiple proxy instances.

To disable caching completely, set `-cache-enabled=false` flag or `cache_enabled: false` in your configuration file.

To use Redis cache, enable it with the `-redis-enabled` flag or set `redis_enabled: true` in your configuration file. When Redis is enabled, the in-memory cache is automatically disabled. Note that `cache_enabled` must be `true` for Redis to work.

### Configuration File

You can use a YAML configuration file instead of command-line flags:

```yaml
# config.yaml
proxy_addr: ":3389"
ldap_server: "localhost:389"  # or ldaps://secure.ldap.example.com:636 for TLS
cache_enabled: true  # Set to false to disable caching completely
cache_ttl: 15m
connection_timeout: 10s
client_timeout: 30s

# Optional: Enable Redis cache
redis_enabled: false
redis_addr: "localhost:6379"
redis_password: ""
redis_db: 0
```

Then run:

```bash
./ldap-proxy -config config.yaml
```

**Note:** When using a YAML config file, all command-line flags are optional. CLI flags will override values from the YAML file if both are specified.

### Example

Start the proxy using CLI flags:

```bash
# Connect to unencrypted LDAP server with in-memory cache
./ldap-proxy -proxy-addr :3389 -ldap-server ldap.example.com:389 -cache-ttl 15m

# Connect to LDAPS (LDAP over TLS) server with in-memory cache
./ldap-proxy -proxy-addr :3389 -ldap-server ldaps://secure.example.com:636 -cache-ttl 15m

# Disable cache completely (all requests go directly to backend)
./ldap-proxy -proxy-addr :3389 -ldap-server ldap.example.com:389 -cache-enabled=false

# Use Redis cache instead of in-memory cache
./ldap-proxy -proxy-addr :3389 -ldap-server ldap.example.com:389 -redis-enabled -redis-addr localhost:6379

# Use Redis cache with authentication
./ldap-proxy -redis-enabled -redis-addr localhost:6379 -redis-password mypassword -redis-db 1
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
- (Optional) Redis server for external caching

## Dependencies

- [github.com/go-ldap/ldap/v3](https://github.com/go-ldap/ldap) - LDAP client library
- [github.com/go-asn1-ber/asn1-ber](https://github.com/go-asn1-ber/asn1-ber) - ASN.1 BER encoding/decoding
- [github.com/redis/go-redis/v9](https://github.com/redis/go-redis) - Redis client library (when using Redis cache)

## License

This project is open source and available under the MIT License.

