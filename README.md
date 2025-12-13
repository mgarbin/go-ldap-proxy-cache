# go-ldap-proxy-cache

A Go-based LDAP proxy with integrated caching to offload OpenLDAP servers.

## Features

- **LDAP Protocol Proxy**: Acts as a transparent proxy for LDAP client connections (no HTTP protocol)
- **15-Minute Cache**: Caches LDAP search results with a configurable TTL (default: 15 minutes)
- **Paginated Results Handling**: Automatically handles paginated LDAP responses with offsets, fetching all results from the backend server
- **Connection Pooling**: Efficiently manages connections to the backend LDAP server

## Installation

```bash
go build -o ldap-proxy
```

## Usage

```bash
./ldap-proxy [options]
```

### Options

- `-proxy-addr`: Proxy listen address (default: `:3389`)
- `-ldap-server`: Backend LDAP server address (default: `localhost:389`)
- `-cache-ttl`: Cache TTL duration (default: `15m`)
- `-bind-dn`: LDAP bind DN (optional)
- `-bind-pass`: LDAP bind password (optional)

### Example

Start the proxy on port 3389, connecting to an LDAP server at ldap.example.com:389 with a 15-minute cache:

```bash
./ldap-proxy -proxy-addr :3389 -ldap-server ldap.example.com:389 -cache-ttl 15m
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

- Go 1.21 or higher
- Access to an LDAP server

## Dependencies

- [github.com/go-ldap/ldap/v3](https://github.com/go-ldap/ldap) - LDAP client library
- [github.com/go-asn1-ber/asn1-ber](https://github.com/go-asn1-ber/asn1-ber) - ASN.1 BER encoding/decoding

## License

This project is open source and available under the MIT License.

