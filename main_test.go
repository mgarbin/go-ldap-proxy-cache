package main

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// getTestLogger creates a logger for tests that discards output
func getTestLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

func TestCache(t *testing.T) {
	cache := NewCache(100*time.Millisecond, getTestLogger())

	// Test basic set and get
	baseDN := "dc=example,dc=com"
	filter := "(uid=test)"
	attributes := []string{"cn", "mail"}
	scope := 2
	data := "test data"

	cache.Set(baseDN, filter, attributes, scope, data)

	result, found := cache.Get(baseDN, filter, attributes, scope)
	if !found {
		t.Error("Expected to find cached data")
	}
	if result != data {
		t.Errorf("Expected %v, got %v", data, result)
	}

	// Test cache statistics
	hits, misses, size := cache.Stats()
	if hits != 1 {
		t.Errorf("Expected 1 hit, got %d", hits)
	}
	if misses != 0 {
		t.Errorf("Expected 0 misses, got %d", misses)
	}
	if size != 1 {
		t.Errorf("Expected 1 entry, got %d", size)
	}

	// Test cache miss
	_, found = cache.Get("dc=other,dc=com", filter, attributes, scope)
	if found {
		t.Error("Expected cache miss for different baseDN")
	}

	// Verify miss was counted
	hits, misses, _ = cache.Stats()
	if misses != 1 {
		t.Errorf("Expected 1 miss after cache miss, got %d", misses)
	}

	// Test cache expiration
	time.Sleep(150 * time.Millisecond)
	_, found = cache.Get(baseDN, filter, attributes, scope)
	if found {
		t.Error("Expected cache entry to be expired")
	}

	// Verify expired entry counts as miss
	hits, misses, _ = cache.Stats()
	if misses != 2 {
		t.Errorf("Expected 2 misses after expiration, got %d", misses)
	}
}

func TestCacheKeyGeneration(t *testing.T) {
	baseDN1 := "dc=example,dc=com"
	filter1 := "(uid=test)"
	attributes1 := []string{"cn", "mail"}
	scope1 := 2

	key1 := generateCacheKey(baseDN1, filter1, attributes1, scope1)
	key2 := generateCacheKey(baseDN1, filter1, attributes1, scope1)

	if key1 != key2 {
		t.Error("Same parameters should generate same key")
	}

	// Different filter should generate different key
	key3 := generateCacheKey(baseDN1, "(uid=other)", attributes1, scope1)
	if key1 == key3 {
		t.Error("Different filters should generate different keys")
	}

	// Different attributes should generate different key
	key4 := generateCacheKey(baseDN1, filter1, []string{"cn"}, scope1)
	if key1 == key4 {
		t.Error("Different attributes should generate different keys")
	}
}

func TestConfig(t *testing.T) {
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
	}

	if config.ProxyAddr != ":3389" {
		t.Errorf("Expected proxy addr :3389, got %s", config.ProxyAddr)
	}

	if config.LDAPServer != "localhost:389" {
		t.Errorf("Expected LDAP server localhost:389, got %s", config.LDAPServer)
	}

	if config.CacheTTL != 15*time.Minute {
		t.Errorf("Expected cache TTL 15m, got %v", config.CacheTTL)
	}

	if config.ConnectionTimeout != 10*time.Second {
		t.Errorf("Expected connection timeout 10s, got %v", config.ConnectionTimeout)
	}

	if config.ClientTimeout != 30*time.Second {
		t.Errorf("Expected client timeout 30s, got %v", config.ClientTimeout)
	}
}

func TestYAMLConfig(t *testing.T) {
	// Create a temporary YAML config file
	yamlContent := `proxy_addr: ":4389"
ldap_server: "ldap.test.com:389"
cache_ttl: 30m
connection_timeout: 15s
client_timeout: 45s
`

	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Test loading YAML config
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
	}

	err = loadYAMLConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("Failed to load YAML config: %v", err)
	}

	if config.ProxyAddr != ":4389" {
		t.Errorf("Expected proxy addr :4389, got %s", config.ProxyAddr)
	}

	if config.LDAPServer != "ldap.test.com:389" {
		t.Errorf("Expected LDAP server ldap.test.com:389, got %s", config.LDAPServer)
	}

	if config.CacheTTL != 30*time.Minute {
		t.Errorf("Expected cache TTL 30m, got %v", config.CacheTTL)
	}

	if config.ConnectionTimeout != 15*time.Second {
		t.Errorf("Expected connection timeout 15s, got %v", config.ConnectionTimeout)
	}

	if config.ClientTimeout != 45*time.Second {
		t.Errorf("Expected client timeout 45s, got %v", config.ClientTimeout)
	}
}

func TestYAMLConfigPartial(t *testing.T) {
	// Test that partial YAML config doesn't override defaults
	yamlContent := `proxy_addr: ":4389"
ldap_server: "ldap.test.com:389"
`

	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Test loading partial YAML config
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		RedisEnabled:      false,
	}

	err = loadYAMLConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("Failed to load YAML config: %v", err)
	}

	// These should be overridden by YAML
	if config.ProxyAddr != ":4389" {
		t.Errorf("Expected proxy addr :4389, got %s", config.ProxyAddr)
	}

	if config.LDAPServer != "ldap.test.com:389" {
		t.Errorf("Expected LDAP server ldap.test.com:389, got %s", config.LDAPServer)
	}

	// These should keep their default values (not in YAML)
	if config.CacheTTL != 15*time.Minute {
		t.Errorf("Expected cache TTL 15m (default), got %v", config.CacheTTL)
	}

	if config.ConnectionTimeout != 10*time.Second {
		t.Errorf("Expected connection timeout 10s (default), got %v", config.ConnectionTimeout)
	}

	if config.ClientTimeout != 30*time.Second {
		t.Errorf("Expected client timeout 30s (default), got %v", config.ClientTimeout)
	}

	// Boolean fields should keep their defaults when not present in YAML
	if !config.CacheEnabled {
		t.Error("Expected cache to remain enabled (default) when not specified in YAML")
	}

	if config.RedisEnabled {
		t.Error("Expected Redis to remain disabled (default) when not specified in YAML")
	}
}

func TestEnsureLDAPURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Plain hostname with port",
			input:    "localhost:389",
			expected: "ldap://localhost:389",
		},
		{
			name:     "Already has ldap:// prefix",
			input:    "ldap://localhost:389",
			expected: "ldap://localhost:389",
		},
		{
			name:     "Has ldaps:// prefix",
			input:    "ldaps://secure.example.com:636",
			expected: "ldaps://secure.example.com:636",
		},
		{
			name:     "Has ldapi:// prefix",
			input:    "ldapi:///var/run/slapd/ldapi",
			expected: "ldapi:///var/run/slapd/ldapi",
		},
		{
			name:     "Has cldap:// prefix",
			input:    "cldap://ad.example.com:389",
			expected: "cldap://ad.example.com:389",
		},
		{
			name:     "Plain hostname without port",
			input:    "ldap.example.com",
			expected: "ldap://ldap.example.com",
		},
		{
			name:     "IP address with port",
			input:    "192.168.1.1:389",
			expected: "ldap://192.168.1.1:389",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ensureLDAPURL(tt.input)
			if result != tt.expected {
				t.Errorf("ensureLDAPURL(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRedisConfig(t *testing.T) {
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		RedisEnabled:      true,
		RedisAddr:         "localhost:6379",
		RedisPassword:     "mypassword",
		RedisDB:           1,
	}

	if !config.RedisEnabled {
		t.Error("Expected Redis to be enabled")
	}

	if config.RedisAddr != "localhost:6379" {
		t.Errorf("Expected Redis addr localhost:6379, got %s", config.RedisAddr)
	}

	if config.RedisPassword != "mypassword" {
		t.Errorf("Expected Redis password mypassword, got %s", config.RedisPassword)
	}

	if config.RedisDB != 1 {
		t.Errorf("Expected Redis DB 1, got %d", config.RedisDB)
	}
}

func TestNoOpCache(t *testing.T) {
	cache := NewNoOpCache()

	// Test that Get always returns a miss
	baseDN := "dc=example,dc=com"
	filter := "(uid=test)"
	attributes := []string{"cn", "mail"}
	scope := 2
	data := "test data"

	// Set some data (should be ignored)
	cache.Set(baseDN, filter, attributes, scope, data)

	// Try to get the data back (should always miss)
	result, found := cache.Get(baseDN, filter, attributes, scope)
	if found {
		t.Error("NoOpCache should always return cache miss")
	}
	if result != nil {
		t.Error("NoOpCache should always return nil data")
	}

	// Test statistics (should all be zero)
	hits, misses, size := cache.Stats()
	if hits != 0 {
		t.Errorf("Expected 0 hits, got %d", hits)
	}
	if misses != 0 {
		t.Errorf("Expected 0 misses, got %d", misses)
	}
	if size != 0 {
		t.Errorf("Expected 0 size, got %d", size)
	}

	// Test Close (should not error)
	if err := cache.Close(); err != nil {
		t.Errorf("NoOpCache.Close() should not return error, got %v", err)
	}
}

func TestYAMLConfigWithRedis(t *testing.T) {
	// Create a temporary YAML config file with Redis settings
	yamlContent := `proxy_addr: ":4389"
ldap_server: "ldap.test.com:389"
cache_ttl: 30m
connection_timeout: 15s
client_timeout: 45s
redis_enabled: true
redis_addr: "redis.test.com:6379"
redis_password: "testpass"
redis_db: 2
`

	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Test loading YAML config with Redis settings
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		RedisEnabled:      false,
		RedisAddr:         "localhost:6379",
		RedisPassword:     "",
		RedisDB:           0,
	}

	err = loadYAMLConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("Failed to load YAML config: %v", err)
	}

	if !config.RedisEnabled {
		t.Error("Expected Redis to be enabled from YAML")
	}

	if config.RedisAddr != "redis.test.com:6379" {
		t.Errorf("Expected Redis addr redis.test.com:6379, got %s", config.RedisAddr)
	}

	if config.RedisPassword != "testpass" {
		t.Errorf("Expected Redis password testpass, got %s", config.RedisPassword)
	}

	if config.RedisDB != 2 {
		t.Errorf("Expected Redis DB 2, got %d", config.RedisDB)
	}
}

func TestYAMLConfigCacheDisabled(t *testing.T) {
	// Create a temporary YAML config file with cache disabled
	yamlContent := `proxy_addr: ":4389"
ldap_server: "ldap.test.com:389"
cache_enabled: false
cache_ttl: 30m
`

	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Test loading YAML config with cache disabled
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
	}

	err = loadYAMLConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("Failed to load YAML config: %v", err)
	}

	if config.CacheEnabled {
		t.Error("Expected cache to be disabled from YAML")
	}

	if config.ProxyAddr != ":4389" {
		t.Errorf("Expected proxy addr :4389, got %s", config.ProxyAddr)
	}
}

func TestConfigCacheEnabled(t *testing.T) {
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
	}

	if !config.CacheEnabled {
		t.Error("Expected cache to be enabled by default")
	}
}

func TestConfigCacheDisabled(t *testing.T) {
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      false,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
	}

	if config.CacheEnabled {
		t.Error("Expected cache to be disabled")
	}
}

func TestLogJSON(t *testing.T) {
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		LogJSON:           true,
	}

	if !config.LogJSON {
		t.Error("Expected LogJSON to be true")
	}

	// Test default value
	config2 := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		LogJSON:           false,
	}

	if config2.LogJSON {
		t.Error("Expected LogJSON to be false by default")
	}
}

func TestYAMLConfigWithLogJSON(t *testing.T) {
	// Create a temporary YAML config file with log_json setting
	yamlContent := `proxy_addr: ":4389"
ldap_server: "ldap.test.com:389"
cache_ttl: 30m
connection_timeout: 15s
client_timeout: 45s
log_json: true
`

	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Test loading YAML config with log_json setting
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		LogJSON:           false,
	}

	err = loadYAMLConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("Failed to load YAML config: %v", err)
	}

	if !config.LogJSON {
		t.Error("Expected LogJSON to be true from YAML")
	}

	if config.ProxyAddr != ":4389" {
		t.Errorf("Expected proxy addr :4389, got %s", config.ProxyAddr)
	}
}

func TestYAMLConfigWithLogFile(t *testing.T) {
	// Create a temporary YAML config file with log_file setting
	yamlContent := `proxy_addr: ":4389"
ldap_server: "ldap.test.com:389"
cache_ttl: 30m
connection_timeout: 15s
client_timeout: 45s
log_file: "/var/log/ldap-proxy.log"
`

	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Test loading YAML config with log_file setting
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		LogFile:           "",
	}

	err = loadYAMLConfig(tmpFile.Name(), config)
	if err != nil {
		t.Fatalf("Failed to load YAML config: %v", err)
	}

	if config.LogFile != "/var/log/ldap-proxy.log" {
		t.Errorf("Expected LogFile to be '/var/log/ldap-proxy.log' from YAML, got %s", config.LogFile)
	}

	if config.ProxyAddr != ":4389" {
		t.Errorf("Expected proxy addr :4389, got %s", config.ProxyAddr)
	}
}

func TestLogFileConfig(t *testing.T) {
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		LogFile:           "/var/log/test.log",
	}

	if config.LogFile != "/var/log/test.log" {
		t.Errorf("Expected LogFile to be '/var/log/test.log', got %s", config.LogFile)
	}

	// Test default value
	config2 := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		LogFile:           "",
	}

	if config2.LogFile != "" {
		t.Errorf("Expected LogFile to be empty by default, got %s", config2.LogFile)
	}
}

func TestInitLoggerWithFile(t *testing.T) {
	// Test creating logger with file output
	tmpFile, err := os.CreateTemp("", "test-log-*.log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	logger, cleanup, err := InitLogger(false, tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create logger with file: %v", err)
	}
	defer cleanup()

	// Write a test log
	logger.Info().Msg("Test log message")

	// Verify the log was written to file
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Expected log file to contain content")
	}
}

func TestInitLoggerStdout(t *testing.T) {
	// Test creating logger with stdout (default)
	logger, cleanup, err := InitLogger(false, "")
	if err != nil {
		t.Fatalf("Failed to create logger with stdout: %v", err)
	}
	defer cleanup()

	// Just verify that logger was created successfully
	logger.Info().Msg("Test log message to stdout")
}
