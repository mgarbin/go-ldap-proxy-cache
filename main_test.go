package main

import (
	"os"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	cache := NewCache(100 * time.Millisecond)

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
	cache := NewCache(time.Minute)

	baseDN1 := "dc=example,dc=com"
	filter1 := "(uid=test)"
	attributes1 := []string{"cn", "mail"}
	scope1 := 2

	key1 := cache.generateKey(baseDN1, filter1, attributes1, scope1)
	key2 := cache.generateKey(baseDN1, filter1, attributes1, scope1)

	if key1 != key2 {
		t.Error("Same parameters should generate same key")
	}

	// Different filter should generate different key
	key3 := cache.generateKey(baseDN1, "(uid=other)", attributes1, scope1)
	if key1 == key3 {
		t.Error("Different filters should generate different keys")
	}

	// Different attributes should generate different key
	key4 := cache.generateKey(baseDN1, filter1, []string{"cn"}, scope1)
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
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
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
