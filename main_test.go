package main

import (
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
		ProxyAddr:  ":3389",
		LDAPServer: "localhost:389",
		CacheTTL:   15 * time.Minute,
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
}
