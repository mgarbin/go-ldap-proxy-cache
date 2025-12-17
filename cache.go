package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// CacheInterface defines the contract for cache implementations
type CacheInterface interface {
	Get(baseDN, filter string, attributes []string, scope int) (interface{}, bool)
	Set(baseDN, filter string, attributes []string, scope int, data interface{})
	Stats() (hits, misses uint64, size int)
}

type CacheEntry struct {
	Data      interface{}
	ExpiresAt time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	ttl     time.Duration
	hits    uint64
	misses  uint64
}

func NewCache(ttl time.Duration) *Cache {
	c := &Cache{
		entries: make(map[string]*CacheEntry),
		ttl:     ttl,
	}
	go c.cleanup()
	return c
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		cleaned := 0
		for key, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				delete(c.entries, key)
				cleaned++
			}
		}
		c.mu.Unlock()
		if cleaned > 0 {
			log.Printf("Cache cleanup: removed %d expired entries", cleaned)
		}
	}
}

func (c *Cache) generateKey(baseDN, filter string, attributes []string, scope int) string {
	data := struct {
		BaseDN     string
		Filter     string
		Attributes []string
		Scope      int
	}{
		BaseDN:     baseDN,
		Filter:     filter,
		Attributes: attributes,
		Scope:      scope,
	}

	// json.Marshal is safe to use here as we're only marshaling simple types
	// (strings, slices of strings, and int) which cannot fail
	jsonData, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:])
}

func (c *Cache) Get(baseDN, filter string, attributes []string, scope int) (interface{}, bool) {
	key := c.generateKey(baseDN, filter, attributes, scope)

	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		// Remove expired entry immediately to prevent memory leaks
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	atomic.AddUint64(&c.hits, 1)
	return entry.Data, true
}

func (c *Cache) Set(baseDN, filter string, attributes []string, scope int, data interface{}) {
	key := c.generateKey(baseDN, filter, attributes, scope)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &CacheEntry{
		Data:      data,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

func (c *Cache) Stats() (hits, misses uint64, size int) {
	c.mu.RLock()
	size = len(c.entries)
	c.mu.RUnlock()

	hits = atomic.LoadUint64(&c.hits)
	misses = atomic.LoadUint64(&c.misses)
	return
}
