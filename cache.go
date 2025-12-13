package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

type CacheEntry struct {
	Data      interface{}
	ExpiresAt time.Time
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	ttl     time.Duration
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
		for key, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
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
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

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
