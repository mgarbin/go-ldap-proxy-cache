package main

// NoOpCache is a cache implementation that does nothing.
// It always returns cache misses and doesn't store any data.
// This is used when caching is disabled via configuration.
type NoOpCache struct{}

// NewNoOpCache creates a new no-op cache
func NewNoOpCache() *NoOpCache {
	return &NoOpCache{}
}

// Get always returns a cache miss
func (nc *NoOpCache) Get(baseDN, filter string, attributes []string, scope int) (interface{}, bool) {
	return nil, false
}

// Set does nothing
func (nc *NoOpCache) Set(baseDN, filter string, attributes []string, scope int, data interface{}) {
	// Intentionally empty - no caching
}

// Stats returns zero values
func (nc *NoOpCache) Stats() (hits, misses uint64, size int) {
	return 0, 0, 0
}

// Close is a no-op for NoOpCache
func (nc *NoOpCache) Close() error {
	return nil
}
