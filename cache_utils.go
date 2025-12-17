package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// generateCacheKey generates a consistent cache key based on LDAP search parameters
// This is used by all cache implementations to ensure consistent key generation
func generateCacheKey(baseDN, filter string, attributes []string, scope int) string {
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
