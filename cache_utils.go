package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	// json.Marshal with simple types (strings, slices of strings, and int) should never fail
	// If it does, this indicates a critical system issue that should be caught immediately
	jsonData, err := json.Marshal(data)
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal cache key data: %v", err))
	}
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:])
}
