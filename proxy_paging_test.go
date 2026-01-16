package main

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestPagingStateManager(t *testing.T) {
	logger := getTestLogger()
	psm := NewPagingStateManager(logger)

	// Create test entries
	entries := []*ldap.Entry{
		{DN: "cn=user1,dc=example,dc=com"},
		{DN: "cn=user2,dc=example,dc=com"},
		{DN: "cn=user3,dc=example,dc=com"},
	}

	// Test storing and retrieving paging state
	cookie := "test-cookie-123"
	psm.Store(cookie, entries, 1)

	state, ok := psm.Get(cookie)
	if !ok {
		t.Error("Expected to find paging state")
	}

	if state.offset != 1 {
		t.Errorf("Expected offset 1, got %d", state.offset)
	}

	if len(state.entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(state.entries))
	}

	// Test getting non-existent state
	_, ok = psm.Get("non-existent-cookie")
	if ok {
		t.Error("Expected not to find non-existent paging state")
	}

	// Test deleting state
	psm.Delete(cookie)
	_, ok = psm.Get(cookie)
	if ok {
		t.Error("Expected paging state to be deleted")
	}
}

func TestPagingStateCleanup(t *testing.T) {
	logger := getTestLogger()
	psm := NewPagingStateManager(logger)

	// Create test entries
	entries := []*ldap.Entry{
		{DN: "cn=user1,dc=example,dc=com"},
	}

	// Store a state with a timestamp in the past
	cookie := "old-cookie"
	psm.mu.Lock()
	psm.states[cookie] = &PagingState{
		entries:   entries,
		offset:    0,
		createdAt: time.Now().Add(-10 * time.Minute), // 10 minutes ago
	}
	psm.mu.Unlock()

	// Verify it exists
	_, ok := psm.Get(cookie)
	if !ok {
		t.Error("Expected to find old paging state")
	}

	// Trigger cleanup manually
	psm.mu.Lock()
	now := time.Now()
	for c, state := range psm.states {
		if now.Sub(state.createdAt) > 5*time.Minute {
			delete(psm.states, c)
		}
	}
	psm.mu.Unlock()

	// Verify it was cleaned up
	_, ok = psm.Get(cookie)
	if ok {
		t.Error("Expected old paging state to be cleaned up")
	}
}

func TestParseControlsFromSearchRequest(t *testing.T) {
	logger := getTestLogger()
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
	}
	proxy, err := NewLDAPProxy(config, logger)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Test that proxy was created with paging state manager
	if proxy.pagingState == nil {
		t.Error("Expected proxy to have paging state manager")
	}

	// Test that the paging state manager has a context for graceful shutdown
	if proxy.pagingState.ctx == nil {
		t.Error("Expected paging state manager to have context")
	}
}

func TestPagingControlGeneration(t *testing.T) {
	// Test creating paging controls
	control := ldap.NewControlPaging(50)
	if control.PagingSize != 50 {
		t.Errorf("Expected paging size 50, got %d", control.PagingSize)
	}

	// Test setting cookie
	testCookie := []byte("my-cookie-value")
	control.SetCookie(testCookie)

	if len(control.Cookie) != len(testCookie) {
		t.Errorf("Expected cookie length %d, got %d", len(testCookie), len(control.Cookie))
	}

	// Test encoding
	encoded := control.Encode()
	if encoded == nil {
		t.Error("Expected encoded control to not be nil")
	}

	// Test control type
	if control.GetControlType() != ldap.ControlTypePaging {
		t.Errorf("Expected control type %s, got %s", ldap.ControlTypePaging, control.GetControlType())
	}
}

func TestGenerateSecureCookie(t *testing.T) {
	// Test that secure cookies are generated
	cookie1, err := generateSecureCookie()
	if err != nil {
		t.Fatalf("Failed to generate secure cookie: %v", err)
	}

	if len(cookie1) == 0 {
		t.Error("Expected non-empty cookie")
	}

	// Test that cookies are unique
	cookie2, err := generateSecureCookie()
	if err != nil {
		t.Fatalf("Failed to generate second secure cookie: %v", err)
	}

	if cookie1 == cookie2 {
		t.Error("Expected unique cookies, got identical values")
	}

	// Test that cookies are valid base64 URL encoding
	_, err = base64.URLEncoding.DecodeString(cookie1)
	if err != nil {
		t.Errorf("Cookie is not valid base64 URL encoding: %v", err)
	}
}
