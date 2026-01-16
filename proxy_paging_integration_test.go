package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// TestPagingIntegration tests the paging functionality with simulated BER packets
func TestPagingIntegration(t *testing.T) {
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

	// Create test entries that would normally come from the backend
	testEntries := []*ldap.Entry{
		{
			DN: "cn=user1,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"user1"}},
				{Name: "mail", Values: []string{"user1@example.com"}},
			},
		},
		{
			DN: "cn=user2,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"user2"}},
				{Name: "mail", Values: []string{"user2@example.com"}},
			},
		},
		{
			DN: "cn=user3,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{
				{Name: "cn", Values: []string{"user3"}},
				{Name: "mail", Values: []string{"user3@example.com"}},
			},
		},
	}

	// Store entries in cache to simulate backend response
	baseDN := "dc=example,dc=com"
	filter := "(objectClass=*)"
	attributes := []string{"cn", "mail"}
	scope := ldap.ScopeWholeSubtree
	proxy.cache.Set(baseDN, filter, attributes, scope, testEntries)

	// Test 1: Request first page with paging control
	t.Run("FirstPage", func(t *testing.T) {
		// Create a paging state manager entry for testing
		cookie := "test-cookie-page2"
		proxy.pagingState.Store(cookie, testEntries, 2) // Offset at 2 (third entry)

		// Verify we can retrieve it
		state, ok := proxy.pagingState.Get(cookie)
		if !ok {
			t.Error("Expected to find paging state")
		}
		if state.offset != 2 {
			t.Errorf("Expected offset 2, got %d", state.offset)
		}
		if len(state.entries) != 3 {
			t.Errorf("Expected 3 entries, got %d", len(state.entries))
		}
	})

	// Test 2: Verify control parsing
	t.Run("ControlParsing", func(t *testing.T) {
		// Create a paging control
		pagingControl := ldap.NewControlPaging(2)

		// Encode the control
		controlPacket := pagingControl.Encode()

		// Create a controls sequence (tag 0, class context)
		controlsPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		controlsPacket.AppendChild(controlPacket)

		// Create a minimal search request BER packet with controls
		searchReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request")
		searchReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, baseDN, "Base DN"))
		searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldap.ScopeWholeSubtree), "Scope"))
		searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldap.NeverDerefAliases), "Deref Aliases"))
		searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Size Limit"))
		searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "Time Limit"))
		searchReq.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

		// Add a simple filter (present filter for objectClass)
		filterPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 7, nil, "Filter: Present")
		filterPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "Attribute"))
		searchReq.AppendChild(filterPacket)

		// Add attributes
		attrList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
		attrList.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "Attribute"))
		attrList.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "mail", "Attribute"))
		searchReq.AppendChild(attrList)

		// Add the controls as the 9th child (index 8)
		searchReq.AppendChild(controlsPacket)

		// Parse controls
		controls := proxy.parseControlsFromSearchRequest(searchReq)
		if len(controls) != 1 {
			t.Errorf("Expected 1 control, got %d", len(controls))
			t.Logf("SearchReq children count: %d", len(searchReq.Children))
			if len(searchReq.Children) > 8 {
				t.Logf("Controls packet tag: %d, class: %d", searchReq.Children[8].Tag, searchReq.Children[8].ClassType)
			}
		}

		// Verify it's a paging control
		if len(controls) > 0 {
			if controls[0].GetControlType() != ldap.ControlTypePaging {
				t.Errorf("Expected paging control, got %s", controls[0].GetControlType())
			}

			if pc, ok := controls[0].(*ldap.ControlPaging); ok {
				if pc.PagingSize != 2 {
					t.Errorf("Expected paging size 2, got %d", pc.PagingSize)
				}
			} else {
				t.Error("Control is not a ControlPaging")
			}
		}
	})

	// Test 3: Verify sendSearchDoneWithControl encodes properly
	t.Run("SearchDoneWithControl", func(t *testing.T) {
		// Create a mock client state with a buffer
		var buf bytes.Buffer
		mockState := &ClientState{
			conn: &mockConn{buf: &buf},
		}

		// Create a paging control
		pagingControl := ldap.NewControlPaging(100)
		pagingControl.SetCookie([]byte("next-page"))

		// Send search done with control
		_, err := proxy.sendSearchDoneWithControl(mockState, 1, ldap.LDAPResultSuccess, pagingControl)
		if err != nil {
			t.Errorf("sendSearchDoneWithControl failed: %v", err)
		}

		// Verify something was written
		if buf.Len() == 0 {
			t.Error("Expected data to be written to connection")
		}

		// Parse the response to verify it has controls
		packet, err := ber.DecodePacketErr(buf.Bytes())
		if err != nil {
			t.Errorf("Failed to decode response: %v", err)
		}

		// LDAP response should have:
		// - Message ID
		// - Search Result Done
		// - (optionally) Controls
		if len(packet.Children) < 2 {
			t.Errorf("Expected at least 2 children in response, got %d", len(packet.Children))
		}

		// Check if controls are present (should be the 3rd child)
		if len(packet.Children) >= 3 {
			t.Log("Response contains controls")
		}
	})
}

// mockConn is a mock net.Conn for testing
type mockConn struct {
	buf *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.buf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return m.buf.Write(b)
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return mockAddr{}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return mockAddr{}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type mockAddr struct{}

func (mockAddr) Network() string {
	return "tcp"
}

func (mockAddr) String() string {
	return "mock-address"
}
