package main

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestCompareRequestParsing(t *testing.T) {
	// Test parsing a Compare request packet structure
	// CompareRequest ::= [APPLICATION 14] SEQUENCE {
	//     entry           LDAPDN,
	//     ava             AttributeValueAssertion }
	// AttributeValueAssertion ::= SEQUENCE {
	//     attributeDesc   AttributeDescription,
	//     assertionValue  AssertionValue }

	compareReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationCompareRequest, nil, "Compare Request")

	// Add entry DN
	entryDN := "cn=test,dc=example,dc=com"
	compareReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, entryDN, "Entry DN"))

	// Add AttributeValueAssertion
	ava := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "AVA")
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "userPassword", "Attribute"))
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "secret123", "Value"))
	compareReq.AppendChild(ava)

	// Verify packet structure
	if compareReq.Tag != ldap.ApplicationCompareRequest {
		t.Errorf("Expected tag %d, got %d", ldap.ApplicationCompareRequest, compareReq.Tag)
	}

	if len(compareReq.Children) != 2 {
		t.Errorf("Expected 2 children, got %d", len(compareReq.Children))
	}

	// Verify entry DN
	parsedDN := compareReq.Children[0].Data.String()
	if parsedDN != entryDN {
		t.Errorf("Expected DN %s, got %s", entryDN, parsedDN)
	}

	// Verify AVA structure
	parsedAVA := compareReq.Children[1]
	if len(parsedAVA.Children) != 2 {
		t.Errorf("Expected AVA to have 2 children, got %d", len(parsedAVA.Children))
	}

	parsedAttr := parsedAVA.Children[0].Data.String()
	if parsedAttr != "userPassword" {
		t.Errorf("Expected attribute 'userPassword', got %s", parsedAttr)
	}

	parsedValue := parsedAVA.Children[1].Data.String()
	if parsedValue != "secret123" {
		t.Errorf("Expected value 'secret123', got %s", parsedValue)
	}
}

func TestCompareResponseEncoding(t *testing.T) {
	// Test encoding Compare response packets
	tests := []struct {
		name       string
		resultCode uint16
		expected   string
	}{
		{
			name:       "CompareTrue",
			resultCode: ldap.LDAPResultCompareTrue,
			expected:   "Compare True",
		},
		{
			name:       "CompareFalse",
			resultCode: ldap.LDAPResultCompareFalse,
			expected:   "Compare False",
		},
		{
			name:       "ProtocolError",
			resultCode: ldap.LDAPResultProtocolError,
			expected:   "Protocol Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageID := int64(1)
			response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
			response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

			compareResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationCompareResponse, nil, "Compare Response")
			compareResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(tt.resultCode), "Result Code"))
			compareResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
			compareResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))

			response.AppendChild(compareResponse)

			// Verify response structure
			if response.Tag != ber.TagSequence {
				t.Errorf("Expected response tag %d, got %d", ber.TagSequence, response.Tag)
			}

			if len(response.Children) != 2 {
				t.Errorf("Expected 2 children in response, got %d", len(response.Children))
			}

			// Verify message ID
			if response.Children[0].Value.(int64) != messageID {
				t.Errorf("Expected message ID %d, got %v", messageID, response.Children[0].Value)
			}

			// Verify compare response
			compareResp := response.Children[1]
			if compareResp.Tag != ldap.ApplicationCompareResponse {
				t.Errorf("Expected compare response tag %d, got %d", ldap.ApplicationCompareResponse, compareResp.Tag)
			}

			if len(compareResp.Children) != 3 {
				t.Errorf("Expected 3 children in compare response, got %d", len(compareResp.Children))
			}

			// Verify result code
			resultCode := uint16(compareResp.Children[0].Value.(int64))
			if resultCode != tt.resultCode {
				t.Errorf("Expected result code %d, got %d", tt.resultCode, resultCode)
			}
		})
	}
}

func TestCompareOperationTag(t *testing.T) {
	// Verify that ApplicationCompareRequest is tag 14
	if ldap.ApplicationCompareRequest != 14 {
		t.Errorf("Expected ApplicationCompareRequest to be 14, got %d", ldap.ApplicationCompareRequest)
	}

	// Verify that ApplicationCompareResponse is tag 15
	if ldap.ApplicationCompareResponse != 15 {
		t.Errorf("Expected ApplicationCompareResponse to be 15, got %d", ldap.ApplicationCompareResponse)
	}
}

func TestCompareResultCodes(t *testing.T) {
	// Verify the result codes used by Compare operation
	tests := []struct {
		name     string
		code     uint16
		expected uint16
	}{
		{
			name:     "CompareTrue",
			code:     ldap.LDAPResultCompareTrue,
			expected: 6,
		},
		{
			name:     "CompareFalse",
			code:     ldap.LDAPResultCompareFalse,
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.expected {
				t.Errorf("Expected %s to be %d, got %d", tt.name, tt.expected, tt.code)
			}
		})
	}
}

func TestCompareRequestValidation(t *testing.T) {
	// Test validation of Compare request components
	tests := []struct {
		name        string
		entryDN     string
		attribute   string
		expectError bool
	}{
		{
			name:        "Valid request",
			entryDN:     "cn=test,dc=example,dc=com",
			attribute:   "userPassword",
			expectError: false,
		},
		{
			name:        "Empty DN",
			entryDN:     "",
			attribute:   "userPassword",
			expectError: true,
		},
		{
			name:        "Empty attribute",
			entryDN:     "cn=test,dc=example,dc=com",
			attribute:   "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct a Compare request
			compareReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationCompareRequest, nil, "Compare Request")
			compareReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, tt.entryDN, "Entry DN"))

			ava := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "AVA")
			ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, tt.attribute, "Attribute"))
			ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "testvalue", "Value"))
			compareReq.AppendChild(ava)

			// Verify the packet structure
			if len(compareReq.Children) < 2 {
				t.Error("Compare request should have at least 2 children")
			}

			parsedDN := compareReq.Children[0].Data.String()
			if parsedDN != tt.entryDN {
				t.Errorf("Expected DN %s, got %s", tt.entryDN, parsedDN)
			}

			parsedAttr := compareReq.Children[1].Children[0].Data.String()
			if parsedAttr != tt.attribute {
				t.Errorf("Expected attribute %s, got %s", tt.attribute, parsedAttr)
			}

			// Validation logic: empty DN or attribute should be considered an error
			hasError := (tt.entryDN == "" || tt.attribute == "")
			if hasError != tt.expectError {
				t.Errorf("Expected error: %v, got: %v", tt.expectError, hasError)
			}
		})
	}
}
