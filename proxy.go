package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const (
	// ldapPageSize defines the number of entries to fetch per page when handling
	// paginated LDAP responses from the backend server
	ldapPageSize = 1000
)

type LDAPProxy struct {
	config *Config
	cache  CacheInterface
}

type ClientState struct {
	conn net.Conn
	// backendDN and backendPwd store credentials for the backend LDAP server
	// Note: These are stored in plaintext as they're needed for each backend request.
	// In production, consider implementing credential caching with encryption at rest
	// or using a more secure credential management system.
	backendDN  string
	backendPwd string
	mu         sync.Mutex
}

func NewLDAPProxy(config *Config) *LDAPProxy {
	var cache CacheInterface

	if config.RedisEnabled {
		// Try to create Redis cache
		redisCache, err := NewRedisCache(config.RedisAddr, config.RedisPassword, config.RedisDB, config.CacheTTL)
		if err != nil {
			log.Fatalf("Failed to connect to Redis: %v", err)
		}
		cache = redisCache
		log.Printf("Using Redis cache at %s (db=%d)", config.RedisAddr, config.RedisDB)
	} else {
		// Use in-memory cache
		cache = NewCache(config.CacheTTL)
		log.Printf("Using in-memory cache")
	}

	return &LDAPProxy{
		config: config,
		cache:  cache,
	}
}

// ensureLDAPURL ensures that the server address has an LDAP protocol prefix.
// If the address already has ldap://, ldaps://, ldapi://, or cldap://, it's returned as-is.
// Otherwise, ldap:// is prepended for backward compatibility.
func ensureLDAPURL(server string) string {
	if strings.HasPrefix(server, "ldap://") ||
		strings.HasPrefix(server, "ldaps://") ||
		strings.HasPrefix(server, "ldapi://") ||
		strings.HasPrefix(server, "cldap://") {
		return server
	}
	return "ldap://" + server
}

func (p *LDAPProxy) Start() error {
	listener, err := net.Listen("tcp", p.config.ProxyAddr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}
	defer listener.Close()

	log.Printf("LDAP proxy listening on %s", p.config.ProxyAddr)
	log.Printf("Forwarding to LDAP server: %s", p.config.LDAPServer)
	log.Printf("Cache TTL: %s", p.config.CacheTTL)

	// Start cache statistics reporter
	go p.reportCacheStats()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go p.handleConnection(conn)
	}
}

func (p *LDAPProxy) reportCacheStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		hits, misses, size := p.cache.Stats()
		total := hits + misses
		hitRate := float64(0)
		if total > 0 {
			hitRate = float64(hits) / float64(total) * 100
		}
		log.Printf("Cache stats: hits=%d, misses=%d, hit_rate=%.2f%%, entries=%d", hits, misses, hitRate, size)
	}
}

func (p *LDAPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	log.Printf("New connection from %s", clientConn.RemoteAddr())

	state := &ClientState{
		conn: clientConn,
	}

	for {
		// Set deadline before blocking read operation
		if p.config.ClientTimeout > 0 {
			clientConn.SetDeadline(time.Now().Add(p.config.ClientTimeout))
		}

		packet, err := ber.ReadPacket(clientConn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Failed to read LDAP packet: %v", err)
			}
			return
		}

		if err := p.handleRequest(state, packet); err != nil {
			log.Printf("Error handling request: %v", err)
			return
		}
	}
}

func (p *LDAPProxy) handleRequest(state *ClientState, packet *ber.Packet) error {
	if len(packet.Children) < 2 {
		return fmt.Errorf("invalid LDAP message")
	}

	messageID := packet.Children[0].Value.(int64)
	protocolOp := packet.Children[1]

	switch protocolOp.Tag {
	case ldap.ApplicationBindRequest:
		return p.handleBind(state, messageID, protocolOp)
	case ldap.ApplicationSearchRequest:
		return p.handleSearch(state, messageID, protocolOp)
	case ldap.ApplicationUnbindRequest:
		return p.handleUnbind(state)
	default:
		log.Printf("Unsupported LDAP operation: tag %d", protocolOp.Tag)
		return fmt.Errorf("unsupported operation")
	}
}

func (p *LDAPProxy) handleBind(state *ClientState, messageID int64, bindReq *ber.Packet) error {
	if len(bindReq.Children) < 3 {
		return p.sendBindResponse(state, messageID, ldap.LDAPResultProtocolError)
	}

	version := bindReq.Children[0].Value.(int64)
	name := string(bindReq.Children[1].Data.String())
	password := string(bindReq.Children[2].Data.String())

	log.Printf("Bind request: version=%d, name=%s", version, name)

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: p.config.ConnectionTimeout,
	}
	ldapConn, err := ldap.DialURL(ensureLDAPURL(p.config.LDAPServer), ldap.DialWithDialer(dialer))
	if err != nil {
		log.Printf("Failed to connect to backend: %v", err)
		return p.sendBindResponse(state, messageID, ldap.LDAPResultUnavailable)
	}
	defer ldapConn.Close()

	if name == "" && password == "" {
		err = ldapConn.UnauthenticatedBind("")
		if err != nil {
			log.Printf("Anonymous bind failed: %v", err)
			return p.sendBindResponse(state, messageID, ldap.LDAPResultInvalidCredentials)
		}
		log.Printf("Anonymous bind successful")
		return p.sendBindResponse(state, messageID, ldap.LDAPResultSuccess)
	}

	err = ldapConn.Bind(name, password)
	if err != nil {
		log.Printf("Backend bind failed: %v", err)
		return p.sendBindResponse(state, messageID, ldap.LDAPResultInvalidCredentials)
	}

	state.mu.Lock()
	state.backendDN = name
	state.backendPwd = password
	state.mu.Unlock()

	log.Printf("Bind successful for: %s", name)
	return p.sendBindResponse(state, messageID, ldap.LDAPResultSuccess)
}

func (p *LDAPProxy) sendBindResponse(state *ClientState, messageID int64, resultCode uint16) error {
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	bindResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind Response")
	bindResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "Result Code"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))

	response.AppendChild(bindResponse)

	_, err := state.conn.Write(response.Bytes())
	return err
}

func (p *LDAPProxy) handleSearch(state *ClientState, messageID int64, searchReq *ber.Packet) error {
	if len(searchReq.Children) < 7 {
		return p.sendSearchDone(state, messageID, ldap.LDAPResultProtocolError)
	}

	baseDN := string(searchReq.Children[0].ByteValue)
	scope := int(searchReq.Children[1].Value.(int64))
	filterPacket := searchReq.Children[6]

	attributes := []string{}
	if len(searchReq.Children) > 7 {
		attrList := searchReq.Children[7]
		for _, attr := range attrList.Children {
			attributes = append(attributes, string(attr.ByteValue))
		}
	}

	filterStr, err := ldap.DecompileFilter(filterPacket)
	if err != nil {
		log.Printf("Failed to decompile filter: %v", err)
		return p.sendSearchDone(state, messageID, ldap.LDAPResultProtocolError)
	}

	// Generate a key for logging purposes
	reqKey := generateCacheKey(baseDN, filterStr, attributes, scope)

	if cachedData, found := p.cache.Get(baseDN, filterStr, attributes, scope); found {
		log.Printf("[%s] Cache hit for search : host=%s, base=%s, scope=%d, filter=%s", reqKey, state.conn.RemoteAddr().String(), baseDN, scope, filterStr)
		entries := cachedData.([]*ldap.Entry)
		for _, entry := range entries {
			if err := p.sendSearchEntry(state, messageID, entry); err != nil {
				return err
			}
		}
		return p.sendSearchDone(state, messageID, ldap.LDAPResultSuccess)
	}

	log.Printf("[%s] Cache miss - querying backend", reqKey)

	// Start to calculate elapsed time
	startDate := time.Now()

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: p.config.ConnectionTimeout,
	}
	ldapConn, err := ldap.DialURL(ensureLDAPURL(p.config.LDAPServer), ldap.DialWithDialer(dialer))
	if err != nil {
		log.Printf("[%s] Failed to connect to backend: %v", reqKey, err)
		return p.sendSearchDone(state, messageID, ldap.LDAPResultUnavailable)
	}
	defer ldapConn.Close()

	state.mu.Lock()
	bindDN := state.backendDN
	bindPwd := state.backendPwd
	state.mu.Unlock()

	if bindDN != "" {
		if err := ldapConn.Bind(bindDN, bindPwd); err != nil {
			log.Printf("[%s] Backend bind failed: %v", reqKey, err)
			return p.sendSearchDone(state, messageID, ldap.LDAPResultInvalidCredentials)
		}
	}

	entries, err := p.searchBackendWithPaging(ldapConn, baseDN, scope, filterStr, attributes)
	if err != nil {
		log.Printf("[%s] Backend search failed: %v", reqKey, err)
		return p.sendSearchDone(state, messageID, ldap.LDAPResultOperationsError)
	}

	// Store results in cache
	p.cache.Set(baseDN, filterStr, attributes, scope, entries)

	// End time for elapsed calculation
	endDate := time.Now()
	// Calculate the duration
	duration := endDate.Sub(startDate)
	// Convert duration to milliseconds (as an integer value)
	durationMilliseconds := duration.Milliseconds() // This gives an integer value

	log.Printf("[%s] Search request : host=%s, base=%s, scope=%d, filter=%s, elapsed=%d", reqKey, state.conn.RemoteAddr().String(), baseDN, scope, filterStr, durationMilliseconds)

	for _, entry := range entries {
		if err := p.sendSearchEntry(state, messageID, entry); err != nil {
			return err
		}
	}

	return p.sendSearchDone(state, messageID, ldap.LDAPResultSuccess)
}

func (p *LDAPProxy) searchBackendWithPaging(conn *ldap.Conn, baseDN string, scope int, filter string, attributes []string) ([]*ldap.Entry, error) {
	var allEntries []*ldap.Entry

	pagingControl := ldap.NewControlPaging(ldapPageSize)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		[]ldap.Control{pagingControl},
	)

	for {
		result, err := conn.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("search failed: %w", err)
		}

		allEntries = append(allEntries, result.Entries...)

		// Check if there are more pages to fetch
		pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			break
		}

		currentPaging, ok := pagingResult.(*ldap.ControlPaging)
		if !ok || len(currentPaging.Cookie) == 0 {
			break
		}

		// Set up the next page request with the cookie from the current page
		nextPageControl := ldap.NewControlPaging(ldapPageSize)
		nextPageControl.SetCookie(currentPaging.Cookie)
		searchRequest.Controls = []ldap.Control{nextPageControl}
	}

	log.Printf("Retrieved %d entries from backend", len(allEntries))
	return allEntries, nil
}

func (p *LDAPProxy) sendSearchEntry(state *ClientState, messageID int64, entry *ldap.Entry) error {
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	searchEntry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Search Result Entry")
	searchEntry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, entry.DN, "Object Name"))

	attrList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attr := range entry.Attributes {
		attrSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		attrSeq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr.Name, "Attribute Name"))

		valSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
		for _, val := range attr.Values {
			valSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, val, "Attribute Value"))
		}
		attrSeq.AppendChild(valSet)
		attrList.AppendChild(attrSeq)
	}
	searchEntry.AppendChild(attrList)

	response.AppendChild(searchEntry)

	_, err := state.conn.Write(response.Bytes())
	return err
}

func (p *LDAPProxy) sendSearchDone(state *ClientState, messageID int64, resultCode uint16) error {
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	searchDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, "Search Result Done")
	searchDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "Result Code"))
	searchDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	searchDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))

	response.AppendChild(searchDone)

	_, err := state.conn.Write(response.Bytes())
	return err
}

func (p *LDAPProxy) handleUnbind(state *ClientState) error {
	log.Printf("Unbind request received")
	return io.EOF
}
