package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog"
)

const (
	// ldapPageSize defines the number of entries to fetch per page when handling
	// paginated LDAP responses from the backend server
	ldapPageSize = 1000
)

type LDAPProxy struct {
	config      *Config
	cache       CacheInterface
	logger      zerolog.Logger
	pagingState *PagingStateManager
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

// PagingStateManager manages paging state for client queries
type PagingStateManager struct {
	states map[string]*PagingState
	mu     sync.RWMutex
	logger zerolog.Logger
	ctx    context.Context
	cancel context.CancelFunc
}

// PagingState stores the state for a paged query
type PagingState struct {
	entries   []*ldap.Entry
	offset    int
	createdAt time.Time
}

// NewPagingStateManager creates a new paging state manager
func NewPagingStateManager(logger zerolog.Logger) *PagingStateManager {
	ctx, cancel := context.WithCancel(context.Background())
	psm := &PagingStateManager{
		states: make(map[string]*PagingState),
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
	// Start cleanup goroutine to remove old paging states
	go psm.cleanupOldStates()
	return psm
}

// Stop gracefully stops the paging state manager
func (psm *PagingStateManager) Stop() {
	psm.cancel()
}

// cleanupOldStates removes paging states older than 5 minutes
func (psm *PagingStateManager) cleanupOldStates() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-psm.ctx.Done():
			return
		case <-ticker.C:
			psm.mu.Lock()
			now := time.Now()
			for cookie, state := range psm.states {
				if now.Sub(state.createdAt) > 5*time.Minute {
					delete(psm.states, cookie)
					psm.logger.Debug().Msg("Removed expired paging state")
				}
			}
			psm.mu.Unlock()
		}
	}
}

// Store saves paging state with a cookie
func (psm *PagingStateManager) Store(cookie string, entries []*ldap.Entry, offset int) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	psm.states[cookie] = &PagingState{
		entries:   entries,
		offset:    offset,
		createdAt: time.Now(),
	}
}

// Get retrieves paging state by cookie
func (psm *PagingStateManager) Get(cookie string) (*PagingState, bool) {
	psm.mu.RLock()
	defer psm.mu.RUnlock()

	state, ok := psm.states[cookie]
	return state, ok
}

// Delete removes paging state by cookie
func (psm *PagingStateManager) Delete(cookie string) {
	psm.mu.Lock()
	defer psm.mu.Unlock()

	delete(psm.states, cookie)
}

// generateSecureCookie generates a cryptographically secure random cookie
func generateSecureCookie() (string, error) {
	// Generate 32 bytes of random data
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random cookie: %w", err)
	}
	// Encode as base64 for URL-safe string
	return base64.URLEncoding.EncodeToString(randomBytes), nil
}

func NewLDAPProxy(config *Config, logger zerolog.Logger) (*LDAPProxy, error) {
	var cache CacheInterface

	if !config.CacheEnabled {
		// Cache is completely disabled
		cache = NewNoOpCache()
		logger.Info().Msg("Cache system is disabled")
	} else if config.RedisEnabled {
		// Try to create Redis cache
		redisCache, err := NewRedisCache(config.RedisAddr, config.RedisPassword, config.RedisDB, config.CacheTTL, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Redis: %w", err)
		}
		cache = redisCache
		logger.Info().Str("addr", config.RedisAddr).Int("db", config.RedisDB).Msg("Using Redis cache")
	} else {
		// Use in-memory cache
		cache = NewCache(config.CacheTTL, logger)
		logger.Info().Msg("Using in-memory cache")
	}

	return &LDAPProxy{
		config:      config,
		cache:       cache,
		logger:      logger,
		pagingState: NewPagingStateManager(logger),
	}, nil
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

	p.logger.Info().Str("proxy_addr", p.config.ProxyAddr).Msg("LDAP proxy listening")
	p.logger.Info().Str("ldap_server", p.config.LDAPServer).Msg("Forwarding to LDAP server")
	p.logger.Info().Dur("cache_ttl", p.config.CacheTTL).Msg("Cache TTL configured")

	// Start cache statistics reporter
	go p.reportCacheStats()

	for {
		conn, err := listener.Accept()
		if err != nil {
			p.logger.Error().Err(err).Msg("Failed to accept connection")
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
		p.logger.Info().
			Uint64("hits", hits).
			Uint64("misses", misses).
			Float64("hit_rate", hitRate).
			Int("entries", size).
			Msg("Cache stats")
	}
}

func (p *LDAPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	p.logger.Info().Str("remote_addr", clientConn.RemoteAddr().String()).Msg("New connection")

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
				p.logger.Error().Err(err).Msg("Failed to read LDAP packet")
			}
			return
		}

		if err := p.handleRequest(state, packet); err != nil {
			p.logger.Error().Err(err).Msg("Error handling request")
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
	case ldap.ApplicationCompareRequest:
		return p.handleCompare(state, messageID, protocolOp)
	default:
		p.logger.Warn().Int("tag", int(protocolOp.Tag)).Msg("Unsupported LDAP operation")
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

	p.logger.Info().Int64("version", version).Str("name", name).Msg("Bind request")

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: p.config.ConnectionTimeout,
	}
	ldapConn, err := ldap.DialURL(ensureLDAPURL(p.config.LDAPServer), ldap.DialWithDialer(dialer))
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed to connect to backend")
		return p.sendBindResponse(state, messageID, ldap.LDAPResultUnavailable)
	}
	defer ldapConn.Close()

	if name == "" && password == "" {
		err = ldapConn.UnauthenticatedBind("")
		if err != nil {
			p.logger.Error().Err(err).Msg("Anonymous bind failed")
			return p.sendBindResponse(state, messageID, ldap.LDAPResultInvalidCredentials)
		}
		p.logger.Info().Msg("Anonymous bind successful")
		return p.sendBindResponse(state, messageID, ldap.LDAPResultSuccess)
	}

	err = ldapConn.Bind(name, password)
	if err != nil {
		p.logger.Error().Err(err).Msg("Backend bind failed")
		return p.sendBindResponse(state, messageID, ldap.LDAPResultInvalidCredentials)
	}

	state.mu.Lock()
	state.backendDN = name
	state.backendPwd = password
	state.mu.Unlock()

	p.logger.Info().Str("name", name).Msg("Bind successful")
	return p.sendBindResponse(state, messageID, ldap.LDAPResultSuccess)
}

// parseControlsFromSearchRequest extracts controls from LDAP search request packet
func (p *LDAPProxy) parseControlsFromSearchRequest(searchReq *ber.Packet) []ldap.Control {
	var controls []ldap.Control

	// Controls are optional and appear as the 9th child (index 8) if present
	if len(searchReq.Children) > 8 {
		controlsPacket := searchReq.Children[8]
		
		// Controls are context-specific class with tag 0
		// In LDAP messages, controls are wrapped in a context tag
		if controlsPacket.ClassType == ber.ClassContext && controlsPacket.Tag == 0 {
			for _, ctrlPacket := range controlsPacket.Children {
				if ctrl, err := ldap.DecodeControl(ctrlPacket); err == nil {
					controls = append(controls, ctrl)
				}
			}
		}
	}

	return controls
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

	// Calculate request bytes from the search request packet
	requestBytes := len(searchReq.Bytes())

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
		p.logger.Error().Err(err).Msg("Failed to decompile filter")
		return p.sendSearchDone(state, messageID, ldap.LDAPResultProtocolError)
	}

	// Parse controls from the search request
	controls := p.parseControlsFromSearchRequest(searchReq)
	
	// Check if client requested paging
	var clientPagingControl *ldap.ControlPaging
	for _, ctrl := range controls {
		if ctrl.GetControlType() == ldap.ControlTypePaging {
			if pc, ok := ctrl.(*ldap.ControlPaging); ok {
				clientPagingControl = pc
				break
			}
		}
	}

	// Generate a key for logging purposes
	reqKey := generateCacheKey(baseDN, filterStr, attributes, scope)
	
	// Get all entries (from cache or backend)
	var allEntries []*ldap.Entry
	var fromCache bool

	if cachedData, found := p.cache.Get(baseDN, filterStr, attributes, scope); found {
		allEntries = cachedData.([]*ldap.Entry)
		fromCache = true
	} else {
		if p.config.CacheEnabled {
			p.logger.Info().Str("key", reqKey).Msg("Cache miss - querying backend")
		}

		// Start to calculate elapsed time
		startDate := time.Now()

		// Create dialer with timeout
		dialer := &net.Dialer{
			Timeout: p.config.ConnectionTimeout,
		}
		ldapConn, err := ldap.DialURL(ensureLDAPURL(p.config.LDAPServer), ldap.DialWithDialer(dialer))
		if err != nil {
			p.logger.Error().Err(err).Str("key", reqKey).Msg("Failed to connect to backend")
			return p.sendSearchDone(state, messageID, ldap.LDAPResultUnavailable)
		}
		defer ldapConn.Close()

		state.mu.Lock()
		bindDN := state.backendDN
		bindPwd := state.backendPwd
		state.mu.Unlock()

		if bindDN != "" {
			if err := ldapConn.Bind(bindDN, bindPwd); err != nil {
				p.logger.Error().Err(err).Str("key", reqKey).Msg("Backend bind failed")
				return p.sendSearchDone(state, messageID, ldap.LDAPResultInvalidCredentials)
			}
		}

		allEntries, err = p.searchBackendWithPaging(ldapConn, baseDN, scope, filterStr, attributes)
		if err != nil {
			p.logger.Error().Err(err).Str("key", reqKey).Msg("Backend search failed")
			return p.sendSearchDone(state, messageID, ldap.LDAPResultOperationsError)
		}

		// Store results in cache
		p.cache.Set(baseDN, filterStr, attributes, scope, allEntries)

		// End time for elapsed calculation
		endDate := time.Now()
		duration := endDate.Sub(startDate)
		durationMilliseconds := duration.Milliseconds()

		p.logger.Debug().
			Str("key", reqKey).
			Int("total_entries", len(allEntries)).
			Int64("elapsed_ms", durationMilliseconds).
			Msg("Retrieved entries from backend")
	}

	// Now handle paging if client requested it
	var entriesToSend []*ldap.Entry
	var responseControl *ldap.ControlPaging

	if clientPagingControl != nil {
		// Client wants paged results
		pageSize := int(clientPagingControl.PagingSize)
		
		var startOffset int
		
		// Check if this is a continuation of a previous paged search
		if len(clientPagingControl.Cookie) > 0 {
			cookieStr := string(clientPagingControl.Cookie)
			if pagingState, ok := p.pagingState.Get(cookieStr); ok {
				startOffset = pagingState.offset
				allEntries = pagingState.entries
			} else {
				// Cookie is invalid or expired - log without exposing the actual cookie value
				p.logger.Warn().Msg("Invalid or expired paging cookie received")
				return p.sendSearchDone(state, messageID, ldap.LDAPResultOperationsError)
			}
		}
		
		// Determine entries to send for this page
		endOffset := startOffset + pageSize
		if endOffset > len(allEntries) {
			endOffset = len(allEntries)
		}
		entriesToSend = allEntries[startOffset:endOffset]
		
		// Prepare response control
		responseControl = ldap.NewControlPaging(uint32(pageSize))
		
		// If there are more results, generate a cookie
		if endOffset < len(allEntries) {
			// Generate a cryptographically secure random cookie
			cookie, err := generateSecureCookie()
			if err != nil {
				p.logger.Error().Err(err).Msg("Failed to generate paging cookie")
				return p.sendSearchDone(state, messageID, ldap.LDAPResultOperationsError)
			}
			responseControl.SetCookie([]byte(cookie))
			
			// Store the paging state
			p.pagingState.Store(cookie, allEntries, endOffset)
			
			p.logger.Debug().
				Int("offset", endOffset).
				Int("total", len(allEntries)).
				Msg("Created paging cookie")
		} else {
			// No more results, send empty cookie
			responseControl.SetCookie([]byte{})
			
			// Clean up any previous paging state
			if len(clientPagingControl.Cookie) > 0 {
				p.pagingState.Delete(string(clientPagingControl.Cookie))
			}
		}
	} else {
		// Client didn't request paging, send all entries
		entriesToSend = allEntries
	}

	// Send the entries
	var answerBytes int
	for _, entry := range entriesToSend {
		entryBytes, err := p.sendSearchEntryWithSize(state, messageID, entry)
		if err != nil {
			return err
		}
		answerBytes += entryBytes
	}
	
	// Send search done with control if paging was requested
	var doneBytes int
	if responseControl != nil {
		doneBytes, err = p.sendSearchDoneWithControl(state, messageID, ldap.LDAPResultSuccess, responseControl)
	} else {
		doneBytes, err = p.sendSearchDoneWithSize(state, messageID, ldap.LDAPResultSuccess)
	}
	if err != nil {
		return err
	}
	answerBytes += doneBytes

	// Log the search operation
	logEvent := p.logger.Info().
		Str("key", reqKey).
		Str("host", state.conn.RemoteAddr().String()).
		Str("base", baseDN).
		Int("scope", scope).
		Str("filter", filterStr).
		Strs("attributes", attributes).
		Int("request_bytes", requestBytes).
		Int("answer_bytes", answerBytes).
		Int("entries_sent", len(entriesToSend)).
		Int("total_entries", len(allEntries))

	if clientPagingControl != nil {
		logEvent = logEvent.Bool("paged", true).Uint32("page_size", clientPagingControl.PagingSize)
	}
	
	if fromCache {
		logEvent.Msg("Cache hit for search")
	} else {
		logEvent.Msg("Search request")
	}

	return nil
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

	p.logger.Info().Int("count", len(allEntries)).Msg("Retrieved entries from backend")
	return allEntries, nil
}

func (p *LDAPProxy) sendSearchEntry(state *ClientState, messageID int64, entry *ldap.Entry) error {
	_, err := p.sendSearchEntryWithSize(state, messageID, entry)
	return err
}

// sendSearchEntryWithSize sends a search entry response and returns the number of bytes sent
func (p *LDAPProxy) sendSearchEntryWithSize(state *ClientState, messageID int64, entry *ldap.Entry) (int, error) {
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

	responseBytes := response.Bytes()
	_, err := state.conn.Write(responseBytes)
	return len(responseBytes), err
}

func (p *LDAPProxy) sendSearchDone(state *ClientState, messageID int64, resultCode uint16) error {
	_, err := p.sendSearchDoneWithSize(state, messageID, resultCode)
	return err
}

// sendSearchDoneWithSize sends a search done response and returns the number of bytes sent
func (p *LDAPProxy) sendSearchDoneWithSize(state *ClientState, messageID int64, resultCode uint16) (int, error) {
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	searchDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, "Search Result Done")
	searchDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "Result Code"))
	searchDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	searchDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))

	response.AppendChild(searchDone)

	responseBytes := response.Bytes()
	_, err := state.conn.Write(responseBytes)
	return len(responseBytes), err
}

// sendSearchDoneWithControl sends a search done response with a control and returns the number of bytes sent
func (p *LDAPProxy) sendSearchDoneWithControl(state *ClientState, messageID int64, resultCode uint16, control ldap.Control) (int, error) {
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	searchDone := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, "Search Result Done")
	searchDone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "Result Code"))
	searchDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	searchDone.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))

	response.AppendChild(searchDone)

	// Add controls if provided
	if control != nil {
		controlsPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		controlsPacket.AppendChild(control.Encode())
		response.AppendChild(controlsPacket)
	}

	responseBytes := response.Bytes()
	_, err := state.conn.Write(responseBytes)
	return len(responseBytes), err
}

func (p *LDAPProxy) handleCompare(state *ClientState, messageID int64, compareReq *ber.Packet) error {
	// CompareRequest ::= [APPLICATION 14] SEQUENCE {
	//     entry           LDAPDN,
	//     ava             AttributeValueAssertion }
	// AttributeValueAssertion ::= SEQUENCE {
	//     attributeDesc   AttributeDescription,
	//     assertionValue  AssertionValue }
	
	if len(compareReq.Children) < 2 {
		return p.sendCompareResponse(state, messageID, ldap.LDAPResultProtocolError)
	}

	entryDN := string(compareReq.Children[0].ByteValue)
	
	// The second child is the AttributeValueAssertion (AVA)
	ava := compareReq.Children[1]
	if len(ava.Children) < 2 {
		return p.sendCompareResponse(state, messageID, ldap.LDAPResultProtocolError)
	}
	
	attributeDesc := string(ava.Children[0].ByteValue)
	assertionValue := string(ava.Children[1].ByteValue)

	p.logger.Info().
		Str("entry", entryDN).
		Str("attribute", attributeDesc).
		Msg("Compare request")

	// Create dialer with timeout
	dialer := &net.Dialer{
		Timeout: p.config.ConnectionTimeout,
	}
	ldapConn, err := ldap.DialURL(ensureLDAPURL(p.config.LDAPServer), ldap.DialWithDialer(dialer))
	if err != nil {
		p.logger.Error().Err(err).Msg("Failed to connect to backend")
		return p.sendCompareResponse(state, messageID, ldap.LDAPResultUnavailable)
	}
	defer ldapConn.Close()

	// Bind to backend server with stored credentials
	state.mu.Lock()
	bindDN := state.backendDN
	bindPwd := state.backendPwd
	state.mu.Unlock()

	if bindDN != "" {
		if err := ldapConn.Bind(bindDN, bindPwd); err != nil {
			p.logger.Error().Err(err).Msg("Backend bind failed")
			return p.sendCompareResponse(state, messageID, ldap.LDAPResultInvalidCredentials)
		}
	}

	// Perform compare operation on backend
	result, err := ldapConn.Compare(entryDN, attributeDesc, assertionValue)
	if err != nil {
		// Check if it's an LDAP error with a specific result code
		if ldapErr, ok := err.(*ldap.Error); ok {
			p.logger.Error().Err(err).Uint16("result_code", ldapErr.ResultCode).Msg("Backend compare failed")
			return p.sendCompareResponse(state, messageID, ldapErr.ResultCode)
		}
		p.logger.Error().Err(err).Msg("Backend compare failed")
		return p.sendCompareResponse(state, messageID, ldap.LDAPResultOperationsError)
	}

	// Determine the result code based on compare result
	var resultCode uint16
	if result {
		resultCode = ldap.LDAPResultCompareTrue
		p.logger.Info().
			Str("entry", entryDN).
			Str("attribute", attributeDesc).
			Msg("Compare result: TRUE")
	} else {
		resultCode = ldap.LDAPResultCompareFalse
		p.logger.Info().
			Str("entry", entryDN).
			Str("attribute", attributeDesc).
			Msg("Compare result: FALSE")
	}

	return p.sendCompareResponse(state, messageID, resultCode)
}

func (p *LDAPProxy) sendCompareResponse(state *ClientState, messageID int64, resultCode uint16) error {
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	compareResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationCompareResponse, nil, "Compare Response")
	compareResponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "Result Code"))
	compareResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	compareResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))

	response.AppendChild(compareResponse)

	_, err := state.conn.Write(response.Bytes())
	return err
}

func (p *LDAPProxy) handleUnbind(state *ClientState) error {
	p.logger.Info().Msg("Unbind request received")
	return io.EOF
}
