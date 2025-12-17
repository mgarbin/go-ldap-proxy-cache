package main

import (
	"log"
)

func main() {
	config := LoadConfig()

	log.Printf("Starting LDAP proxy with configuration: %s", config)

	proxy, err := NewLDAPProxy(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
