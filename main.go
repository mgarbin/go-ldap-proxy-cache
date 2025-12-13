package main

import (
	"log"
)

func main() {
	config := LoadConfig()

	log.Printf("Starting LDAP proxy with configuration: %s", config)

	proxy := NewLDAPProxy(config)

	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
