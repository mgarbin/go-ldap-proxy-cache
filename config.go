package main

import (
	"flag"
	"fmt"
	"time"
)

type Config struct {
	ProxyAddr  string
	LDAPServer string
	CacheTTL   time.Duration
	BindDN     string
	BindPass   string
}

func LoadConfig() *Config {
	config := &Config{}

	flag.StringVar(&config.ProxyAddr, "proxy-addr", ":3389", "Proxy listen address")
	flag.StringVar(&config.LDAPServer, "ldap-server", "localhost:389", "Backend LDAP server address")
	flag.DurationVar(&config.CacheTTL, "cache-ttl", 15*time.Minute, "Cache TTL duration")
	flag.StringVar(&config.BindDN, "bind-dn", "", "LDAP bind DN")
	flag.StringVar(&config.BindPass, "bind-pass", "", "LDAP bind password")

	flag.Parse()

	return config
}

func (c *Config) String() string {
	return fmt.Sprintf("ProxyAddr: %s, LDAPServer: %s, CacheTTL: %s",
		c.ProxyAddr, c.LDAPServer, c.CacheTTL)
}
