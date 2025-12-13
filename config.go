package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ProxyAddr         string        `yaml:"proxy_addr"`
	LDAPServer        string        `yaml:"ldap_server"`
	CacheTTL          time.Duration `yaml:"cache_ttl"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	ClientTimeout     time.Duration `yaml:"client_timeout"`
}

func LoadConfig() *Config {
	var configFile string
	var proxyAddr string
	var ldapServer string
	var cacheTTL time.Duration
	var connectionTimeout time.Duration
	var clientTimeout time.Duration

	flag.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flag.StringVar(&proxyAddr, "proxy-addr", "", "Proxy listen address")
	flag.StringVar(&ldapServer, "ldap-server", "", "Backend LDAP server address")
	flag.DurationVar(&cacheTTL, "cache-ttl", 0, "Cache TTL duration")
	flag.DurationVar(&connectionTimeout, "connection-timeout", 0, "Backend connection timeout")
	flag.DurationVar(&clientTimeout, "client-timeout", 0, "Client connection timeout")

	flag.Parse()

	// Start with defaults
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
	}

	// Load YAML config if provided (overwrites defaults)
	if configFile != "" {
		if err := loadYAMLConfig(configFile, config); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}
	}

	// Override with CLI flags if explicitly set (CLI flags have highest priority)
	if proxyAddr != "" {
		config.ProxyAddr = proxyAddr
	}
	if ldapServer != "" {
		config.LDAPServer = ldapServer
	}
	if cacheTTL != 0 {
		config.CacheTTL = cacheTTL
	}
	if connectionTimeout != 0 {
		config.ConnectionTimeout = connectionTimeout
	}
	if clientTimeout != 0 {
		config.ClientTimeout = clientTimeout
	}

	return config
}

func loadYAMLConfig(filename string, config *Config) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Create a temporary struct to hold YAML values
	var yamlConfig Config
	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Override config with YAML values only if they are set
	if yamlConfig.ProxyAddr != "" {
		config.ProxyAddr = yamlConfig.ProxyAddr
	}
	if yamlConfig.LDAPServer != "" {
		config.LDAPServer = yamlConfig.LDAPServer
	}
	if yamlConfig.CacheTTL != 0 {
		config.CacheTTL = yamlConfig.CacheTTL
	}
	if yamlConfig.ConnectionTimeout != 0 {
		config.ConnectionTimeout = yamlConfig.ConnectionTimeout
	}
	if yamlConfig.ClientTimeout != 0 {
		config.ClientTimeout = yamlConfig.ClientTimeout
	}

	return nil
}

func (c *Config) String() string {
	return fmt.Sprintf("ProxyAddr: %s, LDAPServer: %s, CacheTTL: %s, ConnectionTimeout: %s, ClientTimeout: %s",
		c.ProxyAddr, c.LDAPServer, c.CacheTTL, c.ConnectionTimeout, c.ClientTimeout)
}
