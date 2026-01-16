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
	CacheEnabled      bool          `yaml:"cache_enabled"`
	CacheTTL          time.Duration `yaml:"cache_ttl"`
	ConnectionTimeout time.Duration `yaml:"connection_timeout"`
	ClientTimeout     time.Duration `yaml:"client_timeout"`
	RedisEnabled      bool          `yaml:"redis_enabled"`
	RedisAddr         string        `yaml:"redis_addr"`
	RedisPassword     string        `yaml:"redis_password"`
	RedisDB           int           `yaml:"redis_db"`
}

func LoadConfig() *Config {
	var configFile string
	var proxyAddr string
	var ldapServer string
	var cacheTTL time.Duration
	var connectionTimeout time.Duration
	var clientTimeout time.Duration
	var redisAddr string
	var redisPassword string
	var redisDB int

	// Use pointer for bool to detect if flag was explicitly set
	cacheEnabled := flag.Bool("cache-enabled", true, "Enable cache system")
	redisEnabled := flag.Bool("redis-enabled", false, "Enable Redis cache")

	flag.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flag.StringVar(&proxyAddr, "proxy-addr", "", "Proxy listen address")
	flag.StringVar(&ldapServer, "ldap-server", "", "Backend LDAP server address")
	flag.DurationVar(&cacheTTL, "cache-ttl", 0, "Cache TTL duration")
	flag.DurationVar(&connectionTimeout, "connection-timeout", 0, "Backend connection timeout")
	flag.DurationVar(&clientTimeout, "client-timeout", 0, "Client connection timeout")
	flag.StringVar(&redisAddr, "redis-addr", "", "Redis server address")
	flag.StringVar(&redisPassword, "redis-password", "", "Redis password")
	flag.IntVar(&redisDB, "redis-db", -1, "Redis database number")

	flag.Parse()

	// Track if cache-enabled and redis-enabled were explicitly set
	cacheEnabledSet := false
	redisEnabledSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "cache-enabled" {
			cacheEnabledSet = true
		}
		if f.Name == "redis-enabled" {
			redisEnabledSet = true
		}
	})

	// Start with defaults
	config := &Config{
		ProxyAddr:         ":3389",
		LDAPServer:        "localhost:389",
		CacheEnabled:      true,
		CacheTTL:          15 * time.Minute,
		ConnectionTimeout: 10 * time.Second,
		ClientTimeout:     30 * time.Second,
		RedisEnabled:      false,
		RedisAddr:         "localhost:6379",
		RedisPassword:     "",
		RedisDB:           0,
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
	// Only override cache-enabled if it was explicitly set via CLI flag
	if cacheEnabledSet {
		config.CacheEnabled = *cacheEnabled
	}
	// Only override redis-enabled if it was explicitly set via CLI flag
	if redisEnabledSet {
		config.RedisEnabled = *redisEnabled
	}
	if redisAddr != "" {
		config.RedisAddr = redisAddr
	}
	if redisPassword != "" {
		config.RedisPassword = redisPassword
	}
	if redisDB != -1 {
		config.RedisDB = redisDB
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
	// For bool, always use YAML value (false or true)
	config.CacheEnabled = yamlConfig.CacheEnabled
	config.RedisEnabled = yamlConfig.RedisEnabled
	if yamlConfig.RedisAddr != "" {
		config.RedisAddr = yamlConfig.RedisAddr
	}
	if yamlConfig.RedisPassword != "" {
		config.RedisPassword = yamlConfig.RedisPassword
	}
	// For RedisDB, only override if Redis is enabled or value is non-zero
	// This allows explicit 0 when Redis is enabled, but keeps default when Redis is disabled
	if yamlConfig.RedisEnabled || yamlConfig.RedisDB != 0 {
		config.RedisDB = yamlConfig.RedisDB
	}

	return nil
}

func (c *Config) String() string {
	cacheInfo := "disabled"
	if c.CacheEnabled {
		if c.RedisEnabled {
			cacheInfo = fmt.Sprintf("enabled (Redis: addr=%s, db=%d, ttl=%s)", c.RedisAddr, c.RedisDB, c.CacheTTL)
		} else {
			cacheInfo = fmt.Sprintf("enabled (in-memory, ttl=%s)", c.CacheTTL)
		}
	}
	return fmt.Sprintf("ProxyAddr: %s, LDAPServer: %s, ConnectionTimeout: %s, ClientTimeout: %s, Cache: %s",
		c.ProxyAddr, c.LDAPServer, c.ConnectionTimeout, c.ClientTimeout, cacheInfo)
}
