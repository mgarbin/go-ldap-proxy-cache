package main

import (
	"fmt"
	"os"
)

func main() {
	config := LoadConfig()

	// Initialize logger based on configuration
	logger, cleanup, err := InitLogger(config.LogJSON, config.LogFile)
	if err != nil {
		// If we can't initialize the logger, print to stderr and exit
		// We use fmt.Fprintf instead of logger since logger initialization failed
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer cleanup() // Ensure log file is closed on exit

	logger.Info().Str("config", config.String()).Msg("Starting LDAP proxy")

	proxy, err := NewLDAPProxy(config, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create proxy")
	}

	if err := proxy.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start proxy")
	}
}
