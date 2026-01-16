package main

import (
	"github.com/rs/zerolog"
)

var logger zerolog.Logger

func main() {
	config := LoadConfig()

	// Initialize logger based on configuration
	logger = InitLogger(config.LogJSON)

	logger.Info().Msgf("Starting LDAP proxy with configuration: %s", config)

	proxy, err := NewLDAPProxy(config)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create proxy")
	}

	if err := proxy.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start proxy")
	}
}
