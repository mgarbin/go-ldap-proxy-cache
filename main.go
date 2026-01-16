package main

func main() {
	config := LoadConfig()

	// Initialize logger based on configuration
	logger := InitLogger(config.LogJSON)

	logger.Info().Str("config", config.String()).Msg("Starting LDAP proxy")

	proxy, err := NewLDAPProxy(config, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create proxy")
	}

	if err := proxy.Start(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start proxy")
	}
}
