package main

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger initializes the global logger based on the configuration
// Returns a zerolog.Logger instance configured for either JSON or console output
func InitLogger(logJSON bool) zerolog.Logger {
	if logJSON {
		// JSON output
		return zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
	// Console output with human-readable format
	return log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"})
}
