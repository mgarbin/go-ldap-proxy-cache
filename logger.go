package main

import (
	"io"
	"os"

	"github.com/rs/zerolog"
)

// InitLogger initializes the global logger based on the configuration
// Returns a zerolog.Logger instance configured for either JSON or console output
// If logFile is specified, logs are written to that file; otherwise, logs go to stdout
func InitLogger(logJSON bool, logFile string) (zerolog.Logger, error) {
	var writer io.Writer

	// Determine output destination
	if logFile != "" {
		// Open log file for writing (create if not exists, append to existing)
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return zerolog.Logger{}, err
		}
		writer = file
	} else {
		writer = os.Stdout
	}

	if logJSON {
		// JSON output
		return zerolog.New(writer).With().Timestamp().Logger(), nil
	}
	// Console output with human-readable format
	return zerolog.New(zerolog.ConsoleWriter{Out: writer, TimeFormat: "15:04:05"}).With().Timestamp().Logger(), nil
}
