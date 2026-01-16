package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
)

// InitLogger initializes the global logger based on the configuration
// Returns a zerolog.Logger instance configured for either JSON or console output
// If logFile is specified, logs are written to that file; otherwise, logs go to stdout
// Returns a cleanup function that should be called when done (e.g., defer cleanup())
func InitLogger(logJSON bool, logFile string) (zerolog.Logger, func(), error) {
	var writer io.Writer
	cleanup := func() {} // Default no-op cleanup

	// Determine output destination
	if logFile != "" {
		// Open log file for writing (create if not exists, append to existing)
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return zerolog.Logger{}, cleanup, err
		}
		writer = file
		// Return cleanup function to close the file
		// Note: We write errors to stderr since we can't use the logger during cleanup
		cleanup = func() {
			if err := file.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Error closing log file: %v\n", err)
			}
		}
	} else {
		writer = os.Stdout
	}

	if logJSON {
		// JSON output
		return zerolog.New(writer).With().Timestamp().Logger(), cleanup, nil
	}
	// Console output with human-readable format
	return zerolog.New(zerolog.ConsoleWriter{Out: writer, TimeFormat: "15:04:05"}).With().Timestamp().Logger(), cleanup, nil
}
