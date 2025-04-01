// config.go
// This file handles configuration and input validation for DeepPacketAI.
// Core functionalities:
// - Processes command line arguments
// - Validates time ranges for packet filtering
// - Handles compressed pcap files
//
// Example configurations:
// 1. Time Range Analysis:
//    --start "15:04:05" --end "15:05:00"
//    Analyzes packets within specified timeframe
//
// 2. Compressed File Processing:
//    input.pcap.gz -> input.pcap
//    Automatically extracts compressed captures

package config

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type UserInput struct {
	Files     []string
	StartTime time.Time
	EndTime   time.Time
	Prompt    string
	Url       string
	Model     string
}

var Input UserInput

func HandleUserInput() {
	filesArg := flag.String("i", "", "Comma-separated list of pcap files to process")
	dirArg := flag.String("d", "", "Directory containing pcap files")
	startTime := flag.String("start-time", "", "Start time in HH:MM or HH:MM:SS format")
	endTime := flag.String("end-time", "", "Start time in HH:MM or HH:MM:SS format")
	flag.StringVar(&Input.Prompt, "p", "", "Prompt string")
	flag.StringVar(&Input.Url, "u", "", "Url where AI model is running e.g., https://ollama.run.app/api/chat or http://localhost:11434/api/chat")
	flag.StringVar(&Input.Model, "m", "", "Name of Ollama AI Model e.g., gemma2:2b, mistral etc.")

	flag.Parse()

	// Process -i option (multiple files)
	if *filesArg != "" {
		for _, file := range strings.Split(*filesArg, ",") {
			Input.Files = append(Input.Files, strings.TrimSpace(file))
		}
	}

	// Process -d option (directory)
	if *dirArg != "" {
		files, err := os.ReadDir(*dirArg)
		if err != nil {
			log.Fatalf("Error reading directory: %v", err)
		}
		for _, file := range files {
			if !file.IsDir() && (strings.HasSuffix(file.Name(), ".pcap") || strings.HasSuffix(file.Name(), ".pcapng")) {
				Input.Files = append(Input.Files, filepath.Join(*dirArg, file.Name()))
			}
		}
	}

	validateTime(startTime, endTime)
}

func SaveDirectoryFiles(dirArg *string) {
	if *dirArg != "" {
		files, err := os.ReadDir(*dirArg)
		if err != nil {
			log.Fatalf("Error reading directory: %v", err)
		}
		for _, file := range files {
			if !file.IsDir() && (strings.HasSuffix(file.Name(), ".pcap") || strings.HasSuffix(file.Name(), ".pcapng")) {
				Input.Files = append(Input.Files, filepath.Join(*dirArg, file.Name()))
			}
		}
	}
}

// validateTime ensures time parameters are properly formatted
// Parameters:
// - startTime: Beginning of analysis period (HH:MM:SS)
// - endTime: End of analysis period (HH:MM:SS)
func validateTime(startTime, endTime *string) {
	// Validate start time format if provided
	// Accepts HH:MM or HH:MM:SS
	if *startTime != "" && !isTimeValid(*startTime) {
		fmt.Println("Invalid start time format. Please use HH:MM or HH:MM:SS.")
		os.Exit(1)
	}

	// Validate end time format if provided
	// Accepts HH:MM or HH:MM:SS
	if *endTime != "" && !isTimeValid(*endTime) {
		fmt.Println("Invalid start time format. Please use HH:MM or HH:MM:SS.")
		os.Exit(1)
	}

	var err error
	// Parse and store start time if provided
	// Converts string time to time.Time
	if *startTime != "" {
		Input.StartTime, err = parseTime(*startTime)
		if err != nil {
			fmt.Println("Error parsing start time:", err)
			os.Exit(1)
		}
	}

	// Parse and store end time if provided
	// Converts string time to time.Time
	if *endTime != "" {
		Input.EndTime, err = parseTime(*endTime)
		if err != nil {
			fmt.Println("Error parsing end time:", err)
			os.Exit(1)
		}
	}
}

// parseTime converts string time to time.Time
// Parameters:
// - timeStr: Time string in various formats
// Returns:
// - Parsed time.Time value
// - Error if parsing fails
func parseTime(timeStr string) (time.Time, error) {
	// Try parsing as RFC3339 format first
	// Example: 2024-03-20T15:04:05Z
	t, err := time.Parse(time.RFC3339, timeStr)
	if err == nil {
		return t, nil
	}

	timeFormats := []string{"15:04", "15:04:05"}
	for _, format := range timeFormats {
		t, err = time.Parse(format, timeStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time format")
}

// isTimeValid checks if a time string matches required format
// Parameters:
// - timeStr: Time string to validate
// Returns:
// - true if format is valid (HH:MM or HH:MM:SS)
// - false otherwise
func isTimeValid(timeStr string) bool {
	// Regular expression for time format validation
	// Matches both HH:MM and HH:MM:SS
	timeRegex := regexp.MustCompile(`^([0-1][0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$`)
	return timeRegex.MatchString(timeStr)
}
