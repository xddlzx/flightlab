package parser

import (
	"regexp"
	"strings"

	"flightlab/internal/scenario"
)

var eventPattern = regexp.MustCompile(
	`^(\d{2}:\d{2}:\d{2}) \[([^\]]+)\] (.+)$`,
)

// ParseFlightSimOutput extracts structured events
// from FlightSim terminal output.
func ParseFlightSimOutput(output string) []scenario.Event {
	var events []scenario.Event

	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		match := eventPattern.FindStringSubmatch(line)

		// Ignore non-event lines such as the FlightSim banner,
		// interface information, and goodbye message.
		if match == nil {
			continue
		}

		message := match[3]

		event := scenario.Event{
			Time:    match[1],
			Module:  match[2],
			Type:    classifyEvent(message),
			Message: message,
		}

		events = append(events, event)
	}

	return events
}

func classifyEvent(message string) string {
	switch {
	case strings.HasPrefix(message, "FATAL:"):
		return "fatal"

	case strings.HasPrefix(message, "ERROR:"):
		return "error"

	case strings.HasPrefix(message, "Done ("):
		return "completion"

	default:
		return "activity"
	}
}
