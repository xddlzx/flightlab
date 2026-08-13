package scenario

// Event represents one structured FlightSim output message.
type Event struct {
	Time    string `json:"time"`
	Module  string `json:"module"`
	Type    string `json:"type"`
	Message string `json:"message"`
}
