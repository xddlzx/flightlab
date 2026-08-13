package scenario

// DetectionAlert represents a Suricata alert
// correlated with a FlightSim-generated target.
type DetectionAlert struct {
	Timestamp   string `json:"timestamp"`
	Target      string `json:"target"`
	SourceIP    string `json:"source_ip"`
	DestIP      string `json:"dest_ip"`
	Signature   string `json:"signature"`
	SignatureID int    `json:"signature_id"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

