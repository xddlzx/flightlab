package scenario

// DetectionMetrics describes how FlightSim targets
// appeared in Suricata output.
type DetectionMetrics struct {
	TargetsTotal    int `json:"targets_total"`
	TargetsObserved int `json:"targets_observed"`
	TargetsAlerted  int `json:"targets_alerted"`

	VisibilityRate float64 `json:"visibility_rate"`
	DetectionRate  float64 `json:"detection_rate"`

	ObservedTargets []string       `json:"observed_targets"`
	TargetResults   []TargetResult `json:"target_results,omitempty"`
	AlertedTargets  []string       `json:"alerted_targets"`
}

type TargetResult struct {
	Value    string `json:"value"`
	Type     string `json:"type"`
	Observed bool   `json:"observed"`
	Alerted  bool   `json:"alerted"`
}
