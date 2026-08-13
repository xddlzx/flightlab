package scenario

import "time"

type DiagnosisStatus string

const (
	DiagnosisDetected DiagnosisStatus = "detected"

	DiagnosisDetectionGap DiagnosisStatus = "detection_gap"

	DiagnosisTelemetryGap DiagnosisStatus = "telemetry_gap"

	DiagnosisSimulationFailure DiagnosisStatus = "simulation_failure"
)

type TargetDiagnosis struct {
	Value string `json:"value"`
	Type  string `json:"type"`

	TrafficGenerated bool `json:"traffic_generated"`
	Observed         bool `json:"observed"`
	Alerted          bool `json:"alerted"`

	Status DiagnosisStatus `json:"status"`
	Reason string          `json:"reason"`
}

type DiagnosisSummary struct {
	Total int `json:"total"`

	Detected           int `json:"detected"`
	DetectionGaps      int `json:"detection_gaps"`
	TelemetryGaps      int `json:"telemetry_gaps"`
	SimulationFailures int `json:"simulation_failures"`

	OverallStatus DiagnosisStatus `json:"overall_status"`
	OverallReason string          `json:"overall_reason"`

	Targets []TargetDiagnosis `json:"targets"`
}

type Result struct {
	ID         string        `json:"id"`
	Config     Config        `json:"config"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Duration   time.Duration `json:"duration"`
	Success    bool          `json:"success"`

	Output string  `json:"output"`
	Events []Event `json:"events"`

	CapturePath     string `json:"capture_path,omitempty"`
	CaptureTempPath string `json:"-"`

	SuricataPath        string          `json:"suricata_path,omitempty"`
	SuricataEventCounts map[string]int  `json:"suricata_event_counts,omitempty"`
	SuricataAlerts      []SuricataAlert `json:"suricata_alerts,omitempty"`
	SuricataAlertCount  int             `json:"suricata_alert_count"`

	SuricataTempPath string `json:"-"`
	SuricataTempDir  string `json:"-"`

	Metrics *DetectionMetrics `json:"metrics,omitempty"`

	AnalysisError string `json:"analysis_error,omitempty"`

	Diagnosis *DiagnosisSummary `json:"diagnosis,omitempty"`

	C2LibraryPath string `json:"c2_library_path,omitempty"`
}
