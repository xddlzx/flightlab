package diagnosis

import (
	"testing"

	"flightlab/internal/scenario"
)

func TestDiagnosisClassification(
	t *testing.T,
) {

	metrics :=
		&scenario.DetectionMetrics{
			TargetResults: []scenario.TargetResult{

				{
					Value:    "detected.test",
					Type:     "dns",
					Observed: true,
					Alerted:  true,
				},

				{
					Value:    "gap.test",
					Type:     "dns",
					Observed: true,
					Alerted:  false,
				},

				{
					Value:    "missing.test",
					Type:     "dns",
					Observed: false,
					Alerted:  false,
				},
			},
		}

	result :=
		Analyze(
			true,
			metrics,
		)

	if result.Total != 3 {
		t.Fatalf(
			"expected 3 targets, got %d",
			result.Total,
		)
	}

	if result.Detected != 1 {
		t.Fatalf(
			"expected 1 detected target",
		)
	}

	if result.DetectionGaps != 1 {
		t.Fatalf(
			"expected 1 detection gap",
		)
	}

	if result.TelemetryGaps != 1 {
		t.Fatalf(
			"expected 1 telemetry gap",
		)
	}
}

func TestSimulationFailure(
	t *testing.T,
) {

	metrics :=
		&scenario.DetectionMetrics{
			TargetResults: []scenario.TargetResult{
				{
					Value: "test.invalid",
					Type:  "dns",
				},
			},
		}

	result :=
		Analyze(
			false,
			metrics,
		)

	if result.SimulationFailures != 1 {
		t.Fatalf(
			"expected simulation failure",
		)
	}

	if result.Targets[0].Status !=
		scenario.DiagnosisSimulationFailure {

		t.Fatalf(
			"unexpected status %q",
			result.Targets[0].Status,
		)
	}
}
