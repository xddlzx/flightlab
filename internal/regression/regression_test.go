package regression

import (
	"testing"

	"flightlab/internal/scenario"
)

func TestDetectionImprovement(
	t *testing.T,
) {

	baseline :=
		&scenario.DetectionMetrics{
			TargetsTotal:   3,
			TargetsAlerted: 2,
			DetectionRate:  66.67,

			TargetResults: []scenario.TargetResult{
				{
					Value:    "one.test",
					Type:     "dns",
					Observed: true,
					Alerted:  true,
				},
				{
					Value:    "two.test",
					Type:     "dns",
					Observed: true,
					Alerted:  true,
				},
				{
					Value:    "three.test",
					Type:     "dns",
					Observed: true,
					Alerted:  false,
				},
			},
		}

	current :=
		&scenario.DetectionMetrics{
			TargetsTotal:   3,
			TargetsAlerted: 3,
			DetectionRate:  100,

			TargetResults: []scenario.TargetResult{
				{
					Value:    "one.test",
					Type:     "dns",
					Observed: true,
					Alerted:  true,
				},
				{
					Value:    "two.test",
					Type:     "dns",
					Observed: true,
					Alerted:  true,
				},
				{
					Value:    "three.test",
					Type:     "dns",
					Observed: true,
					Alerted:  true,
				},
			},
		}

	result :=
		Compare(
			baseline,
			current,
		)

	if result == nil {
		t.Fatal(
			"expected comparison",
		)
	}

	if len(result.NewlyDetected) != 1 {
		t.Fatalf(
			"expected 1 newly detected target, got %d",
			len(result.NewlyDetected),
		)
	}

	if result.NewlyDetected[0].Value !=
		"three.test" {

		t.Fatalf(
			"unexpected newly detected target %q",
			result.NewlyDetected[0].Value,
		)
	}

	if len(result.Regressions) != 0 {
		t.Fatalf(
			"expected no regressions",
		)
	}

	if !result.Improved {
		t.Fatal(
			"expected improved=true",
		)
	}

	if result.Regressed {
		t.Fatal(
			"expected regressed=false",
		)
	}
}

func TestDetectionRegression(
	t *testing.T,
) {

	baseline :=
		&scenario.DetectionMetrics{
			TargetsAlerted: 2,
			DetectionRate:  100,

			TargetResults: []scenario.TargetResult{
				{
					Value:   "one.test",
					Type:    "dns",
					Alerted: true,
				},
				{
					Value:   "two.test",
					Type:    "dns",
					Alerted: true,
				},
			},
		}

	current :=
		&scenario.DetectionMetrics{
			TargetsAlerted: 1,
			DetectionRate:  50,

			TargetResults: []scenario.TargetResult{
				{
					Value:   "one.test",
					Type:    "dns",
					Alerted: true,
				},
				{
					Value:   "two.test",
					Type:    "dns",
					Alerted: false,
				},
			},
		}

	result :=
		Compare(
			baseline,
			current,
		)

	if len(result.Regressions) != 1 {
		t.Fatalf(
			"expected 1 regression, got %d",
			len(result.Regressions),
		)
	}

	if result.Regressions[0].Value !=
		"two.test" {

		t.Fatalf(
			"unexpected regression target %q",
			result.Regressions[0].Value,
		)
	}

	if !result.Regressed {
		t.Fatal(
			"expected regressed=true",
		)
	}
}
