package regression

import (
	"sort"

	"flightlab/internal/scenario"
)

type TargetChange struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type Comparison struct {
	BaselineDetectionRate float64 `json:"baseline_detection_rate"`
	CurrentDetectionRate  float64 `json:"current_detection_rate"`

	DetectionRateChange float64 `json:"detection_rate_change"`

	BaselineDetected int `json:"baseline_detected"`
	CurrentDetected  int `json:"current_detected"`

	NewlyDetected []TargetChange `json:"newly_detected"`
	Regressions   []TargetChange `json:"regressions"`

	Improved  bool `json:"improved"`
	Regressed bool `json:"regressed"`
}

func Compare(
	baseline *scenario.DetectionMetrics,
	current *scenario.DetectionMetrics,
) *Comparison {

	if baseline == nil ||
		current == nil {

		return nil
	}

	result := &Comparison{
		BaselineDetectionRate: baseline.DetectionRate,

		CurrentDetectionRate: current.DetectionRate,

		DetectionRateChange: current.DetectionRate -
			baseline.DetectionRate,

		BaselineDetected: baseline.TargetsAlerted,

		CurrentDetected: current.TargetsAlerted,

		NewlyDetected: []TargetChange{},

		Regressions: []TargetChange{},
	}

	baselineTargets :=
		targetMap(
			baseline.TargetResults,
		)

	currentTargets :=
		targetMap(
			current.TargetResults,
		)

	for key, currentTarget := range currentTargets {

		baselineTarget, exists :=
			baselineTargets[key]

		if !exists {
			continue
		}

		if !baselineTarget.Alerted &&
			currentTarget.Alerted {

			result.NewlyDetected =
				append(
					result.NewlyDetected,
					TargetChange{
						Value: currentTarget.Value,

						Type: currentTarget.Type,
					},
				)
		}

		if baselineTarget.Alerted &&
			!currentTarget.Alerted {

			result.Regressions =
				append(
					result.Regressions,
					TargetChange{
						Value: currentTarget.Value,

						Type: currentTarget.Type,
					},
				)
		}
	}

	sort.Slice(
		result.NewlyDetected,
		func(i, j int) bool {
			return result.NewlyDetected[i].Value <
				result.NewlyDetected[j].Value
		},
	)

	sort.Slice(
		result.Regressions,
		func(i, j int) bool {
			return result.Regressions[i].Value <
				result.Regressions[j].Value
		},
	)

	result.Improved =
		result.DetectionRateChange > 0 ||
			len(result.NewlyDetected) > 0

	result.Regressed =
		result.DetectionRateChange < 0 ||
			len(result.Regressions) > 0

	return result
}

func targetMap(
	targets []scenario.TargetResult,
) map[string]scenario.TargetResult {

	result :=
		make(
			map[string]scenario.TargetResult,
		)

	for _, target := range targets {

		key :=
			target.Type +
				":" +
				target.Value

		result[key] =
			target
	}

	return result
}
