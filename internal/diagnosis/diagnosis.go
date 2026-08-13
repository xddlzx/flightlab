package diagnosis

import "flightlab/internal/scenario"

func Analyze(
	runSuccess bool,
	metrics *scenario.DetectionMetrics,
) *scenario.DiagnosisSummary {

	// FlightSim did not complete successfully.
	//
	// If target information is available, preserve those
	// targets and classify each one as a simulation failure.
	if !runSuccess {

		summary :=
			&scenario.DiagnosisSummary{
				OverallStatus: scenario.DiagnosisSimulationFailure,

				OverallReason: "FlightSim did not complete the simulation successfully.",

				Targets: []scenario.TargetDiagnosis{},
			}

		// There may be no correlation metrics if the
		// simulation failed very early.
		if metrics == nil ||
			len(metrics.TargetResults) == 0 {

			summary.SimulationFailures = 1

			return summary
		}

		for _, target := range metrics.TargetResults {

			item :=
				scenario.TargetDiagnosis{
					Value: target.Value,
					Type:  target.Type,

					TrafficGenerated: false,

					Observed: target.Observed,
					Alerted:  target.Alerted,

					Status: scenario.DiagnosisSimulationFailure,

					Reason: "FlightSim did not complete the simulation successfully.",
				}

			summary.Targets =
				append(
					summary.Targets,
					item,
				)

			summary.SimulationFailures++
		}

		summary.Total =
			len(summary.Targets)

		return summary
	}

	// Modules without implemented correlation
	// do not currently have diagnosis information.
	if metrics == nil {
		return nil
	}
	if len(metrics.TargetResults) == 0 {
		return nil
	}
	summary :=
		&scenario.DiagnosisSummary{
			Targets: []scenario.TargetDiagnosis{},
		}

	for _, target := range metrics.TargetResults {

		item :=
			scenario.TargetDiagnosis{
				Value: target.Value,
				Type:  target.Type,

				TrafficGenerated: true,

				Observed: target.Observed,
				Alerted:  target.Alerted,
			}

		switch {

		case target.Observed &&
			target.Alerted:

			item.Status =
				scenario.DiagnosisDetected

			item.Reason =
				"Traffic was observed by the sensor and a detection alert was generated."

			summary.Detected++

		case target.Observed &&
			!target.Alerted:

			item.Status =
				scenario.DiagnosisDetectionGap

			item.Reason =
				"Traffic reached the monitoring sensor, but no detection rule triggered."

			summary.DetectionGaps++

		default:

			item.Status =
				scenario.DiagnosisTelemetryGap

			item.Reason =
				"FlightSim generated the target activity, but the monitoring sensor did not observe matching telemetry."

			summary.TelemetryGaps++
		}

		summary.Targets =
			append(
				summary.Targets,
				item,
			)
	}

	summary.Total =
		len(summary.Targets)

	// Calculate the overall diagnosis.
	switch {

	case summary.TelemetryGaps > 0:

		summary.OverallStatus =
			scenario.DiagnosisTelemetryGap

		summary.OverallReason =
			"Some generated activity was not observed by the monitoring sensor."

	case summary.DetectionGaps > 0:

		summary.OverallStatus =
			scenario.DiagnosisDetectionGap

		summary.OverallReason =
			"Some observed suspicious activity did not trigger a detection rule."

	default:

		summary.OverallStatus =
			scenario.DiagnosisDetected

		summary.OverallReason =
			"All correlated targets were observed and detected."
	}

	return summary
}
