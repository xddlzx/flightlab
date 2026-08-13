package regression

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"flightlab/internal/detection"
	"flightlab/internal/evidence"
	"flightlab/internal/scenario"
)

type ReanalysisResult struct {
	ID string `json:"id"`

	SourceRunID string `json:"source_run_id"`

	CreatedAt time.Time `json:"created_at"`

	CapturePath string `json:"capture_path"`

	RulesPath string `json:"rules_path,omitempty"`

	SuricataConfig string `json:"suricata_config"`

	AlertCount int `json:"alert_count"`

	BaselineMetrics *scenario.DetectionMetrics `json:"baseline_metrics"`

	CurrentMetrics *scenario.DetectionMetrics `json:"current_metrics"`

	Comparison *Comparison `json:"comparison"`

	EvePath string `json:"eve_path"`
}

// Reanalyze always reuses the packet capture belonging
// to the selected FlightLab run.
//
// Only the Suricata configuration/rules may change.
// This keeps target-level regression comparisons valid.
func Reanalyze(
	resultsDir string,
	runID string,
	rulesPath string,
) (ReanalysisResult, error) {

	var result ReanalysisResult

	// Load the baseline FlightLab run.
	baseline, err :=
		evidence.LoadRun(
			resultsDir,
			runID,
		)

	if err != nil {
		return result,
			fmt.Errorf(
				"failed to load baseline run: %w",
				err,
			)
	}

	if baseline.Metrics == nil {
		return result,
			fmt.Errorf(
				"baseline run has no detection metrics",
			)
	}

	if len(
		baseline.Metrics.TargetResults,
	) == 0 {

		return result,
			fmt.Errorf(
				"baseline run has no target-level correlation results",
			)
	}

	// Regression always uses the ORIGINAL capture
	// from this exact run.
	pcapPath :=
		filepath.Join(
			resultsDir,
			runID,
			"capture.pcap",
		)

	if _, err :=
		os.Stat(
			pcapPath,
		); err != nil {

		return result,
			fmt.Errorf(
				"baseline PCAP is unavailable: %w",
				err,
			)
	}

	analysis, err :=
		detection.AnalyzeWithSuricataOptions(
			pcapPath,
			runID+"-regression",
			detection.SuricataOptions{
				ConfigPath: detection.DefaultSuricataConfig,

				RulesPath: rulesPath,
			},
		)

	if err != nil {
		return result,
			fmt.Errorf(
				"regression Suricata analysis failed: %w",
				err,
			)
	}

	// These FlightSim events belong to this exact PCAP,
	// therefore target-level correlation is valid.
	currentMetrics, err :=
		detection.Correlate(
			baseline.Config.Module,
			baseline.Events,
			analysis.EvePath,
		)

	if err != nil {
		return result,
			fmt.Errorf(
				"failed to correlate regression analysis: %w",
				err,
			)
	}

	if currentMetrics == nil {
		return result,
			fmt.Errorf(
				"module %q does not support regression correlation",
				baseline.Config.Module,
			)
	}

	comparison :=
		Compare(
			baseline.Metrics,
			currentMetrics,
		)

	if comparison == nil {
		return result,
			fmt.Errorf(
				"failed to create regression comparison",
			)
	}

	now := time.Now()

	regressionID :=
		fmt.Sprintf(
			"regression-%s-%09d",
			now.Format(
				"20060102-150405",
			),
			now.Nanosecond(),
		)

	regressionDir :=
		filepath.Join(
			resultsDir,
			runID,
			"regressions",
			regressionID,
		)

	if err :=
		os.MkdirAll(
			regressionDir,
			0755,
		); err != nil {

		return result,
			fmt.Errorf(
				"failed to create regression evidence directory: %w",
				err,
			)
	}

	// Preserve Suricata EVE output.
	eveDestination :=
		filepath.Join(
			regressionDir,
			"suricata-eve.json",
		)

	if err :=
		copyRegressionFile(
			analysis.EvePath,
			eveDestination,
		); err != nil {

		return result,
			fmt.Errorf(
				"failed to preserve regression EVE file: %w",
				err,
			)
	}

	// A browser-uploaded rules file is temporary.
	// Preserve the exact rules used with this regression
	// so the evidence remains reproducible.
	rulesEvidencePath := ""

	if rulesPath != "" {

		rulesDestination :=
			filepath.Join(
				regressionDir,
				"rules.rules",
			)

		if err :=
			copyRegressionFile(
				rulesPath,
				rulesDestination,
			); err != nil {

			return result,
				fmt.Errorf(
					"failed to preserve regression rules file: %w",
					err,
				)
		}

		rulesEvidencePath =
			filepath.ToSlash(
				filepath.Join(
					resultsDir,
					runID,
					"regressions",
					regressionID,
					"rules.rules",
				),
			)
	}

	result =
		ReanalysisResult{
			ID: regressionID,

			SourceRunID: runID,

			CreatedAt: now,

			CapturePath: filepath.ToSlash(
				pcapPath,
			),

			RulesPath: rulesEvidencePath,

			SuricataConfig: analysis.ConfigPath,

			AlertCount: analysis.AlertCount,

			BaselineMetrics: baseline.Metrics,

			CurrentMetrics: currentMetrics,

			Comparison: comparison,

			EvePath: filepath.ToSlash(
				filepath.Join(
					resultsDir,
					runID,
					"regressions",
					regressionID,
					"suricata-eve.json",
				),
			),
		}

	data, err :=
		json.MarshalIndent(
			result,
			"",
			"  ",
		)

	if err != nil {
		return result,
			fmt.Errorf(
				"failed to encode regression result: %w",
				err,
			)
	}

	resultPath :=
		filepath.Join(
			regressionDir,
			"regression.json",
		)

	if err :=
		os.WriteFile(
			resultPath,
			data,
			0644,
		); err != nil {

		return result,
			fmt.Errorf(
				"failed to save regression result: %w",
				err,
			)
	}

	return result, nil
}

func copyRegressionFile(
	source string,
	destination string,
) error {

	data, err :=
		os.ReadFile(
			source,
		)

	if err != nil {
		return err
	}

	return os.WriteFile(
		destination,
		data,
		0644,
	)
}
