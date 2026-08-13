package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"flightlab/internal/api"
	"flightlab/internal/detection"
	"flightlab/internal/diagnosis"
	"flightlab/internal/evidence"
	"flightlab/internal/regression"
	"flightlab/internal/runner"
	"flightlab/internal/scenario"
)

func defaultFlightSimPath() string {
	if runtime.GOOS == "windows" {
		return "flightsim.exe"
	}

	return "flightsim"
}

func main() {
	// Regression analysis options.
	regressionRun := flag.String(
		"regression-run",
		"",
		"re-analyze an existing FlightLab run without regenerating traffic",
	)

	rulesPath := flag.String(
		"rules",
		"",
		"Suricata rules file used for regression analysis",
	)

	// FlightLab command-line options.
	c2Library := flag.String(
		"c2-library",
		"",
		"custom C2 target library file",
	)

	module := flag.String(
		"module",
		"dga",
		"FlightSim module to execute",
	)

	size := flag.Int(
		"size",
		2,
		"number of simulation targets",
	)

	dryRun := flag.Bool(
		"dry",
		true,
		"run without generating network traffic",
	)

	iface := flag.String(
		"iface",
		"",
		"network interface or local IP address",
	)

	captureEnabled := flag.Bool(
		"capture",
		false,
		"capture packets during the simulation",
	)

	serve := flag.Bool(
		"serve",
		false,
		"start the FlightLab HTTP API",
	)

	addr := flag.String(
		"addr",
		"127.0.0.1:8080",
		"HTTP API listen address",
	)

	// Path to the existing FlightSim executable.
	defaultBinaryPath := defaultFlightSimPath()

	flightSimPath := flag.String(
		"flightsim",
		defaultBinaryPath,
		"path to the FlightSim executable",
	)

	runSuricata := flag.Bool(
		"suricata",
		false,
		"analyze captured traffic with Suricata",
	)

	// Save the current CLI configuration as a reusable scenario.
	saveScenario := flag.String(
		"save-scenario",
		"",
		"save the current configuration as a reusable scenario",
	)

	// Load configuration from an existing scenario file.
	scenarioPath := flag.String(
		"scenario",
		"",
		"load configuration from a saved scenario file",
	)

	flag.Parse()

	// Regression mode.
	//
	// Re-analyze an existing FlightLab PCAP with a
	// different Suricata ruleset without generating
	// network traffic again.
	if *regressionRun != "" {
		if *rulesPath == "" {
			fmt.Fprintln(
				os.Stderr,
				"-rules is required with -regression-run",
			)

			os.Exit(1)
		}

		result, err :=
			regression.Reanalyze(
				"results",
				*regressionRun,
				*rulesPath,
			)

		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"Regression analysis failed: %v\n",
				err,
			)

			os.Exit(1)
		}

		printRegressionResult(
			result,
		)

		return
	}

	fs := runner.Runner{
		BinaryPath: *flightSimPath,
	}

	// Start the HTTP API when requested.
	if *serve {
		server := api.Server{
			Runner:     fs,
			ResultsDir: "results",
		}

		fmt.Println("FlightLab API")
		fmt.Println("=============")
		fmt.Printf(
			"Listening on http://%s\n",
			*addr,
		)
		fmt.Println()

		if err := http.ListenAndServe(
			*addr,
			server.Handler(),
		); err != nil {
			log.Fatal(err)
		}

		return
	}

	// Resolve the scenario configuration.
	//
	// If -scenario is provided, load the configuration
	// from the saved scenario file.
	//
	// Otherwise, build the configuration from CLI flags.
	var config scenario.Config

	if *scenarioPath != "" {
		definition, err :=
			scenario.LoadDefinition(
				*scenarioPath,
			)

		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"failed to load scenario: %v\n",
				err,
			)

			os.Exit(1)
		}

		config =
			definition.Config

		fmt.Printf(
			"Loaded scenario: %s\n",
			definition.Name,
		)

	} else {
		config = scenario.Config{
			Module:    *module,
			Size:      *size,
			DryRun:    *dryRun,
			Interface: *iface,
			Capture:   *captureEnabled,
			Suricata:  *runSuricata,
			C2Library: *c2Library,
		}
	}

	// Save the resolved configuration as a reusable
	// scenario when -save-scenario is provided.
	//
	// Saving does not stop execution. The scenario is
	// saved first and then the simulation continues.
	if *saveScenario != "" {
		if *scenarioPath != "" {
			fmt.Fprintln(
				os.Stderr,
				"-save-scenario and -scenario cannot be used together",
			)

			os.Exit(1)
		}

		path, err :=
			scenario.SaveDefinition(
				"scenarios",
				*saveScenario,
				config,
			)

		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"failed to save scenario: %v\n",
				err,
			)

			os.Exit(1)
		}

		fmt.Printf(
			"Saved scenario: %s\n\n",
			path,
		)
	}

	fmt.Println("FlightLab")
	fmt.Println("=========")
	fmt.Println()

	fmt.Printf(
		"Module:    %s\n",
		config.Module,
	)

	if config.Module == "c2" {
		if config.C2Library != "" {
			fmt.Println(
				"C2 source: custom library",
			)

			fmt.Printf(
				"C2 library: %s\n",
				config.C2Library,
			)

		} else {
			fmt.Println(
				"C2 source: AlphaSOC Wisdom",
			)
		}
	}

	fmt.Printf(
		"Size:      %d\n",
		config.Size,
	)

	fmt.Printf(
		"Dry run:   %t\n",
		config.DryRun,
	)

	fmt.Printf(
		"Capture:   %t\n",
		config.Capture,
	)

	fmt.Printf(
		"Suricata:  %t\n",
		config.Suricata,
	)

	if config.Interface == "" {
		fmt.Println(
			"Interface: automatic",
		)
	} else {
		fmt.Printf(
			"Interface: %s\n",
			config.Interface,
		)
	}

	fmt.Println()

	// Run FlightSim.
	result, err :=
		fs.Run(
			config,
		)

	if err != nil {
		log.Fatal(err)
	}

	// Run Suricata analysis when requested.
	if config.Suricata {
		if !config.Capture {
			log.Fatal(
				"Suricata analysis requires packet capture",
			)
		}

		if result.CaptureTempPath == "" {
			log.Fatal(
				"no packet capture is available for Suricata",
			)
		}

		analysis, err :=
			detection.AnalyzeWithSuricata(
				result.CaptureTempPath,
				result.ID,
			)

		if err != nil {
			log.Fatal(err)
		}

		result.SuricataTempPath =
			analysis.EvePath

		result.SuricataTempDir =
			analysis.TempDir

		result.SuricataPath =
			"suricata-eve.json"

		result.SuricataEventCounts =
			analysis.EventCounts

		result.SuricataAlertCount =
			analysis.AlertCount

		result.SuricataAlerts =
			analysis.Alerts

		// Correlate FlightSim targets with Suricata events.
		metrics, err :=
			detection.Correlate(
				config.Module,
				result.Events,
				analysis.EvePath,
			)

		if err != nil {
			log.Fatal(err)
		}

		result.Metrics =
			metrics

		// Analyze the correlated result and identify
		// detection or telemetry gaps.
		result.Diagnosis =
			diagnosis.Analyze(
				result.Success,
				result.Metrics,
			)
	}

	// Save all evidence.
	evidenceDir, err :=
		evidence.Save(
			"results",
			result,
		)

	if err != nil {
		log.Fatal(err)
	}

	// Print original FlightSim output.
	fmt.Print(
		result.Output,
	)

	fmt.Println()
	fmt.Println("FlightLab Result")
	fmt.Println("----------------")

	fmt.Printf(
		"Run ID:   %s\n",
		result.ID,
	)

	fmt.Printf(
		"Evidence: %s\n",
		evidenceDir,
	)

	if result.CapturePath != "" {
		fmt.Printf(
			"PCAP:     %s\n",
			filepath.Join(
				evidenceDir,
				result.CapturePath,
			),
		)
	}

	if result.SuricataPath != "" {
		fmt.Printf(
			"Suricata: %s\n",
			filepath.Join(
				evidenceDir,
				result.SuricataPath,
			),
		)

		fmt.Printf(
			"DNS events: %d\n",
			result.SuricataEventCounts["dns"],
		)

		fmt.Printf(
			"Flow events: %d\n",
			result.SuricataEventCounts["flow"],
		)

		fmt.Printf(
			"Alerts:     %d\n",
			result.SuricataAlertCount,
		)
	}

	if len(
		result.SuricataAlerts,
	) > 0 {

		fmt.Println()
		fmt.Println("Suricata Alerts")
		fmt.Println("---------------")

		for _, alert := range result.SuricataAlerts {

			fmt.Printf(
				"SID %d | Severity %d | %s\n",
				alert.SignatureID,
				alert.Severity,
				alert.Signature,
			)

			if len(
				alert.DNSNames,
			) > 0 {

				fmt.Printf(
					"  DNS: %v\n",
					alert.DNSNames,
				)
			}

			if alert.DNSRCode != "" {
				fmt.Printf(
					"  DNS result: %s\n",
					alert.DNSRCode,
				)
			}

			fmt.Printf(
				"  %s:%d -> %s:%d\n",
				alert.SrcIP,
				alert.SrcPort,
				alert.DestIP,
				alert.DestPort,
			)
		}
	}

	// Print detection metrics.
	if result.Metrics != nil {
		fmt.Println()
		fmt.Println("Detection Metrics")
		fmt.Println("-----------------")

		fmt.Printf(
			"Targets generated: %d\n",
			result.Metrics.TargetsTotal,
		)

		fmt.Printf(
			"Targets observed:  %d\n",
			result.Metrics.TargetsObserved,
		)

		fmt.Printf(
			"Targets alerted:   %d\n",
			result.Metrics.TargetsAlerted,
		)

		fmt.Printf(
			"Visibility rate:   %.2f%%\n",
			result.Metrics.VisibilityRate,
		)

		fmt.Printf(
			"Detection rate:    %.2f%%\n",
			result.Metrics.DetectionRate,
		)

		if len(
			result.Metrics.TargetResults,
		) > 0 {

			fmt.Println()
			fmt.Println("Target Results")
			fmt.Println("--------------")

			for _, target := range result.Metrics.TargetResults {

				fmt.Printf(
					"%-28s %-8s observed=%t alerted=%t\n",
					target.Value,
					target.Type,
					target.Observed,
					target.Alerted,
				)
			}
		}
	}

	// Print detection diagnosis.
	if result.Diagnosis != nil {
		fmt.Println()
		fmt.Println("Detection Diagnosis")
		fmt.Println("-------------------")

		fmt.Printf(
			"Overall: %s\n",
			result.Diagnosis.OverallStatus,
		)

		fmt.Printf(
			"Reason:  %s\n",
			result.Diagnosis.OverallReason,
		)

		fmt.Printf(
			"Detected:           %d\n",
			result.Diagnosis.Detected,
		)

		fmt.Printf(
			"Detection Gaps:     %d\n",
			result.Diagnosis.DetectionGaps,
		)

		fmt.Printf(
			"Telemetry Gaps:     %d\n",
			result.Diagnosis.TelemetryGaps,
		)

		fmt.Printf(
			"Simulation Failures:%d\n",
			result.Diagnosis.SimulationFailures,
		)

		fmt.Println()
		fmt.Println("Target Diagnosis")

		for _, target := range result.Diagnosis.Targets {

			fmt.Printf(
				"\n%s (%s)\n",
				target.Value,
				target.Type,
			)

			fmt.Printf(
				"  Traffic Generated: %t\n",
				target.TrafficGenerated,
			)

			fmt.Printf(
				"  Suricata Observed: %t\n",
				target.Observed,
			)

			fmt.Printf(
				"  Alert Triggered:   %t\n",
				target.Alerted,
			)

			fmt.Printf(
				"  Result:            %s\n",
				target.Status,
			)

			fmt.Printf(
				"  Reason:            %s\n",
				target.Reason,
			)
		}
	}

	fmt.Printf(
		"Success:  %t\n",
		result.Success,
	)

	fmt.Printf(
		"Started:  %s\n",
		result.StartedAt.Format(
			"15:04:05",
		),
	)

	fmt.Printf(
		"Finished: %s\n",
		result.FinishedAt.Format(
			"15:04:05",
		),
	)

	fmt.Printf(
		"Duration: %s\n",
		result.Duration,
	)

	fmt.Printf(
		"Events:   %d\n",
		len(result.Events),
	)

	fmt.Println()
	fmt.Println("Parsed Events")
	fmt.Println("-------------")

	for _, event := range result.Events {

		fmt.Printf(
			"%s [%s] %-10s %s\n",
			event.Time,
			event.Module,
			event.Type,
			event.Message,
		)
	}
}

func printRegressionResult(
	result regression.ReanalysisResult,
) {
	fmt.Println()
	fmt.Println("Detection Regression Test")
	fmt.Println("=========================")

	fmt.Printf(
		"Source Run: %s\n",
		result.SourceRunID,
	)

	fmt.Printf(
		"Ruleset:    %s\n",
		result.RulesPath,
	)

	fmt.Println()

	comparison :=
		result.Comparison

	fmt.Printf(
		"Baseline Detection Rate: %.2f%%\n",
		comparison.BaselineDetectionRate,
	)

	fmt.Printf(
		"Current Detection Rate:  %.2f%%\n",
		comparison.CurrentDetectionRate,
	)

	fmt.Printf(
		"Change:                  %+.2f percentage points\n",
		comparison.DetectionRateChange,
	)

	fmt.Printf(
		"Baseline Detected:       %d\n",
		comparison.BaselineDetected,
	)

	fmt.Printf(
		"Current Detected:        %d\n",
		comparison.CurrentDetected,
	)

	fmt.Println()

	fmt.Println("Newly Detected")
	fmt.Println("--------------")

	if len(
		comparison.NewlyDetected,
	) == 0 {

		fmt.Println(
			"None",
		)

	} else {
		for _, target := range comparison.NewlyDetected {

			fmt.Printf(
				"+ %s (%s)\n",
				target.Value,
				target.Type,
			)
		}
	}

	fmt.Println()

	fmt.Println("Regressions")
	fmt.Println("-----------")

	if len(
		comparison.Regressions,
	) == 0 {

		fmt.Println(
			"None",
		)

	} else {
		for _, target := range comparison.Regressions {

			fmt.Printf(
				"- %s (%s)\n",
				target.Value,
				target.Type,
			)
		}
	}

	fmt.Println()

	switch {

	case comparison.Regressed:

		fmt.Println(
			"Result: DETECTION REGRESSION",
		)

	case comparison.Improved:

		fmt.Println(
			"Result: DETECTION IMPROVEMENT",
		)

	default:

		fmt.Println(
			"Result: NO DETECTION CHANGE",
		)
	}
}
