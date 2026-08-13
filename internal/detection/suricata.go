package detection

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"flightlab/internal/scenario"
)

// DefaultSuricataConfig is used by normal FlightLab runs.
const DefaultSuricataConfig = "/etc/suricata/suricata.yaml"

// SuricataOptions controls an offline Suricata PCAP analysis.
type SuricataOptions struct {
	ConfigPath string
	RulesPath  string
}

// SuricataAnalysis contains the output of one offline PCAP analysis.
type SuricataAnalysis struct {
	EvePath     string
	TempDir     string
	EventCounts map[string]int
	AlertCount  int
	Alerts      []scenario.SuricataAlert

	ConfigPath string
	RulesPath  string
}

// eveRecord is used for counting Suricata event types.
type eveRecord struct {
	EventType string `json:"event_type"`
}

// eveAlertRecord contains the Suricata EVE fields needed
// to build structured alert records.
type eveAlertRecord struct {
	Timestamp string `json:"timestamp"`
	PcapCount int    `json:"pcap_cnt"`
	EventType string `json:"event_type"`

	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`

	DestIP   string `json:"dest_ip"`
	DestPort int    `json:"dest_port"`

	Proto    string `json:"proto"`
	AppProto string `json:"app_proto"`

	DNS struct {
		RCode string `json:"rcode"`

		Queries []struct {
			RRName string `json:"rrname"`
		} `json:"queries"`
	} `json:"dns"`

	Alert struct {
		Action      string `json:"action"`
		SignatureID int    `json:"signature_id"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

// AnalyzeWithSuricata runs Suricata using FlightLab's default configuration.
func AnalyzeWithSuricata(
	pcapPath string,
	runID string,
) (SuricataAnalysis, error) {

	return AnalyzeWithSuricataOptions(
		pcapPath,
		runID,
		SuricataOptions{
			ConfigPath: DefaultSuricataConfig,
		},
	)
}

// AnalyzeWithSuricataOptions runs Suricata against an existing PCAP
// with an optional custom ruleset.
func AnalyzeWithSuricataOptions(
	pcapPath string,
	runID string,
	options SuricataOptions,
) (SuricataAnalysis, error) {

	configPath := options.ConfigPath

	if configPath == "" {
		configPath = DefaultSuricataConfig
	}

	if _, err := os.Stat(pcapPath); err != nil {
		return SuricataAnalysis{},
			fmt.Errorf(
				"PCAP does not exist: %w",
				err,
			)
	}

	if _, err := os.Stat(configPath); err != nil {
		return SuricataAnalysis{},
			fmt.Errorf(
				"Suricata configuration does not exist: %w",
				err,
			)
	}

	if options.RulesPath != "" {

		if _, err :=
			os.Stat(
				options.RulesPath,
			); err != nil {

			return SuricataAnalysis{},
				fmt.Errorf(
					"Suricata ruleset does not exist: %w",
					err,
				)
		}
	}

	tempDir, err :=
		os.MkdirTemp(
			"",
			runID+"-suricata-*",
		)

	if err != nil {
		return SuricataAnalysis{},
			fmt.Errorf(
				"failed to create Suricata output directory: %w",
				err,
			)
	}

	args := []string{
		"-c",
		configPath,
	}

	// -S loads this rules file exclusively.
	// This is useful for regression testing because
	// the same PCAP can be evaluated against different
	// detection rulesets.
	if options.RulesPath != "" {

		args = append(
			args,
			"-S",
			options.RulesPath,
		)
	}

	args = append(
		args,
		"-r",
		pcapPath,
		"-l",
		tempDir,
	)

	cmd :=
		exec.Command(
			"suricata",
			args...,
		)

	output, err :=
		cmd.CombinedOutput()

	if err != nil {
		return SuricataAnalysis{},
			fmt.Errorf(
				"Suricata analysis failed: %w\n%s",
				err,
				string(output),
			)
	}

	evePath :=
		filepath.Join(
			tempDir,
			"eve.json",
		)

	if _, err :=
		os.Stat(
			evePath,
		); err != nil {

		return SuricataAnalysis{},
			fmt.Errorf(
				"Suricata did not produce eve.json: %w",
				err,
			)
	}

	eventCounts, err :=
		countEventTypes(
			evePath,
		)

	if err != nil {
		return SuricataAnalysis{}, err
	}

	alerts, err :=
		parseAlerts(
			evePath,
		)

	if err != nil {
		return SuricataAnalysis{}, err
	}

	return SuricataAnalysis{
		EvePath: evePath,
		TempDir: tempDir,

		EventCounts: eventCounts,

		AlertCount: eventCounts["alert"],

		Alerts: alerts,

		ConfigPath: configPath,

		RulesPath: options.RulesPath,
	}, nil
}

// countEventTypes counts Suricata records by event_type.
func countEventTypes(
	evePath string,
) (map[string]int, error) {

	file, err := os.Open(evePath)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open Suricata EVE file: %w",
			err,
		)
	}
	defer file.Close()

	counts :=
		make(
			map[string]int,
		)

	scanner :=
		bufio.NewScanner(
			file,
		)

	for scanner.Scan() {

		var record eveRecord

		if err := json.Unmarshal(
			scanner.Bytes(),
			&record,
		); err != nil {
			continue
		}

		if record.EventType != "" {
			counts[record.EventType]++
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf(
			"failed while reading Suricata EVE file: %w",
			err,
		)
	}

	return counts, nil
}

// parseAlerts extracts structured alert records from Suricata eve.json.
func parseAlerts(
	evePath string,
) ([]scenario.SuricataAlert, error) {

	file, err := os.Open(evePath)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open Suricata EVE file: %w",
			err,
		)
	}
	defer file.Close()

	alerts :=
		make(
			[]scenario.SuricataAlert,
			0,
		)

	scanner :=
		bufio.NewScanner(
			file,
		)

	for scanner.Scan() {

		var record eveAlertRecord

		if err := json.Unmarshal(
			scanner.Bytes(),
			&record,
		); err != nil {
			continue
		}

		if record.EventType != "alert" {
			continue
		}

		dnsNames :=
			make(
				[]string,
				0,
			)

		for _, query := range record.DNS.Queries {

			if query.RRName != "" {
				dnsNames =
					append(
						dnsNames,
						query.RRName,
					)
			}
		}

		alerts =
			append(
				alerts,
				scenario.SuricataAlert{
					Timestamp: record.Timestamp,

					PcapCount: record.PcapCount,

					SrcIP: record.SrcIP,

					SrcPort: record.SrcPort,

					DestIP: record.DestIP,

					DestPort: record.DestPort,

					Proto: record.Proto,

					AppProto: record.AppProto,

					Action: record.Alert.Action,

					SignatureID: record.Alert.SignatureID,

					Signature: record.Alert.Signature,

					Category: record.Alert.Category,

					Severity: record.Alert.Severity,

					DNSNames: dnsNames,

					DNSRCode: record.DNS.RCode,
				},
			)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf(
			"failed while parsing Suricata alerts: %w",
			err,
		)
	}

	return alerts, nil
}
