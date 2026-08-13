package runner

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"flightlab/internal/c2library"
	"flightlab/internal/capture"
	"flightlab/internal/network"
	"flightlab/internal/parser"
	"flightlab/internal/scenario"
)

// Runner is responsible for executing the local FlightSim binary.
type Runner struct {
	BinaryPath string
}

// AllowedModules contains the FlightSim modules
// that FlightLab is allowed to execute.
var AllowedModules = map[string]bool{
	"c2":           true,
	"cleartext":    true,
	"dga":          true,
	"imposter":     true,
	"irc":          true,
	"miner":        true,
	"oast":         true,
	"scan":         true,
	"sink":         true,
	"spambot":      true,
	"ssh-exfil":    true,
	"ssh-transfer": true,
	"telegram-bot": true,
	"tunnel-dns":   true,
	"tunnel-icmp":  true,
}

// BaseModuleName removes an optional FlightSim scope.
// Example: "ssh-transfer:1MB" becomes "ssh-transfer".
func BaseModuleName(module string) string {
	if i := strings.IndexByte(module, ':'); i >= 0 {
		return module[:i]
	}

	return module
}

// Version executes "flightsim version".
func (r Runner) Version() (string, error) {
	cmd := exec.Command(
		r.BinaryPath,
		"version",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"failed to execute FlightSim: %w\n%s",
			err,
			string(output),
		)
	}

	return string(output), nil
}

// Run executes FlightSim using a validated scenario configuration.
func (r Runner) Run(
	config scenario.Config,
) (scenario.Result, error) {

	// Validate module.
	// FlightSim supports scoped module names such as
	// "ssh-transfer:1MB".
	baseModule := BaseModuleName(config.Module)

	// Keep the stored FlightLab module name unchanged,
	// but build a scoped FlightSim argument when needed.
	moduleArg := config.Module

	if config.SSHTransferSize != "" {

		if baseModule != "ssh-transfer" {
			return scenario.Result{},
				fmt.Errorf(
					"ssh_transfer_size can only be used with ssh-transfer",
				)
		}

		// Avoid combining two different scope mechanisms.
		if config.Module != "ssh-transfer" {
			return scenario.Result{},
				fmt.Errorf(
					"ssh_transfer_size cannot be combined with an already scoped ssh-transfer module",
				)
		}

		allowedTransferSizes := map[string]bool{
			"1MB":  true,
			"5MB":  true,
			"10MB": true,
		}

		if !allowedTransferSizes[config.SSHTransferSize] {
			return scenario.Result{},
				fmt.Errorf(
					"unsupported SSH transfer size: %s",
					config.SSHTransferSize,
				)
		}

		moduleArg = fmt.Sprintf(
			"ssh-transfer:%s",
			config.SSHTransferSize,
		)
	}

	if !AllowedModules[baseModule] {
		return scenario.Result{}, fmt.Errorf(
			"unsupported FlightSim module: %s",
			config.Module,
		)
	}

	// Validate simulation size.
	if config.Size < 1 || config.Size > 100 {
		return scenario.Result{}, fmt.Errorf(
			"size must be between 1 and 100",
		)
	}

	// Validate custom C2 library before passing it
	// to FlightSim.
	if config.C2Library != "" {

		if baseModule != "c2" {
			return scenario.Result{},
				fmt.Errorf(
					"custom C2 library can only be used with the c2 module",
				)
		}

		if _, err :=
			c2library.Load(
				config.C2Library,
			); err != nil {

			return scenario.Result{},
				fmt.Errorf(
					"invalid custom C2 library: %w",
					err,
				)
		}
	}

	// Packet capture requires an explicit interface.
	// If none was provided, resolve the default interface.
	if config.Capture &&
		config.Interface == "" {

		resolvedInterface, err :=
			network.DefaultInterface()

		if err != nil {
			return scenario.Result{}, fmt.Errorf(
				"failed to determine capture interface: %w",
				err,
			)
		}

		config.Interface =
			resolvedInterface
	}

	if config.SSHExfilSize != "" {

		if baseModule != "ssh-exfil" {
			return scenario.Result{},
				fmt.Errorf(
					"ssh_exfil_size can only be used with ssh-exfil",
				)
		}

		// Avoid combining the API size field with an already scoped module.
		if config.Module != "ssh-exfil" {
			return scenario.Result{},
				fmt.Errorf(
					"ssh_exfil_size cannot be combined with an already scoped ssh-exfil module",
				)
		}

		allowedExfilSizes := map[string]bool{
			"1MB":  true,
			"5MB":  true,
			"10MB": true,
		}

		if !allowedExfilSizes[config.SSHExfilSize] {
			return scenario.Result{},
				fmt.Errorf(
					"unsupported SSH exfil size: %s",
					config.SSHExfilSize,
				)
		}

		moduleArg = fmt.Sprintf(
			"ssh-exfil:%s",
			config.SSHExfilSize,
		)
	}

	// Build FlightSim arguments.
	// FlightSim flags must appear before the module name.
	args := []string{
		"run",
	}

	if config.DryRun {
		args = append(
			args,
			"-dry",
		)
	}

	if config.Interface != "" {
		args = append(
			args,
			"-iface",
			config.Interface,
		)
	}

	if config.C2Library != "" {
		args = append(
			args,
			"-c2-file",
			config.C2Library,
		)
	}

	args = append(
		args,
		"-size",
		strconv.Itoa(
			config.Size,
		),
	)

	// The FlightSim module must remain the final
	// positional argument.
	//
	// Keep the full module name here so scoped values
	// such as "ssh-transfer:1MB" reach FlightSim unchanged.
	args = append(
		args,
		moduleArg,
	)

	cmd := exec.Command(
		r.BinaryPath,
		args...,
	)

	// Generate a unique ID before starting capture.
	idTime := time.Now()

	runID := fmt.Sprintf(
		"%s-%s-%09d",
		config.Module,
		idTime.Format("20060102-150405"),
		idTime.Nanosecond(),
	)

	// Start packet capture if requested.
	var captureSession *capture.Session

	if config.Capture {
		var err error

		captureSession, err = capture.Start(
			config.Interface,
			runID,
		)

		if err != nil {
			return scenario.Result{}, fmt.Errorf(
				"failed to start packet capture: %w",
				err,
			)
		}

		// Give tcpdump time to attach to the interface.
		time.Sleep(
			500 * time.Millisecond,
		)
	}

	// Start timing the actual FlightSim execution.
	startedAt := time.Now()

	output, runErr :=
		cmd.CombinedOutput()

	finishedAt := time.Now()

	// Stop packet capture after FlightSim finishes.
	if captureSession != nil {
		if err :=
			captureSession.Stop(); err != nil {

			return scenario.Result{}, fmt.Errorf(
				"failed to stop packet capture: %w",
				err,
			)
		}
	}

	// Create the structured result.
	result := scenario.Result{
		ID:         runID,
		Config:     config,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		Duration:   finishedAt.Sub(startedAt),
		Success:    runErr == nil,
		Output:     string(output),
		Events: parser.ParseFlightSimOutput(
			string(output),
		),
	}

	// Record the capture so the evidence package can later
	// move it into the run evidence directory.
	if captureSession != nil {
		result.CapturePath =
			"capture.pcap"

		result.CaptureTempPath =
			captureSession.Path
	}

	if runErr != nil {
		return result, fmt.Errorf(
			"FlightSim execution failed: %w",
			runErr,
		)
	}

	return result, nil
}
