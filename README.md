# FlightLab

FlightLab is an independent local detection-testing tool built around [AlphaSOC FlightSim](https://github.com/alphasoc/flightsim) and Suricata.

FlightSim generates suspicious network activity. FlightLab adds the surrounding validation workflow: packet capture, Suricata analysis, target correlation, detection metrics, gap diagnosis, evidence storage, and same-PCAP ruleset regression testing.

> FlightLab does **not** include or modify FlightSim source code. FlightSim is installed separately and executed as an external dependency.

## What it does

```text
Generate traffic with FlightSim
        ↓
Capture the traffic to PCAP
        ↓
Analyze the PCAP with Suricata
        ↓
Correlate generated targets with observed telemetry and alerts
        ↓
Measure visibility and detection
        ↓
Diagnose detection / telemetry gaps
        ↓
Store evidence for the run
        ↓
Optionally replay the same PCAP against another Suricata ruleset
```

FlightLab tracks three target-level states:

- **Generated** — FlightSim attempted to generate the activity.
- **Observed** — the activity was visible in Suricata telemetry.
- **Alerted** — a Suricata alert matched the activity.

This lets FlightLab distinguish a **detection gap** (traffic was observed but did not alert) from a **telemetry gap** (generated activity was not observed).

## Main features

- Local web dashboard for running supported FlightSim modules
- Dry-run and live detection-evaluation modes
- Automatic network-interface selection
- Automatic PCAP capture
- Suricata EVE analysis
- Target-level FlightSim ↔ Suricata correlation
- Visibility and detection metrics
- Detection-gap diagnosis
- Evidence storage per run
- Same-PCAP Suricata ruleset regression testing
- Detection coverage history
- Custom C2 target libraries
- Configurable SSH transfer / exfil test sizes

## Requirements

FlightLab is intended for a controlled lab environment. A typical Linux/Kali setup needs:

- Go 1.26.5 or newer
- [AlphaSOC FlightSim](https://github.com/alphasoc/flightsim), installed separately and available in `PATH`
- Suricata
- tcpdump
- Permission to capture traffic on the selected interface

Some FlightSim modules require Internet access or elevated privileges.

## Install FlightSim separately

Follow the upstream FlightSim installation instructions. For example:

```bash
go install github.com/alphasoc/flightsim/v2@latest
```

Verify that it can be found:

```bash
flightsim version
```

If FlightSim is not in `PATH`, FlightLab also accepts an explicit executable path with `-flightsim`.

## Build FlightLab

```bash
git clone <your-flightlab-repository-url>
cd flightlab
go build -o flightlab ./cmd/flightlab
```

## Start the dashboard

```bash
./flightlab -serve
```

Then open:

```text
http://127.0.0.1:8080
```

To use a FlightSim binary outside `PATH`:

```bash
./flightlab -serve -flightsim /path/to/flightsim
```

## Same-PCAP detection regression

After a live run, FlightLab can re-analyze the exact captured PCAP with a different Suricata `.rules` file. FlightSim traffic is not generated again.

This makes the comparison more reproducible because the network evidence stays constant while the detection ruleset changes.

Example rule file:

```text
alert tcp any any -> any 22 (msg:"FlightLab SSH test"; flow:to_server; sid:1000001; rev:1;)
```

A higher detection rate does not automatically mean a rule is production-ready. Rules should also be tested against benign traffic and reviewed for false positives.

## Project layout

```text
cmd/flightlab/        application entry point
internal/api/         HTTP API
internal/capture/     packet capture
internal/detection/   Suricata analysis and correlation
internal/diagnosis/   result diagnosis
internal/evidence/    run evidence and history
internal/regression/  same-PCAP re-analysis
internal/runner/      FlightSim execution
internal/scenario/    run configuration and result models
web/                  local dashboard
examples/suricata/    example Suricata rules
libraries/            example/custom C2 libraries
```

Runtime PCAPs, results, uploaded files, local scenarios, binaries, and environment files are excluded through `.gitignore`.

## FlightSim attribution and license notice

FlightSim is a separate project developed by AlphaSOC:

- Project: **AlphaSOC Network Flight Simulator (FlightSim)**
- Repository: https://github.com/alphasoc/flightsim
- Upstream license: **Creative Commons Attribution-NoDerivs 3.0 Unported (CC BY-ND 3.0)**

FlightLab does not redistribute or modify FlightSim source code. Users install FlightSim separately. FlightLab is an independent project and is not affiliated with, sponsored by, or endorsed by AlphaSOC.

## FlightLab license

The FlightLab source code in this repository is licensed under the [MIT License](LICENSE), except for any separately identified third-party material.

## Responsible use

Use FlightLab only in systems and networks that you own or are explicitly authorized to test. Several modules intentionally generate suspicious network traffic and can trigger security controls.
