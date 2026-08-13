package scenario

// Config describes one FlightSim execution.
//
// The same structure can later be populated by:
//   - the CLI
//   - the web UI
//   - saved reproducible scenario files
type Config struct {
	Module          string `json:"module"`
	Size            int    `json:"size"`
	DryRun          bool   `json:"dry_run"`
	Interface       string `json:"interface,omitempty"`
	Capture         bool   `json:"capture"`
	Suricata        bool   `json:"suricata"`
	C2Library       string `json:"c2_library,omitempty"`
	SSHTransferSize string `json:"ssh_transfer_size,omitempty"`
	SSHExfilSize    string `json:"ssh_exfil_size,omitempty"`
}
