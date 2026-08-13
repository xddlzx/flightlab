package detection

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"flightlab/internal/scenario"
)

// networkTarget represents a generated DNS, IP, or IP:port target.
//
// The type is intentionally module-independent because multiple
// FlightSim modules can produce target formats handled by the same
// Suricata correlation path.
type networkTarget struct {
	Value string
	Type  string
	Host  string
	Port  int
}

// eveCorrelationRecord contains only the Suricata EVE fields
// required for correlation.
type eveCorrelationRecord struct {
	EventType string `json:"event_type"`

	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`

	DestIP   string `json:"dest_ip"`
	DestPort int    `json:"dest_port"`

	Proto string `json:"proto"`

	DNS struct {
		Queries []struct {
			RRName string `json:"rrname"`
		} `json:"queries"`
	} `json:"dns"`

	Alert struct {
		Signature   string `json:"signature"`
		SignatureID int    `json:"signature_id"`
	} `json:"alert"`
}

// Correlate provides the single correlation dispatcher
// used by FlightLab.
//
// This is the only place that decides which correlation
// strategy a FlightSim module should use.
func Correlate(
	module string,
	events []scenario.Event,
	evePath string,
) (*scenario.DetectionMetrics, error) {

	normalizedModule := baseModuleName(module)

	switch normalizedModule {

	case "dga":
		metrics, err := CorrelateDGA(
			events,
			evePath,
		)

		if err != nil {
			return nil, err
		}

		return &metrics, nil

	case "oast":
		return correlateOAST(
			events,
			evePath,
		)

	case "tunnel-dns":
		return correlateTunnelDNS(
			events,
			evePath,
		)

	case "tunnel-icmp":
		return correlateTunnelICMP(
			events,
			evePath,
		)

	case "c2",
		"sink",
		"imposter",
		"miner",
		"irc",
		"scan",
		"cleartext",
		"spambot",
		"ssh-transfer",
		"ssh-exfil",
		"telegram-bot":

		metrics, err := correlateDNSIPTargets(
			module,
			events,
			evePath,
		)

		if err != nil {
			return nil, err
		}

		return &metrics, nil

	default:
		// Correlation has not been implemented
		// for this FlightSim module.
		return nil, nil
	}
}

// CorrelateDGA compares FlightSim-generated DGA domains
// with Suricata DNS and alert events.
func CorrelateDGA(
	events []scenario.Event,
	evePath string,
) (scenario.DetectionMetrics, error) {

	targets := extractDGATargets(
		events,
	)

	metrics := scenario.DetectionMetrics{
		TargetsTotal:    len(targets),
		ObservedTargets: []string{},
		AlertedTargets:  []string{},
		TargetResults:   []scenario.TargetResult{},
	}

	if len(targets) == 0 {
		return metrics, nil
	}

	file, err := os.Open(
		evePath,
	)

	if err != nil {
		return metrics, fmt.Errorf(
			"failed to open Suricata EVE file for DGA correlation: %w",
			err,
		)
	}

	defer file.Close()

	observed := make(
		map[string]bool,
	)

	alerted := make(
		map[string]bool,
	)

	scanner := bufio.NewScanner(
		file,
	)

	for scanner.Scan() {

		var record eveCorrelationRecord

		if err := json.Unmarshal(
			scanner.Bytes(),
			&record,
		); err != nil {
			continue
		}

		switch record.EventType {

		case "dns":

			for _, query := range record.DNS.Queries {

				name := normalizeDomain(
					query.RRName,
				)

				if targets[name] {
					observed[name] = true
				}
			}

		case "alert":

			for _, query := range record.DNS.Queries {

				name := normalizeDomain(
					query.RRName,
				)

				if targets[name] {
					alerted[name] = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return metrics, fmt.Errorf(
			"failed while reading Suricata EVE file for DGA correlation: %w",
			err,
		)
	}

	keys := make(
		[]string,
		0,
		len(targets),
	)

	for target := range targets {
		keys = append(
			keys,
			target,
		)
	}

	sort.Strings(
		keys,
	)

	for _, target := range keys {

		isObserved :=
			observed[target]

		isAlerted :=
			alerted[target]

		metrics.TargetResults = append(
			metrics.TargetResults,
			scenario.TargetResult{
				Value:    target,
				Type:     "dns",
				Observed: isObserved,
				Alerted:  isAlerted,
			},
		)

		if isObserved {
			metrics.ObservedTargets = append(
				metrics.ObservedTargets,
				target,
			)
		}

		if isAlerted {
			metrics.AlertedTargets = append(
				metrics.AlertedTargets,
				target,
			)
		}
	}

	metrics.TargetsObserved =
		len(metrics.ObservedTargets)

	metrics.TargetsAlerted =
		len(metrics.AlertedTargets)

	if metrics.TargetsTotal > 0 {

		metrics.VisibilityRate =
			float64(metrics.TargetsObserved) /
				float64(metrics.TargetsTotal) *
				100

		metrics.DetectionRate =
			float64(metrics.TargetsAlerted) /
				float64(metrics.TargetsTotal) *
				100
	}

	return metrics, nil
}

// extractDGATargets reads FlightSim messages such as:
//
//	Resolving example.info
//
// and produces a unique set of generated DGA domains.
func extractDGATargets(
	events []scenario.Event,
) map[string]bool {

	targets := make(
		map[string]bool,
	)

	for _, event := range events {

		if event.Module != "dga" {
			continue
		}

		const prefix = "Resolving "

		if !strings.HasPrefix(
			event.Message,
			prefix,
		) {
			continue
		}

		target := strings.TrimSpace(
			strings.TrimPrefix(
				event.Message,
				prefix,
			),
		)

		target = normalizeDomain(
			target,
		)

		if target != "" {
			targets[target] = true
		}
	}

	return targets
}

// normalizeDomain provides one common DNS normalization
// strategy for FlightSim and Suricata names.
func normalizeDomain(
	domain string,
) string {

	domain = strings.TrimSpace(
		domain,
	)

	domain = strings.TrimSuffix(
		domain,
		".",
	)

	domain = strings.ToLower(
		domain,
	)

	return domain
}

// extractOASTBase extracts the OAST base domain from
// FlightSim output such as:
//
//	Resolving oast.site
func extractOASTBase(
	events []scenario.Event,
) string {

	const prefix = "Resolving "

	for _, event := range events {

		if baseModuleName(event.Module) != "oast" {
			continue
		}

		message := strings.TrimSpace(
			event.Message,
		)

		if !strings.HasPrefix(
			message,
			prefix,
		) {
			continue
		}

		host := normalizeDomain(
			strings.TrimSpace(
				strings.TrimPrefix(
					message,
					prefix,
				),
			),
		)

		if host != "" {
			return host
		}
	}

	return ""
}

func oastDNSQueryMatches(
	queryName string,
	queryType string,
	baseDomain string,
) bool {

	queryName = normalizeDomain(
		queryName,
	)

	baseDomain = normalizeDomain(
		baseDomain,
	)

	if queryName == "" ||
		baseDomain == "" {

		return false
	}

	// OAST uses IP resolution, so look for A/AAAA traffic.
	if !strings.EqualFold(
		queryType,
		"A",
	) &&
		!strings.EqualFold(
			queryType,
			"AAAA",
		) {

		return false
	}

	suffix := "." + baseDomain

	// The base domain itself is not the simulated OAST payload.
	// FlightSim generates random subdomains beneath it.
	return queryName != baseDomain &&
		strings.HasSuffix(
			queryName,
			suffix,
		)
}

func correlateOAST(
	events []scenario.Event,
	evePath string,
) (*scenario.DetectionMetrics, error) {

	baseDomain :=
		extractOASTBase(
			events,
		)

	if baseDomain == "" {
		return nil, fmt.Errorf(
			"failed to extract OAST target from FlightSim events",
		)
	}

	file, err :=
		os.Open(evePath)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	type dnsQuery struct {
		RRName string `json:"rrname"`
		RRType string `json:"rrtype"`
	}

	type eveRecord struct {
		EventType string `json:"event_type"`

		DNS struct {
			Queries []dnsQuery `json:"queries"`
		} `json:"dns"`
	}

	observed := false
	alerted := false

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

		switch record.EventType {

		case "dns":

			for _, query := range record.DNS.Queries {

				if oastDNSQueryMatches(
					query.RRName,
					query.RRType,
					baseDomain,
				) {

					observed = true
				}
			}

		case "alert":

			for _, query := range record.DNS.Queries {

				if oastDNSQueryMatches(
					query.RRName,
					query.RRType,
					baseDomain,
				) {

					alerted = true
					observed = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	target :=
		scenario.TargetResult{
			Value:    baseDomain,
			Type:     "oast_dns",
			Observed: observed,
			Alerted:  alerted,
		}

	metrics :=
		&scenario.DetectionMetrics{
			TargetsTotal: 1,
			TargetResults: []scenario.TargetResult{
				target,
			},
		}

	if observed {
		metrics.TargetsObserved = 1

		metrics.ObservedTargets =
			[]string{
				baseDomain,
			}

		metrics.VisibilityRate = 100
	}

	if alerted {
		metrics.TargetsAlerted = 1

		metrics.AlertedTargets =
			[]string{
				baseDomain,
			}

		metrics.DetectionRate = 100
	}

	return metrics, nil
}

// extractTunnelDNSBase extracts the base tunnel domain from
// FlightSim output such as:
//
//	Simulating DNS tunneling via *.sandbox.alphasoc.xyz
func extractTunnelDNSBase(
	events []scenario.Event,
) string {

	const prefix = "Simulating DNS tunneling via "

	for _, event := range events {

		message :=
			strings.TrimSpace(
				event.Message,
			)

		if !strings.HasPrefix(
			message,
			prefix,
		) {
			continue
		}

		value :=
			strings.TrimSpace(
				strings.TrimPrefix(
					message,
					prefix,
				),
			)

		value =
			strings.TrimPrefix(
				value,
				"*.",
			)

		value =
			normalizeDomain(
				value,
			)

		if value != "" {
			return value
		}
	}

	return ""
}

func tunnelDNSQueryMatches(
	queryName string,
	queryType string,
	baseDomain string,
) bool {

	queryName =
		normalizeDomain(
			queryName,
		)

	baseDomain =
		normalizeDomain(
			baseDomain,
		)

	if queryName == "" ||
		baseDomain == "" {

		return false
	}

	if !strings.EqualFold(
		queryType,
		"TXT",
	) {
		return false
	}

	// The base domain itself is not enough.
	// We expect a subdomain carrying tunnel data.
	suffix :=
		"." + baseDomain

	return queryName !=
		baseDomain &&
		strings.HasSuffix(
			queryName,
			suffix,
		)
}

func correlateTunnelDNS(
	events []scenario.Event,
	evePath string,
) (*scenario.DetectionMetrics, error) {

	baseDomain :=
		extractTunnelDNSBase(
			events,
		)

	if baseDomain == "" {
		return nil, fmt.Errorf(
			"failed to extract DNS tunnel target from FlightSim events",
		)
	}

	file, err :=
		os.Open(evePath)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	type dnsQuery struct {
		RRName string `json:"rrname"`
		RRType string `json:"rrtype"`
	}

	type eveRecord struct {
		EventType string `json:"event_type"`

		DNS struct {
			Type string `json:"type"`

			Queries []dnsQuery `json:"queries"`
		} `json:"dns"`
	}

	observed := false
	alerted := false

	scanner :=
		bufio.NewScanner(
			file,
		)

	for scanner.Scan() {

		var record eveRecord

		if err :=
			json.Unmarshal(
				scanner.Bytes(),
				&record,
			); err != nil {

			continue
		}

		switch record.EventType {

		case "dns":

			for _, query := range record.DNS.Queries {

				if tunnelDNSQueryMatches(
					query.RRName,
					query.RRType,
					baseDomain,
				) {
					observed = true
				}
			}

		case "alert":

			for _, query := range record.DNS.Queries {

				if tunnelDNSQueryMatches(
					query.RRName,
					query.RRType,
					baseDomain,
				) {
					alerted = true
					observed = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {

		return nil, err
	}

	target :=
		scenario.TargetResult{
			Value: baseDomain,

			Type: "dns_tunnel",

			Observed: observed,

			Alerted: alerted,
		}

	metrics :=
		&scenario.DetectionMetrics{
			TargetsTotal: 1,

			TargetResults: []scenario.TargetResult{
				target,
			},
		}

	if observed {

		metrics.TargetsObserved = 1

		metrics.ObservedTargets =
			[]string{
				baseDomain,
			}

		metrics.VisibilityRate =
			100
	}

	if alerted {

		metrics.TargetsAlerted = 1

		metrics.AlertedTargets =
			[]string{
				baseDomain,
			}

		metrics.DetectionRate =
			100
	}

	return metrics, nil
}

// extractTunnelICMPHost extracts the ICMP tunnel destination
// from FlightSim output such as:
//
//	Simulating ICMP tunneling via icmp.sandbox-services.alphasoc.xyz
func extractTunnelICMPHost(
	events []scenario.Event,
) string {

	const prefix = "Simulating ICMP tunneling via "

	for _, event := range events {

		if event.Module != "tunnel-icmp" {
			continue
		}

		message := strings.TrimSpace(
			event.Message,
		)

		if !strings.HasPrefix(
			message,
			prefix,
		) {
			continue
		}

		host := strings.TrimSpace(
			strings.TrimPrefix(
				message,
				prefix,
			),
		)

		host = normalizeDomain(
			host,
		)

		if host != "" {
			return host
		}
	}

	return ""
}

// correlateTunnelICMP correlates the FlightSim ICMP tunnel
// simulation with Suricata telemetry.
//
// Correlation chain:
//
//	FlightSim hostname
//	    -> DNS A/AAAA resolution observed by Suricata
//	    -> ICMP flow involving the resolved address
//	    -> optional Suricata alert on that ICMP flow
//
// We intentionally do not require FlightSim's current exact packet count.
// The goal is to prove that the monitoring sensor observed the generated
// ICMP behavior without tightly coupling FlightLab to one upstream constant.
func correlateTunnelICMP(
	events []scenario.Event,
	evePath string,
) (*scenario.DetectionMetrics, error) {

	host := extractTunnelICMPHost(
		events,
	)

	if host == "" {
		return nil, fmt.Errorf(
			"failed to extract ICMP tunnel target from FlightSim events",
		)
	}

	resolutions, err := loadDNSResolutions(
		evePath,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to load ICMP tunnel DNS resolution: %w",
			err,
		)
	}

	targetIPs := resolutions[normalizeDomain(host)]

	file, err := os.Open(
		evePath,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to open Suricata EVE file for ICMP tunnel correlation: %w",
			err,
		)
	}

	defer file.Close()

	type flowData struct {
		PktsToServer int `json:"pkts_toserver"`
		PktsToClient int `json:"pkts_toclient"`

		BytesToServer int64 `json:"bytes_toserver"`
		BytesToClient int64 `json:"bytes_toclient"`
	}

	type eveRecord struct {
		EventType string `json:"event_type"`

		SrcIP  string `json:"src_ip"`
		DestIP string `json:"dest_ip"`

		Proto string `json:"proto"`

		Flow flowData `json:"flow"`
	}

	observed := false
	alerted := false

	scanner := bufio.NewScanner(
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

		if !strings.EqualFold(
			record.Proto,
			"ICMP",
		) {
			continue
		}

		targetMatch :=
			targetIPs[record.SrcIP] ||
				targetIPs[record.DestIP]

		if !targetMatch {
			continue
		}

		switch record.EventType {

		case "flow":

			if record.Flow.PktsToServer > 0 ||
				record.Flow.PktsToClient > 0 {

				observed = true
			}

		case "alert":

			alerted = true
			observed = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf(
			"failed while reading Suricata EVE file for ICMP tunnel correlation: %w",
			err,
		)
	}

	target := scenario.TargetResult{
		Value:    host,
		Type:     "icmp_tunnel",
		Observed: observed,
		Alerted:  alerted,
	}

	metrics := &scenario.DetectionMetrics{
		TargetsTotal: 1,
		TargetResults: []scenario.TargetResult{
			target,
		},
	}

	if observed {
		metrics.TargetsObserved = 1
		metrics.ObservedTargets = []string{
			host,
		}
		metrics.VisibilityRate = 100
	}

	if alerted {
		metrics.TargetsAlerted = 1
		metrics.AlertedTargets = []string{
			host,
		}
		metrics.DetectionRate = 100
	}

	return metrics, nil
}

// extractDNSIPTargets extracts targets belonging only to
// the module provided by the caller.
//
// This function does not decide which modules FlightLab supports.
// That policy belongs to Correlate().
//
// Supported FlightSim message formats:
//
//	Resolving <domain>
//	Connecting to <ip>:<port>
//	Simulating IRC traffic to <domain>
//	Simulating IRC traffic to <ip>:<port>
//	Port scanning <ip>
//	Sending random data to <ip>:<port>
func extractDNSIPTargets(
	module string,
	events []scenario.Event,
) map[string]networkTarget {

	targets := make(
		map[string]networkTarget,
	)

	for _, event := range events {

		// Only process events belonging to the module
		// currently being correlated.
		if baseModuleName(event.Module) !=
			baseModuleName(module) {

			continue
		}

		// Telegram Bot API target:
		//
		// Simulating Telegram Bot API traffic to api.telegram.org
		if strings.HasPrefix(
			event.Message,
			"Simulating Telegram Bot API traffic to ",
		) {

			host := strings.TrimSpace(
				strings.TrimPrefix(
					event.Message,
					"Simulating Telegram Bot API traffic to ",
				),
			)

			host = normalizeDomain(host)

			if host == "" {
				continue
			}

			const port = 443

			value := net.JoinHostPort(
				host,
				strconv.Itoa(port),
			)

			key := "host_port:" + value

			targets[key] = networkTarget{
				Value: value,
				Type:  "host_port",
				Host:  host,
				Port:  port,
			}

			continue
		}

		// SSH/SFTP transfer target.
		if strings.HasPrefix(
			event.Message,
			"Simulating an SSH/SFTP file transfer of ",
		) {

			index := strings.LastIndex(
				event.Message,
				" to ",
			)

			if index < 0 {
				continue
			}

			value := strings.TrimSpace(
				event.Message[index+len(" to "):],
			)

			host, portString, err :=
				net.SplitHostPort(value)

			if err != nil {
				continue
			}

			port, err :=
				strconv.Atoi(portString)

			if err != nil {
				continue
			}

			targetType := "host_port"
			normalizedHost := normalizeDomain(host)

			if ip := net.ParseIP(host); ip != nil {
				targetType = "ip_port"
				normalizedHost = ip.String()
			}

			normalizedValue :=
				net.JoinHostPort(
					normalizedHost,
					strconv.Itoa(port),
				)

			key :=
				targetType + ":" +
					normalizedValue

			targets[key] =
				networkTarget{
					Value: normalizedValue,
					Type:  targetType,
					Host:  normalizedHost,
					Port:  port,
				}

			continue
		}

		// IRC target:
		//
		// Simulating IRC traffic to example.com
		// Simulating IRC traffic to 10.0.0.10:6667
		if strings.HasPrefix(
			event.Message,
			"Simulating IRC traffic to ",
		) {

			value := strings.TrimSpace(
				strings.TrimPrefix(
					event.Message,
					"Simulating IRC traffic to ",
				),
			)

			if value == "" {
				continue
			}

			// First try to interpret the IRC target
			// as an IP:port endpoint.
			if host, portString, err :=
				net.SplitHostPort(value); err == nil {

				port, err :=
					strconv.Atoi(
						portString,
					)

				if err != nil {
					continue
				}

				key :=
					"ip_port:" + value

				targets[key] =
					networkTarget{
						Value: value,
						Type:  "ip_port",
						Host:  host,
						Port:  port,
					}

				continue
			}

			// Otherwise interpret the IRC target
			// as a DNS hostname.
			domain :=
				normalizeDomain(
					value,
				)

			if domain == "" {
				continue
			}

			if strings.ContainsAny(
				domain,
				" \t\r\n",
			) {
				continue
			}

			key :=
				"dns:" + domain

			targets[key] =
				networkTarget{
					Value: domain,
					Type:  "dns",
					Host:  domain,
				}

			continue
		}

		// Scan target:
		//
		// Port scanning 192.0.2.10
		if strings.HasPrefix(
			event.Message,
			"Port scanning ",
		) {

			value := strings.TrimSpace(
				strings.TrimPrefix(
					event.Message,
					"Port scanning ",
				),
			)

			ip := net.ParseIP(value)

			if ip == nil {
				continue
			}

			normalized := ip.String()

			key :=
				"ip:" + normalized

			targets[key] =
				networkTarget{
					Value: normalized,
					Type:  "ip",
					Host:  normalized,
				}

			continue
		}

		// Cleartext target:
		//
		// Sending random data to 192.0.2.10:8080
		if strings.HasPrefix(
			event.Message,
			"Sending random data to ",
		) {

			value := strings.TrimSpace(
				strings.TrimPrefix(
					event.Message,
					"Sending random data to ",
				),
			)

			host, portString, err :=
				net.SplitHostPort(
					value,
				)

			if err != nil {
				continue
			}

			port, err :=
				strconv.Atoi(
					portString,
				)

			if err != nil {
				continue
			}

			key :=
				"ip_port:" + value

			targets[key] =
				networkTarget{
					Value: value,
					Type:  "ip_port",
					Host:  host,
					Port:  port,
				}

			continue
		}

		// Generic DNS target:
		//
		// Resolving example.com
		if strings.HasPrefix(
			event.Message,
			"Resolving ",
		) {

			value := strings.TrimSpace(
				strings.TrimPrefix(
					event.Message,
					"Resolving ",
				),
			)

			// FlightSim headers such as:
			//
			// Resolving random imposter domains
			//
			// are descriptions rather than real DNS targets.
			if value == "" ||
				strings.ContainsAny(
					value,
					" \t\r\n",
				) {

				continue
			}

			value =
				normalizeDomain(
					value,
				)

			if value == "" {
				continue
			}

			key :=
				"dns:" + value

			targets[key] =
				networkTarget{
					Value: value,
					Type:  "dns",
					Host:  value,
				}

			continue
		}

		// Generic IP:port target:
		//
		// Connecting to 10.0.0.10:4444
		if strings.HasPrefix(
			event.Message,
			"Connecting to ",
		) {

			value := strings.TrimSpace(
				strings.TrimPrefix(
					event.Message,
					"Connecting to ",
				),
			)

			host, portString, err :=
				net.SplitHostPort(
					value,
				)

			if err != nil {
				continue
			}

			port, err :=
				strconv.Atoi(
					portString,
				)

			if err != nil {
				continue
			}

			targetType := "ip_port"
			normalizedHost := host

			if ip := net.ParseIP(host); ip != nil {

				normalizedHost =
					ip.String()

			} else {

				targetType =
					"host_port"

				normalizedHost =
					normalizeDomain(host)
			}

			normalizedValue :=
				net.JoinHostPort(
					normalizedHost,
					strconv.Itoa(port),
				)

			key :=
				targetType + ":" + normalizedValue

			targets[key] =
				networkTarget{
					Value: normalizedValue,
					Type:  targetType,
					Host:  normalizedHost,
					Port:  port,
				}

			continue
		}
	}

	return targets
}

func loadDNSResolutions(
	evePath string,
) (map[string]map[string]bool, error) {

	resolutions :=
		make(
			map[string]map[string]bool,
		)

	file, err :=
		os.Open(evePath)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	type dnsRecord struct {
		EventType string `json:"event_type"`

		DNS struct {
			Answers []struct {
				RRName string `json:"rrname"`
				RData  string `json:"rdata"`
			} `json:"answers"`
		} `json:"dns"`
	}

	scanner :=
		bufio.NewScanner(file)

	for scanner.Scan() {

		var record dnsRecord

		if err :=
			json.Unmarshal(
				scanner.Bytes(),
				&record,
			); err != nil {

			continue
		}

		if record.EventType != "dns" {
			continue
		}

		for _, answer := range record.DNS.Answers {

			host :=
				normalizeDomain(
					answer.RRName,
				)

			ip :=
				net.ParseIP(
					strings.TrimSpace(
						answer.RData,
					),
				)

			// MX/CNAME-style answers may contain
			// another hostname instead of an IP.
			// We only need actual A/AAAA answers here.
			if host == "" ||
				ip == nil {

				continue
			}

			if resolutions[host] == nil {

				resolutions[host] =
					make(
						map[string]bool,
					)
			}

			resolutions[host][ip.String()] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return resolutions, nil
}

// correlateDNSIPTargets correlates one FlightSim module's
// generated DNS/IP targets with Suricata telemetry.
//
// DNS targets are matched against Suricata DNS rrname values.
// IP:port targets are matched against Suricata flow/alert endpoints.
// IP targets are matched against Suricata source/destination IPs.
func correlateDNSIPTargets(
	module string,
	events []scenario.Event,
	evePath string,
) (scenario.DetectionMetrics, error) {

	targets := extractDNSIPTargets(
		module,
		events,
	)

	metrics := scenario.DetectionMetrics{
		TargetsTotal:    len(targets),
		ObservedTargets: []string{},
		AlertedTargets:  []string{},
		TargetResults:   []scenario.TargetResult{},
	}

	if len(targets) == 0 {
		return metrics, nil
	}

	resolutions, err :=
		loadDNSResolutions(
			evePath,
		)

	if err != nil {
		return metrics, fmt.Errorf(
			"failed to load DNS resolutions: %w",
			err,
		)
	}

	file, err := os.Open(
		evePath,
	)

	if err != nil {
		return metrics, fmt.Errorf(
			"failed to open Suricata EVE file for %s correlation: %w",
			module,
			err,
		)
	}

	defer file.Close()

	observed := make(
		map[string]bool,
	)

	alerted := make(
		map[string]bool,
	)

	scanner := bufio.NewScanner(
		file,
	)

	for scanner.Scan() {

		var record eveCorrelationRecord

		if err := json.Unmarshal(
			scanner.Bytes(),
			&record,
		); err != nil {
			continue
		}

		switch record.EventType {

		case "dns":

			// Match generated DNS targets against
			// Suricata DNS telemetry.
			for _, query := range record.DNS.Queries {

				name := normalizeDomain(
					query.RRName,
				)

				key :=
					"dns:" + name

				if _, ok := targets[key]; ok {
					observed[key] = true
				}
			}

		case "flow":

			// Match generated IP:port and IP targets against
			// Suricata flow endpoints.
			for key, target := range targets {

				matched := false

				if target.Type == "ip_port" {
					matched = endpointMatches(
						record,
						target.Host,
						target.Port,
					)
				}

				if !matched && target.Type == "ip" {
					matched = ipMatches(
						target,
						record.SrcIP,
						record.DestIP,
					)
				}

				if !matched && target.Type == "host_port" {
					matched = hostPortMatches(
						target,
						record.SrcIP,
						record.SrcPort,
						record.DestIP,
						record.DestPort,
						resolutions,
					)
				}

				if matched {
					observed[key] = true
				}
			}

		case "alert":

			// Match DNS-based alerts.
			for _, query := range record.DNS.Queries {

				name := normalizeDomain(
					query.RRName,
				)

				key :=
					"dns:" + name

				if _, ok := targets[key]; ok {
					alerted[key] = true
				}
			}

			// Match generated IP:port and IP targets against
			// Suricata alert endpoints.
			for key, target := range targets {

				matched := false

				if target.Type == "ip_port" {
					matched = endpointMatches(
						record,
						target.Host,
						target.Port,
					)
				}

				if !matched && target.Type == "ip" {
					matched = ipMatches(
						target,
						record.SrcIP,
						record.DestIP,
					)
				}

				if !matched && target.Type == "host_port" {
					matched = hostPortMatches(
						target,
						record.SrcIP,
						record.SrcPort,
						record.DestIP,
						record.DestPort,
						resolutions,
					)
				}

				if matched {
					alerted[key] = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return metrics, fmt.Errorf(
			"failed while reading Suricata EVE file for %s correlation: %w",
			module,
			err,
		)
	}

	return finalizeDNSIPMetrics(
		targets,
		observed,
		alerted,
	), nil
}

// CorrelateC2 is kept for backwards compatibility.
//
// Existing code or tests that directly call CorrelateC2
// continue to correlate only C2 events.
func CorrelateC2(
	events []scenario.Event,
	evePath string,
) (scenario.DetectionMetrics, error) {

	return correlateDNSIPTargets(
		"c2",
		events,
		evePath,
	)
}

// endpointMatches checks whether a Suricata record contains
// the requested IP and port as either its source or destination.
func endpointMatches(
	record eveCorrelationRecord,
	host string,
	port int,
) bool {

	if record.DestIP == host &&
		record.DestPort == port {

		return true
	}

	if record.SrcIP == host &&
		record.SrcPort == port {

		return true
	}

	return false
}

// ipMatches checks whether an IP-only target appears as either
// the source or destination IP in a Suricata record.
func ipMatches(
	target networkTarget,
	srcIP string,
	destIP string,
) bool {

	return target.Type == "ip" &&
		(srcIP == target.Host ||
			destIP == target.Host)
}

func hostPortMatches(
	target networkTarget,
	srcIP string,
	srcPort int,
	destIP string,
	destPort int,
	resolutions map[string]map[string]bool,
) bool {

	if target.Type !=
		"host_port" {

		return false
	}

	ips :=
		resolutions[normalizeDomain(target.Host)]

	if len(ips) == 0 {
		return false
	}

	if srcPort == target.Port &&
		ips[srcIP] {

		return true
	}

	if destPort == target.Port &&
		ips[destIP] {

		return true
	}

	return false
}

func baseModuleName(module string) string {
	if i := strings.IndexByte(module, ':'); i >= 0 {
		return module[:i]
	}

	return module
}

// finalizeDNSIPMetrics builds final detection metrics from
// the unique generated, observed and alerted DNS/IP targets.
func finalizeDNSIPMetrics(
	targets map[string]networkTarget,
	observed map[string]bool,
	alerted map[string]bool,
) scenario.DetectionMetrics {

	metrics := scenario.DetectionMetrics{
		TargetsTotal:    len(targets),
		ObservedTargets: []string{},
		AlertedTargets:  []string{},
		TargetResults:   []scenario.TargetResult{},
	}

	keys := make(
		[]string,
		0,
		len(targets),
	)

	for key := range targets {

		keys = append(
			keys,
			key,
		)
	}

	sort.Strings(
		keys,
	)

	for _, key := range keys {

		target :=
			targets[key]

		isObserved :=
			observed[key]

		isAlerted :=
			alerted[key]

		metrics.TargetResults = append(
			metrics.TargetResults,
			scenario.TargetResult{
				Value:    target.Value,
				Type:     target.Type,
				Observed: isObserved,
				Alerted:  isAlerted,
			},
		)

		if isObserved {

			metrics.ObservedTargets = append(
				metrics.ObservedTargets,
				target.Value,
			)
		}

		if isAlerted {

			metrics.AlertedTargets = append(
				metrics.AlertedTargets,
				target.Value,
			)
		}
	}

	metrics.TargetsObserved =
		len(
			metrics.ObservedTargets,
		)

	metrics.TargetsAlerted =
		len(
			metrics.AlertedTargets,
		)

	if metrics.TargetsTotal > 0 {

		metrics.VisibilityRate =
			float64(
				metrics.TargetsObserved,
			) /
				float64(
					metrics.TargetsTotal,
				) *
				100

		metrics.DetectionRate =
			float64(
				metrics.TargetsAlerted,
			) /
				float64(
					metrics.TargetsTotal,
				) *
				100
	}

	return metrics
}
