package c2library

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type TargetType string

const (
	TargetDNS    TargetType = "dns"
	TargetIPPort TargetType = "ip_port"
)

type Target struct {
	Type  TargetType `json:"type"`
	Value string     `json:"value"`

	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
}

type Library struct {
	Path    string   `json:"path"`
	Targets []Target `json:"targets"`
}

func Load(path string) (Library, error) {

	library := Library{
		Path:    path,
		Targets: []Target{},
	}

	file, err := os.Open(path)
	if err != nil {
		return library, fmt.Errorf(
			"failed to open C2 library: %w",
			err,
		)
	}
	defer file.Close()

	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)

	lineNumber := 0

	for scanner.Scan() {

		lineNumber++

		line :=
			strings.TrimSpace(
				scanner.Text(),
			)

		if line == "" ||
			strings.HasPrefix(line, "#") {

			continue
		}

		target, err :=
			parseLine(line)

		if err != nil {

			return library, fmt.Errorf(
				"line %d: %w",
				lineNumber,
				err,
			)
		}

		key :=
			string(target.Type) +
				":" +
				target.Value

		if seen[key] {
			continue
		}

		seen[key] = true

		library.Targets =
			append(
				library.Targets,
				target,
			)
	}

	if err := scanner.Err(); err != nil {

		return library, fmt.Errorf(
			"failed while reading C2 library: %w",
			err,
		)
	}

	if len(library.Targets) == 0 {

		return library, fmt.Errorf(
			"C2 library contains no valid targets",
		)
	}

	return library, nil
}

func parseLine(
	line string,
) (Target, error) {

	kind, value, found :=
		strings.Cut(line, ":")

	if !found {

		return Target{}, fmt.Errorf(
			"expected dns:<domain> or ip:<host>:<port>",
		)
	}

	kind =
		strings.ToLower(
			strings.TrimSpace(kind),
		)

	value =
		strings.TrimSpace(value)

	switch kind {

	case "dns":

		return parseDNS(value)

	case "ip":

		return parseIPPort(value)

	default:

		return Target{}, fmt.Errorf(
			"unknown target type %q",
			kind,
		)
	}
}

func parseDNS(
	value string,
) (Target, error) {

	domain :=
		strings.ToLower(
			strings.TrimSuffix(
				strings.TrimSpace(value),
				".",
			),
		)

	if !isLabDomain(domain) {

		return Target{}, fmt.Errorf(
			"DNS target %q is not a permitted lab domain",
			domain,
		)
	}

	return Target{
		Type:  TargetDNS,
		Value: domain,
		Host:  domain,
	}, nil
}

func parseIPPort(
	value string,
) (Target, error) {

	host, portString, err :=
		net.SplitHostPort(value)

	if err != nil {

		return Target{}, fmt.Errorf(
			"invalid IP:port target %q: %w",
			value,
			err,
		)
	}

	ip :=
		net.ParseIP(host)

	if ip == nil {

		return Target{}, fmt.Errorf(
			"%q is not a valid IP address",
			host,
		)
	}

	if !ip.IsPrivate() &&
		!ip.IsLoopback() {

		return Target{}, fmt.Errorf(
			"IP %q is not a private or loopback lab address",
			host,
		)
	}

	port, err :=
		strconv.Atoi(portString)

	if err != nil ||
		port < 1 ||
		port > 65535 {

		return Target{}, fmt.Errorf(
			"invalid TCP port %q",
			portString,
		)
	}

	normalized :=
		net.JoinHostPort(
			ip.String(),
			strconv.Itoa(port),
		)

	return Target{
		Type:  TargetIPPort,
		Value: normalized,
		Host:  ip.String(),
		Port:  port,
	}, nil
}

func isLabDomain(
	domain string,
) bool {

	if domain == "localhost" {
		return true
	}

	allowedSuffixes := []string{
		".test",
		".invalid",
		".localhost",
	}

	for _, suffix := range allowedSuffixes {

		if strings.HasSuffix(
			domain,
			suffix,
		) {
			return true
		}
	}

	return false
}

func (l Library) DNSTargets() []string {

	targets := []string{}

	for _, target := range l.Targets {

		if target.Type ==
			TargetDNS {

			targets =
				append(
					targets,
					target.Value,
				)
		}
	}

	return targets
}

func (l Library) IPPortTargets() []string {

	targets := []string{}

	for _, target := range l.Targets {

		if target.Type ==
			TargetIPPort {

			targets =
				append(
					targets,
					target.Value,
				)
		}
	}

	return targets
}
