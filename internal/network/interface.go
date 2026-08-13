package network

import (
	"fmt"
	"net"
)

// DefaultInterface determines which network interface
// the operating system would use for outbound IPv4 traffic.
func DefaultInterface() (string, error) {
	conn, err := net.Dial(
		"udp",
		"1.1.1.1:53",
	)
	if err != nil {
		return "", fmt.Errorf(
			"failed to determine default route: %w",
			err,
		)
	}
	defer conn.Close()

	localAddr, ok :=
		conn.LocalAddr().(*net.UDPAddr)

	if !ok {
		return "", fmt.Errorf(
			"could not determine local address",
		)
	}

	localIP := localAddr.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf(
			"failed to list network interfaces: %w",
			err,
		)
	}

	for _, iface := range interfaces {

		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {

			var ip net.IP

			switch value := addr.(type) {

			case *net.IPNet:
				ip = value.IP

			case *net.IPAddr:
				ip = value.IP
			}

			if ip != nil &&
				ip.Equal(localIP) {

				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf(
		"could not map default IP %s to an interface",
		localIP.String(),
	)
}
