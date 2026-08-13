package capture

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Session represents one running tcpdump capture.
type Session struct {
	cmd    *exec.Cmd
	done   chan error
	stderr bytes.Buffer

	Path string
}

// Start begins packet capture on the requested interface.
func Start(iface string, runID string) (*Session, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf(
			"automatic packet capture is currently supported only on Linux",
		)
	}

	if iface == "" {
		return nil, fmt.Errorf(
			"packet capture requires an explicit interface",
		)
	}

	tempFile, err := os.CreateTemp(
		"",
		runID+"-*.pcap",
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to prepare temporary PCAP path: %w",
			err,
		)
	}

	path := tempFile.Name()

	if err := tempFile.Close(); err != nil {
		return nil, err
	}

	// tcpdump will create the actual capture file itself.
	_ = os.Remove(path)

	session := &Session{
		Path: path,
		done: make(chan error, 1),
	}

	session.cmd = exec.Command(
		"tcpdump",
		"--immediate-mode",
		"-i",
		iface,
		"-U",
		"-s",
		"0",
		"-w",
		path,
	)

	session.cmd.Stdout = io.Discard
	session.cmd.Stderr = &session.stderr

	if err := session.cmd.Start(); err != nil {
		return nil, fmt.Errorf(
			"failed to start tcpdump: %w",
			err,
		)
	}

	go func() {
		session.done <- session.cmd.Wait()
	}()

	// Give tcpdump a short period to open the interface
	// before FlightSim starts generating traffic.
	time.Sleep(300 * time.Millisecond)

	select {
	case err := <-session.done:
		return nil, fmt.Errorf(
			"tcpdump exited during startup: %v: %s",
			err,
			session.stderr.String(),
		)

	default:
	}

	return session, nil
}

// Stop asks tcpdump to finish and close the PCAP cleanly.
func (s *Session) Stop() error {
	if s == nil || s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
		return fmt.Errorf(
			"failed to stop tcpdump: %w",
			err,
		)
	}

	select {
	case err := <-s.done:
		if err != nil {
			return fmt.Errorf(
				"tcpdump stopped with error: %w: %s",
				err,
				s.stderr.String(),
			)
		}

		return nil

	case <-time.After(3 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done

		return fmt.Errorf(
			"tcpdump did not stop cleanly",
		)
	}
}
