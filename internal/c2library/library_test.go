package c2library

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidLibrary(
	t *testing.T,
) {

	dir :=
		t.TempDir()

	path :=
		filepath.Join(
			dir,
			"c2.txt",
		)

	content := `
# test library

dns:beacon-one.test
dns:beacon-two.test

ip:10.0.3.20:4444
ip:192.168.56.50:8080
`

	err :=
		os.WriteFile(
			path,
			[]byte(content),
			0644,
		)

	if err != nil {
		t.Fatal(err)
	}

	library, err :=
		Load(path)

	if err != nil {
		t.Fatal(err)
	}

	if len(library.Targets) != 4 {

		t.Fatalf(
			"expected 4 targets, got %d",
			len(library.Targets),
		)
	}

	if len(
		library.DNSTargets(),
	) != 2 {

		t.Fatalf(
			"expected 2 DNS targets",
		)
	}

	if len(
		library.IPPortTargets(),
	) != 2 {

		t.Fatalf(
			"expected 2 IP targets",
		)
	}
}

func TestRejectPublicIP(
	t *testing.T,
) {

	dir :=
		t.TempDir()

	path :=
		filepath.Join(
			dir,
			"bad.txt",
		)

	content :=
		"ip:8.8.8.8:443\n"

	err :=
		os.WriteFile(
			path,
			[]byte(content),
			0644,
		)

	if err != nil {
		t.Fatal(err)
	}

	_, err =
		Load(path)

	if err == nil {

		t.Fatal(
			"expected public IP to be rejected",
		)
	}
}
