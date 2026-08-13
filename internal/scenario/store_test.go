package scenario

import (
	"path/filepath"
	"testing"
)

func TestSaveAndLoadDefinition(
	t *testing.T,
) {

	dir := t.TempDir()

	config := Config{
		Module:    "c2",
		Size:      2,
		DryRun:    true,
		Capture:   false,
		Suricata:  false,
		C2Library: "libraries/example-c2.txt",
	}

	path, err :=
		SaveDefinition(
			dir,
			"custom-c2-test",
			config,
		)

	if err != nil {
		t.Fatal(err)
	}

	definition, err :=
		LoadDefinition(path)

	if err != nil {
		t.Fatal(err)
	}

	if definition.Name !=
		"custom-c2-test" {

		t.Fatalf(
			"unexpected scenario name %q",
			definition.Name,
		)
	}

	if definition.Config.Module != "c2" {
		t.Fatalf(
			"expected c2 module, got %q",
			definition.Config.Module,
		)
	}

	if definition.Config.Size != 2 {
		t.Fatalf(
			"expected size 2, got %d",
			definition.Config.Size,
		)
	}

	if definition.Config.C2Library !=
		"libraries/example-c2.txt" {

		t.Fatalf(
			"unexpected C2 library %q",
			definition.Config.C2Library,
		)
	}

	expectedPath :=
		filepath.Join(
			dir,
			"custom-c2-test.json",
		)

	if path != expectedPath {
		t.Fatalf(
			"expected path %q, got %q",
			expectedPath,
			path,
		)
	}
}

func TestRejectInvalidScenarioName(
	t *testing.T,
) {

	_, err :=
		SaveDefinition(
			t.TempDir(),
			"../../bad",
			Config{
				Module: "c2",
			},
		)

	if err == nil {
		t.Fatal(
			"expected invalid scenario name to be rejected",
		)
	}
}
