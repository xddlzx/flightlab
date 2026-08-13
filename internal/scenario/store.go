package scenario

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var scenarioNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type Definition struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Config    Config    `json:"config"`
}

func SaveDefinition(
	baseDir string,
	name string,
	config Config,
) (string, error) {

	if !scenarioNamePattern.MatchString(name) {
		return "",
			fmt.Errorf(
				"invalid scenario name %q",
				name,
			)
	}

	if err := os.MkdirAll(
		baseDir,
		0755,
	); err != nil {
		return "",
			fmt.Errorf(
				"failed to create scenario directory: %w",
				err,
			)
	}

	definition := Definition{
		Version:   1,
		Name:      name,
		CreatedAt: time.Now(),
		Config:    config,
	}

	data, err :=
		json.MarshalIndent(
			definition,
			"",
			"  ",
		)

	if err != nil {
		return "",
			fmt.Errorf(
				"failed to encode scenario: %w",
				err,
			)
	}

	path :=
		filepath.Join(
			baseDir,
			name+".json",
		)

	if err := os.WriteFile(
		path,
		data,
		0644,
	); err != nil {
		return "",
			fmt.Errorf(
				"failed to save scenario: %w",
				err,
			)
	}

	return path, nil
}

func LoadDefinition(
	path string,
) (Definition, error) {

	var definition Definition

	data, err :=
		os.ReadFile(path)

	if err != nil {
		return definition,
			fmt.Errorf(
				"failed to read scenario: %w",
				err,
			)
	}

	if err :=
		json.Unmarshal(
			data,
			&definition,
		); err != nil {

		return definition,
			fmt.Errorf(
				"failed to decode scenario: %w",
				err,
			)
	}

	if definition.Version != 1 {
		return definition,
			fmt.Errorf(
				"unsupported scenario version %d",
				definition.Version,
			)
	}

	if !scenarioNamePattern.MatchString(
		definition.Name,
	) {
		return definition,
			fmt.Errorf(
				"invalid scenario name",
			)
	}

	return definition, nil
}
