package coverage

import (
	"sort"
	"strings"
	"time"

	"flightlab/internal/evidence"
	"flightlab/internal/scenario"
)

type Row struct {
	Module string `json:"module"`

	Tested bool `json:"tested"`

	RunID     string     `json:"run_id,omitempty"`
	StartedAt *time.Time `json:"started_at,omitempty"`

	TargetsTotal    int `json:"targets_total"`
	TargetsObserved int `json:"targets_observed"`
	TargetsAlerted  int `json:"targets_alerted"`

	VisibilityRate float64 `json:"visibility_rate"`
	DetectionRate  float64 `json:"detection_rate"`

	Diagnosis scenario.DiagnosisStatus `json:"diagnosis,omitempty"`
}

type Matrix struct {
	TotalModules  int `json:"total_modules"`
	TestedModules int `json:"tested_modules"`

	Rows []Row `json:"rows"`
}

func baseModuleName(
	module string,
) string {

	if i := strings.IndexByte(
		module,
		':',
	); i >= 0 {

		return module[:i]
	}

	return module
}

func Build(
	baseDir string,
	modules []string,
) (Matrix, error) {

	moduleNames :=
		append(
			[]string{},
			modules...,
		)

	sort.Strings(
		moduleNames,
	)

	rows :=
		make(
			map[string]Row,
		)

	for _, module := range moduleNames {

		rows[module] =
			Row{
				Module: module,
			}
	}

	runs, err :=
		evidence.ListRuns(
			baseDir,
		)

	if err != nil {
		return Matrix{}, err
	}

	// ListRuns returns newest runs first.
	for _, run := range runs {

		// Dry runs do not provide real detection coverage.
		if run.DryRun {
			continue
		}

		module :=
			baseModuleName(
				run.Module,
			)

		row, supported :=
			rows[module]

		if !supported {
			continue
		}

		// We already found the newest usable
		// result for this module.
		if row.Tested {
			continue
		}

		result, err :=
			evidence.LoadRun(
				baseDir,
				run.ID,
			)

		if err != nil {
			continue
		}

		// A coverage row needs actual correlation
		// metrics and a diagnosis.
		if result.Metrics == nil ||
			result.Diagnosis == nil {

			continue
		}

		startedAt :=
			result.StartedAt

		row.Tested = true
		row.RunID = result.ID
		row.StartedAt = &startedAt

		row.TargetsTotal =
			result.Metrics.TargetsTotal

		row.TargetsObserved =
			result.Metrics.TargetsObserved

		row.TargetsAlerted =
			result.Metrics.TargetsAlerted

		row.VisibilityRate =
			result.Metrics.VisibilityRate

		row.DetectionRate =
			result.Metrics.DetectionRate

		row.Diagnosis =
			result.Diagnosis.OverallStatus

		rows[module] = row
	}

	matrix :=
		Matrix{
			TotalModules: len(moduleNames),

			Rows: make(
				[]Row,
				0,
				len(moduleNames),
			),
		}

	for _, module := range moduleNames {

		row :=
			rows[module]

		if row.Tested {
			matrix.TestedModules++
		}

		matrix.Rows =
			append(
				matrix.Rows,
				row,
			)
	}

	return matrix, nil
}
