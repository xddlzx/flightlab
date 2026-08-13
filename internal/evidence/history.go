package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"flightlab/internal/scenario"
)

// RunSummary contains the small amount of information
// needed to display one previous run in the dashboard.
type RunSummary struct {
	ID         string        `json:"id"`
	Module     string        `json:"module"`
	Success    bool          `json:"success"`
	DryRun     bool          `json:"dry_run"`
	StartedAt  time.Time     `json:"started_at"`
	Duration   time.Duration `json:"duration"`
	EventCount int           `json:"event_count"`
}

// ListRuns reads previously saved FlightLab results.
func ListRuns(baseDir string) ([]RunSummary, error) {
	entries, err := os.ReadDir(baseDir)

	if os.IsNotExist(err) {
		return []RunSummary{}, nil
	}

	if err != nil {
		return nil, err
	}

	runs := make([]RunSummary, 0)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		resultPath := filepath.Join(
			baseDir,
			entry.Name(),
			"result.json",
		)

		data, err := os.ReadFile(resultPath)
		if err != nil {
			continue
		}

		var result scenario.Result

		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}

		runs = append(runs, RunSummary{
			ID:         result.ID,
			Module:     result.Config.Module,
			Success:    result.Success,
			DryRun:     result.Config.DryRun,
			StartedAt:  result.StartedAt,
			Duration:   result.Duration,
			EventCount: len(result.Events),
		})
	}

	// Newest runs first.
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].StartedAt.After(
			runs[j].StartedAt,
		)
	})

	return runs, nil
}
func LoadRun(
	baseDir string,
	id string,
) (scenario.Result, error) {

	var result scenario.Result

	if id == "" ||
		strings.ContainsAny(id, `/\`) {

		return result, fmt.Errorf(
			"invalid run ID",
		)
	}

	resultPath := filepath.Join(
		baseDir,
		id,
		"result.json",
	)

	data, err := os.ReadFile(resultPath)
	if err != nil {
		return result, fmt.Errorf(
			"failed to read run result: %w",
			err,
		)
	}

	if err := json.Unmarshal(
		data,
		&result,
	); err != nil {

		return result, fmt.Errorf(
			"failed to decode run result: %w",
			err,
		)
	}

	return result, nil
}
