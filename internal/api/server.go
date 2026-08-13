package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"flightlab/internal/c2library"
	"flightlab/internal/coverage"
	"flightlab/internal/detection"
	"flightlab/internal/diagnosis"
	"flightlab/internal/evidence"
	"flightlab/internal/regression"
	"flightlab/internal/runner"
	"flightlab/internal/scenario"
)

// Server exposes FlightLab functionality through a small local HTTP API.
type Server struct {
	Runner     runner.Runner
	ResultsDir string
}

// regressionRequest describes one regression re-analysis request.
type regressionRequest struct {
	RunID     string `json:"run_id"`
	RulesPath string `json:"rules_path"`
}

// Handler creates the HTTP routes used by the web UI.
func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(
		"/api/health",
		s.handleHealth,
	)

	mux.HandleFunc(
		"/api/modules",
		s.handleModules,
	)

	mux.HandleFunc(
		"/api/run",
		s.handleRun,
	)

	mux.HandleFunc(
		"/api/runs",
		s.handleRuns,
	)

	mux.HandleFunc(
		"/api/runs/",
		s.handleRunDetail,
	)

	mux.HandleFunc(
		"/api/c2-library",
		s.handleC2LibraryUpload,
	)

	mux.HandleFunc(
		"/api/regression-rules",
		s.handleRegressionRulesUpload,
	)
	mux.HandleFunc(
		"/api/regression",
		s.handleRegression,
	)

	mux.Handle(
		"/",
		http.FileServer(
			http.Dir("web"),
		),
	)

	mux.HandleFunc(
		"/api/coverage",
		s.handleCoverage,
	)
	return mux
}

// handleC2LibraryUpload accepts a custom C2 target library
// from the web UI, validates it, and stores it under
// libraries/uploads/.
func (s Server) handleC2LibraryUpload(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	// Limit the complete multipart request.
	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		128*1024,
	)

	if err := r.ParseMultipartForm(
		128 * 1024,
	); err != nil {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid or oversized upload",
			},
		)
		return
	}

	file, header, err :=
		r.FormFile("file")

	if err != nil {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "C2 library file is required",
			},
		)
		return
	}

	defer file.Close()

	// Individual C2 library files may not exceed 64 KB.
	if header.Size > 64*1024 {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "C2 library must be smaller than 64 KB",
			},
		)
		return
	}

	// Only plain .txt target libraries are accepted.
	if strings.ToLower(
		filepath.Ext(header.Filename),
	) != ".txt" {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "C2 library must be a .txt file",
			},
		)
		return
	}

	uploadDir := filepath.Join(
		"libraries",
		"uploads",
	)

	if err := os.MkdirAll(
		uploadDir,
		0755,
	); err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "failed to create library upload directory",
			},
		)
		return
	}

	fileName := fmt.Sprintf(
		"c2-%d.txt",
		time.Now().UnixNano(),
	)

	path := filepath.Join(
		uploadDir,
		fileName,
	)

	destination, err :=
		os.Create(path)

	if err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "failed to store C2 library",
			},
		)
		return
	}

	_, copyErr :=
		io.Copy(
			destination,
			file,
		)

	closeErr :=
		destination.Close()

	if copyErr != nil ||
		closeErr != nil {

		_ = os.Remove(path)

		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "failed to save C2 library",
			},
		)
		return
	}

	// Validate the uploaded file using the same C2
	// library parser used by the runner.
	library, err :=
		c2library.Load(path)

	if err != nil {
		_ = os.Remove(path)

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": err.Error(),
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"path": filepath.ToSlash(
				path,
			),
			"targets": len(
				library.Targets,
			),
			"dns": len(
				library.DNSTargets(),
			),
			"ip_targets": len(
				library.IPPortTargets(),
			),
		},
	)
}

// handleRegressionRulesUpload accepts a Suricata rules file
// and stores it temporarily outside the repository.
func (s Server) handleRegressionRulesUpload(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		512*1024,
	)

	if err := r.ParseMultipartForm(
		512 * 1024,
	); err != nil {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid or oversized rules upload",
			},
		)
		return
	}

	file, header, err :=
		r.FormFile("file")

	if err != nil {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "Suricata rules file is required",
			},
		)
		return
	}

	defer file.Close()

	if strings.ToLower(
		filepath.Ext(header.Filename),
	) != ".rules" {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "file must use the .rules extension",
			},
		)
		return
	}

	uploadDir := filepath.Join(
		os.TempDir(),
		"flightlab-regression-rules",
	)

	if err := os.MkdirAll(
		uploadDir,
		0755,
	); err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "failed to create rules upload directory",
			},
		)
		return
	}

	fileName := fmt.Sprintf(
		"rules-%d.rules",
		time.Now().UnixNano(),
	)

	path := filepath.Join(
		uploadDir,
		fileName,
	)

	destination, err :=
		os.Create(path)

	if err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "failed to store rules file",
			},
		)
		return
	}

	_, copyErr :=
		io.Copy(
			destination,
			file,
		)

	closeErr :=
		destination.Close()

	if copyErr != nil ||
		closeErr != nil {

		_ = os.Remove(path)

		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": "failed to save rules file",
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"name": header.Filename,
			"path": filepath.ToSlash(
				path,
			),
		},
	)
}

// handleRegression re-analyzes an existing FlightLab
// capture using a supplied Suricata ruleset.
func (s Server) handleRegression(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	decoder :=
		json.NewDecoder(
			r.Body,
		)

	decoder.DisallowUnknownFields()

	var request regressionRequest

	if err :=
		decoder.Decode(
			&request,
		); err != nil {

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid regression request",
			},
		)
		return
	}

	if request.RunID == "" {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "run_id is required",
			},
		)
		return
	}

	// Custom rules are optional.
	//
	// If no rules file is supplied, Suricata uses
	// FlightLab's current/default Suricata configuration.
	if request.RulesPath != "" {

		rulesRoot, err :=
			filepath.Abs(
				filepath.Join(
					os.TempDir(),
					"flightlab-regression-rules",
				),
			)

		if err != nil {
			writeJSON(
				w,
				http.StatusInternalServerError,
				map[string]string{
					"error": "failed to resolve temporary rules directory",
				},
			)
			return
		}

		rulesPath, err :=
			filepath.Abs(
				request.RulesPath,
			)

		if err != nil {
			writeJSON(
				w,
				http.StatusBadRequest,
				map[string]string{
					"error": "invalid rules path",
				},
			)
			return
		}

		relative, err :=
			filepath.Rel(
				rulesRoot,
				rulesPath,
			)

		if err != nil ||
			relative == ".." ||
			strings.HasPrefix(
				relative,
				".."+string(os.PathSeparator),
			) {

			writeJSON(
				w,
				http.StatusBadRequest,
				map[string]string{
					"error": "rules file must come from FlightLab's temporary upload directory",
				},
			)
			return
		}

		// Reanalyze() preserves the exact rules file
		// inside regression evidence before this temporary
		// upload is deleted.
		defer os.Remove(
			rulesPath,
		)
	}

	result, err :=
		regression.Reanalyze(
			s.ResultsDir,
			request.RunID,
			request.RulesPath,
		)

	if err != nil {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": err.Error(),
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		result,
	)
}

func (s Server) handleRunDetail(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	id := strings.TrimPrefix(
		r.URL.Path,
		"/api/runs/",
	)

	if id == "" ||
		strings.Contains(id, "/") {

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid run ID",
			},
		)
		return
	}

	result, err :=
		evidence.LoadRun(
			s.ResultsDir,
			id,
		)

	if err != nil {
		writeJSON(
			w,
			http.StatusNotFound,
			map[string]string{
				"error": err.Error(),
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"result": result,
		},
	)
}

func (s Server) handleHealth(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]string{
			"status": "ok",
		},
	)
}

func (s Server) handleModules(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	modules := make(
		[]string,
		0,
		len(runner.AllowedModules),
	)

	for module := range runner.AllowedModules {

		modules = append(
			modules,
			module,
		)
	}

	sort.Strings(modules)

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"modules": modules,
		},
	)
}

func (s Server) handleRun(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	// Prevent unexpectedly large request bodies.
	r.Body = http.MaxBytesReader(
		w,
		r.Body,
		1024*1024,
	)

	decoder :=
		json.NewDecoder(
			r.Body,
		)

	decoder.DisallowUnknownFields()

	var config scenario.Config

	if err :=
		decoder.Decode(
			&config,
		); err != nil {

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "invalid request: " + err.Error(),
			},
		)
		return
	}

	// Protect the API from arbitrary filesystem paths.
	// Custom C2 libraries submitted by the browser must
	// live under FlightLab's libraries directory.
	if config.C2Library != "" {

		if config.Module != "c2" {
			writeJSON(
				w,
				http.StatusBadRequest,
				map[string]string{
					"error": "custom C2 library can only be used with c2",
				},
			)
			return
		}

		libraryRoot, err :=
			filepath.Abs(
				"libraries",
			)

		if err != nil {
			writeJSON(
				w,
				http.StatusInternalServerError,
				map[string]string{
					"error": "failed to resolve library directory",
				},
			)
			return
		}

		libraryPath, err :=
			filepath.Abs(
				config.C2Library,
			)

		if err != nil {
			writeJSON(
				w,
				http.StatusBadRequest,
				map[string]string{
					"error": "invalid C2 library path",
				},
			)
			return
		}

		relative, err :=
			filepath.Rel(
				libraryRoot,
				libraryPath,
			)

		if err != nil ||
			relative == ".." ||
			strings.HasPrefix(
				relative,
				".."+string(os.PathSeparator),
			) {

			writeJSON(
				w,
				http.StatusBadRequest,
				map[string]string{
					"error": "C2 library must be inside the FlightLab libraries directory",
				},
			)
			return
		}
	}

	// Validate UI/API input before executing FlightSim.
	if !runner.AllowedModules[config.Module] {
		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "unsupported FlightSim module",
			},
		)
		return
	}

	if config.Size < 1 ||
		config.Size > 100 {

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "size must be between 1 and 100",
			},
		)
		return
	}

	// Suricata analysis requires a PCAP to analyze.
	if config.Suricata &&
		!config.Capture {

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "Suricata analysis requires packet capture",
			},
		)
		return
	}

	// Suricata requires real traffic rather than a dry run.
	if config.Suricata &&
		config.DryRun {

		writeJSON(
			w,
			http.StatusBadRequest,
			map[string]string{
				"error": "Suricata analysis requires a live simulation",
			},
		)
		return
	}

	result, runErr :=
		s.Runner.Run(
			config,
		)

	// Keep Suricata/correlation failures separate from
	// FlightSim execution failures.
	//
	// The run evidence should still be preserved even when
	// detection analysis fails.
	var analysisErr error

	// If the FlightSim run succeeded and Suricata was requested,
	// analyze the temporary packet capture before saving evidence.
	if runErr == nil &&
		config.Suricata {

		analysis, err :=
			detection.AnalyzeWithSuricata(
				result.CaptureTempPath,
				result.ID,
			)

		if err != nil {

			analysisErr =
				fmt.Errorf(
					"Suricata analysis failed: %w",
					err,
				)

			result.AnalysisError =
				analysisErr.Error()

		} else {

			result.SuricataTempPath =
				analysis.EvePath

			result.SuricataTempDir =
				analysis.TempDir

			result.SuricataPath =
				"suricata-eve.json"

			result.SuricataEventCounts =
				analysis.EventCounts

			result.SuricataAlertCount =
				analysis.AlertCount

			result.SuricataAlerts =
				analysis.Alerts

			// Use the generic correlation entry point.
			metrics, err :=
				detection.Correlate(
					config.Module,
					result.Events,
					analysis.EvePath,
				)

			if err != nil {

				analysisErr =
					fmt.Errorf(
						"detection correlation failed: %w",
						err,
					)

				result.AnalysisError =
					analysisErr.Error()

			} else {

				result.Metrics =
					metrics

				result.Diagnosis =
					diagnosis.Analyze(
						result.Success,
						result.Metrics,
					)
			}
		}
	}

	// Save evidence even when FlightSim starts but later fails,
	// or when Suricata/correlation analysis fails.
	evidenceDir := ""

	if result.ID != "" {
		var saveErr error

		evidenceDir, saveErr =
			evidence.Save(
				s.ResultsDir,
				result,
			)

		if saveErr != nil {
			writeJSON(
				w,
				http.StatusInternalServerError,
				map[string]string{
					"error": saveErr.Error(),
				},
			)
			return
		}
	}

	// FlightSim itself failed.
	// Evidence has already been preserved above when possible.
	if runErr != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]any{
				"error":        runErr.Error(),
				"result":       result,
				"evidence_dir": evidenceDir,
			},
		)
		return
	}

	// FlightSim succeeded, but Suricata or correlation failed.
	// Again, evidence has already been preserved.
	if analysisErr != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]any{
				"error":        analysisErr.Error(),
				"result":       result,
				"evidence_dir": evidenceDir,
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"result":       result,
			"evidence_dir": evidenceDir,
		},
	)
}
func writeJSON(
	w http.ResponseWriter,
	status int,
	value any,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(status)

	_ = json.NewEncoder(
		w,
	).Encode(value)
}

func (s Server) handleCoverage(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	modules := make(
		[]string,
		0,
		len(runner.AllowedModules),
	)

	for module := range runner.AllowedModules {

		modules = append(
			modules,
			module,
		)
	}

	matrix, err :=
		coverage.Build(
			s.ResultsDir,
			modules,
		)

	if err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": err.Error(),
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		matrix,
	)
}

func (s Server) handleRuns(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		writeJSON(
			w,
			http.StatusMethodNotAllowed,
			map[string]string{
				"error": "method not allowed",
			},
		)
		return
	}

	runs, err :=
		evidence.ListRuns(
			s.ResultsDir,
		)

	if err != nil {
		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error": err.Error(),
			},
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"runs": runs,
		},
	)
}
