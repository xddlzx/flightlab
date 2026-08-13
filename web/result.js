const params =
    new URLSearchParams(
        window.location.search
    );

const runId =
    params.get("id");


// Regression UI elements.
const regressionSection =
    document.getElementById(
        "regression-section"
    );

const regressionRulesFile =
    document.getElementById(
        "regression-rules-file"
    );

const regressionRunButton =
    document.getElementById(
        "regression-run-button"
    );

const regressionStatus =
    document.getElementById(
        "regression-status"
    );

const regressionResult =
    document.getElementById(
        "regression-result"
    );


// Stores the result currently displayed on the page.
let currentRun = null;


async function loadResult() {

    if (!runId) {
        showLoadError(
            "No run ID was provided."
        );

        return;
    }

    try {

        const response =
            await fetch(
                `/api/runs/${encodeURIComponent(runId)}`
            );

        const data =
            await response.json();

        if (!response.ok) {
            throw new Error(
                data.error ||
                "Could not load run"
            );
        }

        displayResult(
            data.result
        );

    } catch (error) {

        showLoadError(
            error.message
        );
    }
}


function displayResult(result) {

    // Remember the currently opened run.
    currentRun =
        result;


    document.getElementById(
        "result-subtitle"
    ).textContent =
        result.id;


    const status =
        document.getElementById(
            "result-status"
        );

    status.textContent =
        result.success
            ? "Success"
            : "Failed";

    status.className =
        result.success
            ? "success"
            : "failure";


    document.getElementById(
        "result-module"
    ).textContent =
        result.config.module;


    document.getElementById(
        "result-id"
    ).textContent =
        result.id;


    document.getElementById(
        "result-duration"
    ).textContent =
        (
            result.duration /
            1000000
        ).toFixed(2) + " ms";


    document.getElementById(
        "result-interface"
    ).textContent =
        result.config.interface ||
        "Automatic";


    document.getElementById(
        "result-mode"
    ).textContent =
        result.config.dry_run
            ? "Dry Run"
            : "Live";


    const counts =
        result.suricata_event_counts ||
        {};


    document.getElementById(
        "result-dns-events"
    ).textContent =
        counts.dns ?? "-";


    document.getElementById(
        "result-alert-count"
    ).textContent =
        result.suricata_alert_count ??
        "-";


    document.getElementById(
        "result-evidence"
    ).textContent =
        `results/${result.id}`;


    // Detection Metrics
    displayMetrics(
        result.metrics
    );


    // Detection Gap Diagnosis
    renderDiagnosis(
        result.diagnosis
    );


    // Suricata alerts
    displayAlerts(
        result
    );


    // Configure same-PCAP regression.
    configureRegression(
        result
    );


    // Parsed FlightSim events
    displayEvents(
        result.events || []
    );


    // Raw FlightSim output
    document.getElementById(
        "raw-output"
    ).textContent =
        result.output || "";
}


function displayMetrics(metrics) {

    const section =
        document.getElementById(
            "metrics-section"
        );

    if (!metrics) {

        section.classList.add(
            "hidden"
        );

        return;
    }


    section.classList.remove(
        "hidden"
    );


    document.getElementById(
        "metric-total"
    ).textContent =
        metrics.targets_total;


    document.getElementById(
        "metric-observed"
    ).textContent =
        metrics.targets_observed;


    document.getElementById(
        "metric-alerted"
    ).textContent =
        metrics.targets_alerted;


    document.getElementById(
        "metric-visibility"
    ).textContent =
        metrics.visibility_rate
            .toFixed(2) + "%";


    document.getElementById(
        "metric-detection"
    ).textContent =
        metrics.detection_rate
            .toFixed(2) + "%";


    displayTargets(
        "observed-targets",
        metrics.observed_targets
    );


    displayTargets(
        "alerted-targets",
        metrics.alerted_targets
    );
}


function displayTargets(
    elementId,
    targets
) {

    const list =
        document.getElementById(
            elementId
        );

    list.innerHTML = "";


    if (
        !targets ||
        targets.length === 0
    ) {

        const item =
            document.createElement(
                "li"
            );

        item.textContent =
            "None";

        list.appendChild(
            item
        );

        return;
    }


    for (const target of targets) {

        const item =
            document.createElement(
                "li"
            );

        item.textContent =
            target;

        list.appendChild(
            item
        );
    }
}


function diagnosisLabel(status) {

    switch (status) {

        case "detected":
            return "DETECTED";

        case "detection_gap":
            return "DETECTION GAP";

        case "telemetry_gap":
            return "TELEMETRY GAP";

        case "simulation_failure":
            return "SIMULATION FAILURE";

        default:
            return status || "UNKNOWN";
    }
}


function diagnosisClass(status) {

    switch (status) {

        case "detected":
            return "diagnosis-detected";

        case "detection_gap":
            return "diagnosis-detection-gap";

        case "telemetry_gap":
            return "diagnosis-telemetry-gap";

        case "simulation_failure":
            return "diagnosis-simulation-failure";

        default:
            return "";
    }
}


function renderDiagnosis(diagnosis) {

    const section =
        document.getElementById(
            "diagnosis-section"
        );

    if (
        !diagnosis ||
        !diagnosis.targets ||
        diagnosis.targets.length === 0
    ) {
        section.classList.add(
            "hidden"
        );

        return;
    }


    section.classList.remove(
        "hidden"
    );


    const status =
        document.getElementById(
            "diagnosis-status"
        );

    status.textContent =
        diagnosisLabel(
            diagnosis.overall_status
        );

    status.className =
        "diagnosis-status " +
        diagnosisClass(
            diagnosis.overall_status
        );


    document.getElementById(
        "diagnosis-reason"
    ).textContent =
        diagnosis.overall_reason || "";


    document.getElementById(
        "diag-detected"
    ).textContent =
        diagnosis.detected ?? 0;


    document.getElementById(
        "diag-detection-gaps"
    ).textContent =
        diagnosis.detection_gaps ?? 0;


    document.getElementById(
        "diag-telemetry-gaps"
    ).textContent =
        diagnosis.telemetry_gaps ?? 0;


    document.getElementById(
        "diag-simulation-failures"
    ).textContent =
        diagnosis.simulation_failures ?? 0;


    const body =
        document.getElementById(
            "diagnosis-target-body"
        );

    body.replaceChildren();


    for (const target of diagnosis.targets) {

        const row =
            document.createElement(
                "tr"
            );


        addCell(
            row,
            target.value
        );


        addCell(
            row,
            target.type
        );


        addStateCell(
            row,
            target.traffic_generated
        );


        addStateCell(
            row,
            target.observed
        );


        addStateCell(
            row,
            target.alerted
        );


        const diagnosisCell =
            document.createElement(
                "td"
            );

        const badge =
            document.createElement(
                "span"
            );

        badge.className =
            "diagnosis-badge " +
            diagnosisClass(
                target.status
            );

        badge.textContent =
            diagnosisLabel(
                target.status
            );

        diagnosisCell.appendChild(
            badge
        );

        row.appendChild(
            diagnosisCell
        );


        addCell(
            row,
            target.reason
        );


        body.appendChild(
            row
        );
    }
}


function addCell(
    row,
    value
) {

    const cell =
        document.createElement(
            "td"
        );

    cell.textContent =
        value ?? "-";

    row.appendChild(
        cell
    );
}


function addStateCell(
    row,
    value
) {

    const cell =
        document.createElement(
            "td"
        );

    cell.textContent =
        value
            ? "✓"
            : "✕";

    cell.className =
        value
            ? "state-yes"
            : "state-no";

    row.appendChild(
        cell
    );
}


// Configure whether same-PCAP regression can be used.
function configureRegression(result) {

    if (!regressionSection) {
        return;
    }

    const hasCapture =
        Boolean(
            result.capture_path
        );

    const hasMetrics =
        Boolean(
            result.metrics &&
            result.metrics.target_results &&
            result.metrics.target_results.length > 0
        );


    if (
        !hasCapture ||
        !hasMetrics
    ) {

        regressionSection.classList.add(
            "hidden"
        );

        return;
    }


    regressionSection.classList.remove(
        "hidden"
    );
}


// Upload a Suricata .rules file to FlightLab.
async function uploadRegressionRules() {

    const file =
        regressionRulesFile.files[0];


    if (!file) {
        return "";
    }


    const formData =
        new FormData();

    formData.append(
        "file",
        file
    );


    regressionStatus.className =
        "regression-status";

    regressionStatus.textContent =
        "Uploading ruleset...";


    const response =
        await fetch(
            "/api/regression-rules",
            {
                method: "POST",
                body: formData
            }
        );


    const data =
        await response.json();


    if (!response.ok) {

        throw new Error(
            data.error ||
            "Rules upload failed."
        );
    }


    return data.path;
}


// Re-analyze the original PCAP from the baseline run.
// A custom Suricata ruleset is optional.
async function runRegression() {

    if (!currentRun) {
        return;
    }


    regressionRunButton.disabled =
        true;

    regressionResult.classList.add(
        "hidden"
    );


    try {

        const hasRules =
            regressionRulesFile &&
            regressionRulesFile.files.length > 0;


        const rulesPath =
            hasRules
                ? await uploadRegressionRules()
                : "";


        regressionStatus.className =
            "regression-status";


        regressionStatus.textContent =
            hasRules
                ? "Re-analyzing the original PCAP with the uploaded ruleset..."
                : "Re-analyzing the original PCAP with the current Suricata configuration...";


        const response =
            await fetch(
                "/api/regression",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            run_id:
                                currentRun.id,

                            rules_path:
                                rulesPath
                        })
                }
            );


        const data =
            await response.json();


        if (!response.ok) {
            throw new Error(
                data.error ||
                "Regression analysis failed."
            );
        }


        regressionStatus.className =
            "regression-status success";


        regressionStatus.textContent =
            hasRules
                ? "Rules regression on the original PCAP completed."
                : "Original-PCAP re-analysis completed.";


        renderRegression(
            data
        );

    } catch (error) {

        regressionStatus.className =
            "regression-status error";

        regressionStatus.textContent =
            `Error: ${error.message}`;

    } finally {

        regressionRunButton.disabled =
            false;
    }
}


// Display the regression comparison.
function renderRegression(data) {

    const comparison =
        data.comparison;


    if (!comparison) {
        return;
    }


    regressionResult.classList.remove(
        "hidden"
    );


    document.getElementById(
        "reg-baseline-rate"
    ).textContent =
        `${comparison.baseline_detection_rate.toFixed(2)}%`;


    document.getElementById(
        "reg-current-rate"
    ).textContent =
        `${comparison.current_detection_rate.toFixed(2)}%`;


    const change =
        comparison.detection_rate_change;


    document.getElementById(
        "reg-rate-change"
    ).textContent =
        `${change >= 0 ? "+" : ""}` +
        `${change.toFixed(2)} pp`;


    renderRegressionVerdict(
        comparison
    );


    renderRegressionTargets(
        "reg-newly-detected",
        comparison.newly_detected,
        "regression-target-positive",
        "+"
    );


    renderRegressionTargets(
        "reg-regressions",
        comparison.regressions,
        "regression-target-negative",
        "-"
    );
}


// Display regression / improvement / unchanged verdict.
function renderRegressionVerdict(
    comparison
) {

    const element =
        document.getElementById(
            "regression-verdict"
        );


    element.className =
        "regression-verdict";


    if (comparison.regressed) {

        element.textContent =
            "DETECTION REGRESSION";

        element.classList.add(
            "regression-regressed"
        );

        return;
    }


    if (comparison.improved) {

        element.textContent =
            "DETECTION IMPROVEMENT";

        element.classList.add(
            "regression-improved"
        );

        return;
    }


    element.textContent =
        "NO DETECTION CHANGE";

    element.classList.add(
        "regression-unchanged"
    );
}


// Display target-level regression differences.
function renderRegressionTargets(
    elementID,
    targets,
    className,
    prefix
) {

    const container =
        document.getElementById(
            elementID
        );


    container.replaceChildren();


    if (
        !targets ||
        targets.length === 0
    ) {

        container.textContent =
            "None";

        return;
    }


    for (const target of targets) {

        const item =
            document.createElement(
                "div"
            );

        item.className =
            className;

        item.textContent =
            `${prefix} ${target.value} (${target.type})`;

        container.appendChild(
            item
        );
    }
}


function displayAlerts(result) {

    const section =
        document.getElementById(
            "alerts-section"
        );

    const body =
        document.getElementById(
            "alerts-body"
        );

    const summary =
        document.getElementById(
            "alerts-summary"
        );


    const alerts =
        result.suricata_alerts ||
        [];


    if (
        !result.suricata_path &&
        alerts.length === 0
    ) {

        section.classList.add(
            "hidden"
        );

        return;
    }


    section.classList.remove(
        "hidden"
    );

    body.innerHTML = "";


    summary.textContent =
        alerts.length === 1
            ? "1 Suricata alert was generated."
            : `${alerts.length} Suricata alerts were generated.`;


    if (alerts.length === 0) {

        const row =
            document.createElement(
                "tr"
            );

        const cell =
            document.createElement(
                "td"
            );

        cell.colSpan = 7;

        cell.textContent =
            "No Suricata alerts were generated for this run.";

        row.appendChild(
            cell
        );

        body.appendChild(
            row
        );

        return;
    }


    for (const alert of alerts) {

        const row =
            document.createElement(
                "tr"
            );


        const target =
            alert.dns_names &&
            alert.dns_names.length > 0
                ? alert.dns_names.join(
                    ", "
                )
                : "-";


        const values = [

            formatSuricataTime(
                alert.timestamp
            ),

            target,

            alert.signature_id ??
                "-",

            alert.severity ??
                "-",

            alert.signature ||
                "-",

            alert.dns_rcode ||
                "-",

            alert.action ||
                "-"
        ];


        for (const value of values) {

            const cell =
                document.createElement(
                    "td"
                );

            cell.textContent =
                value;

            row.appendChild(
                cell
            );
        }


        body.appendChild(
            row
        );
    }
}


function displayEvents(events) {

    const body =
        document.getElementById(
            "events-body"
        );

    body.innerHTML = "";


    for (const event of events) {

        const row =
            document.createElement(
                "tr"
            );


        const values = [
            event.time,
            event.module,
            event.type,
            event.message
        ];


        for (const value of values) {

            const cell =
                document.createElement(
                    "td"
                );

            cell.textContent =
                value;

            row.appendChild(
                cell
            );
        }


        body.appendChild(
            row
        );
    }
}


function formatSuricataTime(
    timestamp
) {

    if (!timestamp) {
        return "-";
    }

    const match =
        timestamp.match(
            /T(\d{2}:\d{2}:\d{2})/
        );

    if (match) {
        return match[1];
    }

    return timestamp;
}


function showLoadError(message) {

    document.getElementById(
        "result-subtitle"
    ).textContent =
        "Failed to load run";

    document.getElementById(
        "raw-output"
    ).textContent =
        message;
}


// Run same-PCAP regression when the button is clicked.
if (regressionRunButton) {
    regressionRunButton.addEventListener(
        "click",
        runRegression
    );
}


// Load the selected result.
loadResult();
