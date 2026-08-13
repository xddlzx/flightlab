const moduleSelect = document.getElementById("module");
const sizeInput = document.getElementById("size");
const interfaceInput = document.getElementById("interface");
const runModeSelect = document.getElementById("run-mode");
const runModeHelp = document.getElementById("run-mode-help");
const runButton = document.getElementById("run-button");
const runMessage = document.getElementById("run-message");
const runsBody = document.getElementById("runs-body");
const refreshRunsButton = document.getElementById("refresh-runs");

const c2Options = document.getElementById("c2-options");
const c2Source = document.getElementById("c2-source");
const c2FileGroup = document.getElementById("c2-file-group");
const c2FileInput = document.getElementById("c2-file");
const c2LibraryStatus = document.getElementById(
    "c2-library-status"
);

const coverageBody = document.getElementById(
    "coverage-body"
);

const coverageSummary = document.getElementById(
    "coverage-summary"
);

const refreshCoverageButton = document.getElementById(
    "refresh-coverage"
);
const sshTransferOptions =
    document.getElementById(
        "ssh-transfer-options"
    );

const sshTransferSize =
    document.getElementById(
        "ssh-transfer-size"
    );
   
const sshExfilOptions =
    document.getElementById(
        "ssh-exfil-options"
    );

const sshExfilSize =
    document.getElementById(
        "ssh-exfil-size"
    );
    
function updateSSHExfilControls() {

    const isSSHExfil =
        moduleSelect.value ===
        "ssh-exfil";

    sshExfilOptions.classList.toggle(
        "hidden",
        !isSSHExfil
    );
}

async function loadHealth() {

    const status =
        document.getElementById(
            "api-status"
        );

    if (!status) {
        return;
    }

    status.textContent =
        "Checking API...";

    status.classList.remove(
        "success",
        "failure"
    );

    try {

        const response =
            await fetch(
                "/api/health"
            );

        const data =
            await response.json();

        if (
            !response.ok ||
            data.status !== "ok"
        ) {
            throw new Error(
                "API health check failed"
            );
        }

        status.textContent =
            "API Online";

        status.classList.add(
            "success"
        );

    } catch (error) {

        status.textContent =
            "API Offline";

        status.classList.add(
            "failure"
        );
    }
}


async function loadModules() {

    if (!moduleSelect) {
        return;
    }

    try {

        const response =
            await fetch(
                "/api/modules"
            );

        const data =
            await response.json();

        if (
            !response.ok ||
            !Array.isArray(
                data.modules
            )
        ) {
            throw new Error(
                data.error ||
                "Could not load modules"
            );
        }

        moduleSelect.innerHTML =
            "";

        for (
            const module of data.modules
        ) {

            const option =
                document.createElement(
                    "option"
                );

            option.value =
                module;

            option.textContent =
                module;

            moduleSelect.appendChild(
                option
            );
        }

        // DGA is useful as the first
        // default test.
        if (
            data.modules.includes(
                "dga"
            )
        ) {
            moduleSelect.value =
                "dga";
        }

        updateC2Controls();
        updateSSHTransferControls();
        updateSSHExfilControls();

    } catch (error) {

        if (runMessage) {

            runMessage.textContent =
                "Could not load FlightSim modules.";
        }
    }
}


function updateC2Controls() {

    if (
        !moduleSelect ||
        !c2Options
    ) {
        return;
    }

    const isC2 =
        moduleSelect.value ===
        "c2";

    c2Options.classList.toggle(
        "hidden",
        !isC2
    );

    if (!isC2) {

        if (c2FileGroup) {

            c2FileGroup.classList.add(
                "hidden"
            );
        }

        if (c2LibraryStatus) {

            c2LibraryStatus.textContent =
                "";
        }

        return;
    }

    if (
        !c2Source ||
        !c2FileGroup
    ) {
        return;
    }

    const custom =
        c2Source.value ===
        "custom";

    c2FileGroup.classList.toggle(
        "hidden",
        !custom
    );
}

function updateSSHTransferControls() {

    const isSSHTransfer =
        moduleSelect.value ===
        "ssh-transfer";

    sshTransferOptions.classList.toggle(
        "hidden",
        !isSSHTransfer
    );
}

function updateRunModeHelp() {

    if (
        !runModeSelect ||
        !runModeHelp
    ) {
        return;
    }

    if (
        runModeSelect.value ===
        "evaluation"
    ) {

        runModeHelp.textContent =
            "Generates live traffic, captures the PCAP, " +
            "analyzes it with Suricata, calculates detection " +
            "metrics and diagnosis, and enables same-PCAP regression.";

        return;
    }

    runModeHelp.textContent =
        "Preview only — no real traffic, packet capture, " +
        "detection metrics, or regression testing.";
}


async function uploadC2Library() {

    if (
        !c2FileInput ||
        !c2LibraryStatus
    ) {
        throw new Error(
            "C2 library controls are unavailable."
        );
    }

    const file =
        c2FileInput.files[0];

    if (!file) {

        throw new Error(
            "Choose a C2 target library."
        );
    }

    c2LibraryStatus.className =
        "library-status";

    c2LibraryStatus.textContent =
        "Uploading and validating...";

    const formData =
        new FormData();

    formData.append(
        "file",
        file
    );

    const response =
        await fetch(
            "/api/c2-library",
            {
                method: "POST",
                body: formData
            }
        );

    const data =
        await response.json();

    if (!response.ok) {

        c2LibraryStatus.className =
            "library-status error";

        c2LibraryStatus.textContent =
            data.error ||
            "Library validation failed.";

        throw new Error(
            data.error ||
            "C2 library upload failed"
        );
    }

    c2LibraryStatus.className =
        "library-status success";

    c2LibraryStatus.textContent =
        `${data.targets} targets validated — ` +
        `${data.dns} DNS, ` +
        `${data.ip_targets} IP:port`;

    return data.path;
}


async function runSimulation() {

    if (
        !moduleSelect ||
        !sizeInput ||
        !interfaceInput ||
        !runModeSelect ||
        !runButton ||
        !runMessage
    ) {
        return;
    }

    if (!moduleSelect.value) {

        runMessage.textContent =
            "Choose a FlightSim module first.";

        return;
    }

    runButton.disabled =
        true;

    runMessage.textContent =
        "Running simulation...";

    try {

        let c2Library =
            "";

        if (
            moduleSelect.value === "c2" &&
            c2Source &&
            c2Source.value === "custom"
        ) {

            c2Library =
                await uploadC2Library();
        }

        const evaluation =
            runModeSelect.value ===
            "evaluation";

        const request = {
        
        ssh_exfil_size:
   		 moduleSelect.value === "ssh-exfil"
     		 ? sshExfilSize.value
     	 	 : "",
        
       	ssh_transfer_size:
    		moduleSelect.value === "ssh-transfer"
        	? sshTransferSize.value
        	: "",

            module:
                moduleSelect.value,

            size:
                Number(
                    sizeInput.value
                ),

            dry_run:
                !evaluation,

            interface:
                interfaceInput.value.trim(),

            capture:
                evaluation,

            suricata:
                evaluation,

            c2_library:
                c2Library
        };

        const response =
            await fetch(
                "/api/run",
                {
                    method:
                        "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify(
                            request
                        )
                }
            );

        const data =
            await response.json();

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Simulation failed"
            );
        }

        runMessage.textContent =
            "Simulation completed. Opening result...";

        window.location.href =
            `/result.html?id=${encodeURIComponent(
                data.result.id
            )}`;

    } catch (error) {

        runMessage.textContent =
            "Error: " +
            error.message;

    } finally {

        runButton.disabled =
            false;
    }
}


// Legacy same-page result rendering.
// Kept so existing functionality is
// not removed if it is used elsewhere.
function displayResult(
    result,
    evidenceDir
) {

    const resultSection =
        document.getElementById(
            "result-section"
        );

    const eventsSection =
        document.getElementById(
            "events-section"
        );

    const outputSection =
        document.getElementById(
            "output-section"
        );

    if (
        !resultSection ||
        !eventsSection ||
        !outputSection
    ) {
        return;
    }

    resultSection.classList.remove(
        "hidden"
    );

    eventsSection.classList.remove(
        "hidden"
    );

    outputSection.classList.remove(
        "hidden"
    );


    const status =
        document.getElementById(
            "result-status"
        );

    const resultModule =
        document.getElementById(
            "result-module"
        );

    const resultID =
        document.getElementById(
            "result-id"
        );

    const resultDuration =
        document.getElementById(
            "result-duration"
        );

    const resultEvidence =
        document.getElementById(
            "result-evidence"
        );

    const resultDNSEvents =
        document.getElementById(
            "result-dns-events"
        );

    const resultAlertCount =
        document.getElementById(
            "result-alert-count"
        );


    if (status) {

        status.textContent =
            result.success
                ? "Success"
                : "Failed";

        status.className =
            result.success
                ? "success"
                : "failure";
    }


    if (resultModule) {

        resultModule.textContent =
            result.config?.module ??
            "-";
    }


    if (resultID) {

        resultID.textContent =
            result.id ??
            "-";
    }


    if (resultDuration) {

        const milliseconds =
            (
                result.duration ||
                0
            ) /
            1000000;

        resultDuration.textContent =
            `${milliseconds.toFixed(
                2
            )} ms`;
    }


    if (resultEvidence) {

        resultEvidence.textContent =
            evidenceDir ||
            "-";
    }


    const suricataCounts =
        result.suricata_event_counts ||
        {};


    if (resultDNSEvents) {

        resultDNSEvents.textContent =
            suricataCounts.dns ??
            "-";
    }


    if (resultAlertCount) {

        resultAlertCount.textContent =
            result.suricata_alert_count ??
            "-";
    }


    const metricsSection =
        document.getElementById(
            "metrics-section"
        );


    if (metricsSection) {

        if (result.metrics) {

            metricsSection.classList.remove(
                "hidden"
            );


            const metricTotal =
                document.getElementById(
                    "metric-total"
                );

            const metricObserved =
                document.getElementById(
                    "metric-observed"
                );

            const metricAlerted =
                document.getElementById(
                    "metric-alerted"
                );

            const metricVisibility =
                document.getElementById(
                    "metric-visibility"
                );

            const metricDetection =
                document.getElementById(
                    "metric-detection"
                );


            if (metricTotal) {

                metricTotal.textContent =
                    result.metrics
                        .targets_total;
            }


            if (metricObserved) {

                metricObserved.textContent =
                    result.metrics
                        .targets_observed;
            }


            if (metricAlerted) {

                metricAlerted.textContent =
                    result.metrics
                        .targets_alerted;
            }


            if (metricVisibility) {

                metricVisibility.textContent =
                    `${
                        Number(
                            result.metrics
                                .visibility_rate ||
                            0
                        ).toFixed(2)
                    }%`;
            }


            if (metricDetection) {

                metricDetection.textContent =
                    `${
                        Number(
                            result.metrics
                                .detection_rate ||
                            0
                        ).toFixed(2)
                    }%`;
            }


            displayTargets(
                "observed-targets",
                result.metrics
                    .observed_targets
            );


            displayTargets(
                "alerted-targets",
                result.metrics
                    .alerted_targets
            );

        } else {

            metricsSection.classList.add(
                "hidden"
            );
        }
    }


    const eventsBody =
        document.getElementById(
            "events-body"
        );


    if (eventsBody) {

        eventsBody.innerHTML =
            "";

        for (
            const event of
            result.events ||
            []
        ) {

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

            for (
                const value of values
            ) {

                const cell =
                    document.createElement(
                        "td"
                    );

                cell.textContent =
                    value ??
                    "-";

                row.appendChild(
                    cell
                );
            }

            eventsBody.appendChild(
                row
            );
        }
    }


    const rawOutput =
        document.getElementById(
            "raw-output"
        );


    if (rawOutput) {

        rawOutput.textContent =
            result.output ||
            "";
    }


    displaySuricataAlerts(
        result
    );
}


function displaySuricataAlerts(
    result
) {

    const section =
        document.getElementById(
            "alerts-section"
        );

    const summary =
        document.getElementById(
            "alerts-summary"
        );

    const body =
        document.getElementById(
            "alerts-body"
        );


    if (
        !section ||
        !summary ||
        !body
    ) {
        return;
    }


    body.innerHTML =
        "";


    const alerts =
        result.suricata_alerts ||
        [];


    // If Suricata was not used at all,
    // don't show the section.
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


    summary.textContent =
        alerts.length === 1
            ? "1 Suricata alert was generated."
            : `${alerts.length} Suricata alerts were generated.`;


    if (
        alerts.length === 0
    ) {

        const row =
            document.createElement(
                "tr"
            );

        const cell =
            document.createElement(
                "td"
            );

        cell.colSpan =
            7;

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


    for (
        const alert of alerts
    ) {

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


        values.forEach(
            (
                value,
                index
            ) => {

                const cell =
                    document.createElement(
                        "td"
                    );

                cell.textContent =
                    value;


                if (
                    index === 1
                ) {

                    cell.className =
                        "alert-target";
                }


                if (
                    index === 4
                ) {

                    cell.className =
                        "alert-signature";
                }


                row.appendChild(
                    cell
                );
            }
        );


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


function displayTargets(
    elementId,
    targets
) {

    const list =
        document.getElementById(
            elementId
        );


    if (!list) {
        return;
    }


    list.innerHTML =
        "";


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


    for (
        const target of targets
    ) {

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


function formatDiagnosis(
    diagnosis
) {

    if (!diagnosis) {
        return "-";
    }


    return diagnosis
        .replaceAll(
            "_",
            " "
        )
        .toUpperCase();
}


async function loadCoverage() {

    if (
        !coverageSummary ||
        !coverageBody
    ) {
        return;
    }


    coverageSummary.textContent =
        "Loading module coverage...";


    coverageBody.innerHTML =
        "";


    try {

        const response =
            await fetch(
                "/api/coverage"
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Could not load coverage."
            );
        }


        coverageSummary.textContent =
            `${data.tested_modules}/${data.total_modules} ` +
            "supported modules evaluated";


        for (
            const coverage of
            data.rows ||
            []
        ) {

            const tableRow =
                document.createElement(
                    "tr"
                );


            if (
                coverage.tested &&
                coverage.run_id
            ) {

                tableRow.classList.add(
                    "clickable-row"
                );

                tableRow.title =
                    "Open latest evaluation result";


                tableRow.addEventListener(
                    "click",
                    () => {

                        window.location.href =
                            `/result.html?id=${encodeURIComponent(
                                coverage.run_id
                            )}`;
                    }
                );
            }


            const values =
                coverage.tested

                    ? [

                        coverage.module,

                        "Yes",

                        coverage.targets_total,

                        coverage.targets_observed,

                        coverage.targets_alerted,

                        `${
                            Number(
                                coverage.visibility_rate ||
                                0
                            ).toFixed(2)
                        }%`,

                        `${
                            Number(
                                coverage.detection_rate ||
                                0
                            ).toFixed(2)
                        }%`,

                        formatDiagnosis(
                            coverage.diagnosis
                        )
                    ]

                    : [

                        coverage.module,

                        "No",

                        "-",

                        "-",

                        "-",

                        "-",

                        "-",

                        "NOT TESTED"
                    ];


            for (
                const value of values
            ) {

                const cell =
                    document.createElement(
                        "td"
                    );


                cell.textContent =
                    value;


                tableRow.appendChild(
                    cell
                );
            }


            coverageBody.appendChild(
                tableRow
            );
        }

    } catch (error) {

        coverageBody.innerHTML =
            "";


        const tableRow =
            document.createElement(
                "tr"
            );


        const cell =
            document.createElement(
                "td"
            );


        cell.colSpan =
            8;


        cell.textContent =
            "Could not load detection coverage.";


        tableRow.appendChild(
            cell
        );


        coverageBody.appendChild(
            tableRow
        );


        coverageSummary.textContent =
            "Coverage unavailable.";
    }
}


async function loadRuns() {

    if (!runsBody) {
        return;
    }


    try {

        const response =
            await fetch(
                "/api/runs"
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Could not load run history."
            );
        }


        runsBody.innerHTML =
            "";


        for (
            const run of
            data.runs ||
            []
        ) {

            const row =
                document.createElement(
                    "tr"
                );


            row.classList.add(
                "clickable-row"
            );


            row.addEventListener(
                "click",
                () => {

                    window.location.href =
                        `/result.html?id=${encodeURIComponent(
                            run.id
                        )}`;
                }
            );


            const started =
                new Date(
                    run.started_at
                );


            const time =
                started.toLocaleTimeString();


            const milliseconds =
                (
                    run.duration ||
                    0
                ) /
                1000000;


            const values = [

                time,

                run.module,

                run.dry_run
                    ? "Dry Run"
                    : "Live",

                run.success
                    ? "Success"
                    : "Failed",

                run.event_count,

                `${
                    milliseconds.toFixed(
                        2
                    )
                } ms`,

                run.id
            ];


            values.forEach(
                (
                    value,
                    index
                ) => {

                    const cell =
                        document.createElement(
                            "td"
                        );


                    cell.textContent =
                        value;


                    if (
                        index === 3 &&
                        run.success
                    ) {

                        cell.className =
                            "status-success";
                    }


                    if (
                        index === 3 &&
                        !run.success
                    ) {

                        cell.className =
                            "status-failure";
                    }


                    if (
                        index === 6
                    ) {

                        cell.className =
                            "run-id";
                    }


                    row.appendChild(
                        cell
                    );
                }
            );


            runsBody.appendChild(
                row
            );
        }

    } catch (error) {

        runsBody.innerHTML =
            "";


        const row =
            document.createElement(
                "tr"
            );


        const cell =
            document.createElement(
                "td"
            );


        cell.colSpan =
            7;


        cell.textContent =
            "Could not load run history.";


        row.appendChild(
            cell
        );


        runsBody.appendChild(
            row
        );
    }
}


// Run simulation.
if (runButton) {

    runButton.addEventListener(
        "click",
        runSimulation
    );
}


// Refresh run history.
if (refreshRunsButton) {

    refreshRunsButton.addEventListener(
        "click",
        loadRuns
    );
}


// Refresh detection coverage.
if (refreshCoverageButton) {

    refreshCoverageButton.addEventListener(
        "click",
        loadCoverage
    );
}


// Change Preview / Detection Evaluation mode.
if (runModeSelect) {

    runModeSelect.addEventListener(
        "change",
        updateRunModeHelp
    );
}


// Show C2-specific controls only when
// the C2 module is selected.
if (moduleSelect) {

    moduleSelect.addEventListener(
        "change",
        updateC2Controls
    );
    moduleSelect.addEventListener(
    "change",
    updateSSHTransferControls
	);
	moduleSelect.addEventListener(
    	"change",
    	updateSSHExfilControls
	);
}


// Show file chooser only when
// Custom C2 Library is selected.
if (c2Source) {

    c2Source.addEventListener(
        "change",
        updateC2Controls
    );
}


// Clear the old validation message when
// the user chooses another C2 file.
if (
    c2FileInput &&
    c2LibraryStatus
) {

    c2FileInput.addEventListener(
        "change",
        () => {

            c2LibraryStatus.className =
                "library-status";

            c2LibraryStatus.textContent =
                "";
        }
    );
}


// Initial page load.
updateRunModeHelp();

loadHealth();

loadModules();

loadCoverage();

loadRuns();
