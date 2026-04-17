/**
 * OSINT Master Tool — Frontend Application Logic
 * Handles navigation, dynamic form generation, SSE streaming, and job management.
 */

(function () {
    "use strict";

    // =========================================================================
    // STATE
    // =========================================================================
    const state = {
        toolData: null,       // { categories: [], tools: {} }
        currentPage: "dashboard",
        currentToolId: null,
        currentJobId: null,
        eventSource: null,
        csrfToken: null,
        jobs: [],
    };

    // =========================================================================
    // DOM REFERENCES
    // =========================================================================
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // =========================================================================
    // INITIALIZATION
    // =========================================================================
    document.addEventListener("DOMContentLoaded", async () => {
        try {
            const resp = await fetch("/api/tools");
            if (!resp.ok) throw new Error("Failed to load tool configs");
            const data = await resp.json();
            state.toolData = data;
            state.csrfToken = data.csrf_token;
            buildSidebar();
            buildDashboard();
            setupEventListeners();
            pollJobs();
        } catch (err) {
            showToast("Failed to initialize: " + err.message, "error");
        }
    });

    // =========================================================================
    // SIDEBAR NAVIGATION
    // =========================================================================
    function buildSidebar() {
        const container = $("#navToolSections");
        if (!container || !state.toolData) return;

        let html = "";
        for (const cat of state.toolData.categories) {
            const toolsInCat = Object.values(state.toolData.tools).filter(t => t.category === cat.id);
            if (toolsInCat.length === 0) continue;

            html += `<div class="nav-section">`;
            html += `<div class="nav-section-label">${escapeHtml(cat.name)}</div>`;
            for (const tool of toolsInCat) {
                html += `
                    <div class="nav-item" data-page="tool" data-tool-id="${escapeAttr(tool.id)}" id="nav-tool-${escapeAttr(tool.id)}">
                        <span class="nav-item-icon">${tool.icon}</span>
                        <span class="nav-item-label">${escapeHtml(tool.name)}</span>
                    </div>`;
            }
            html += `</div>`;
        }
        container.innerHTML = html;
    }

    function setupEventListeners() {
        // Navigation clicks
        document.addEventListener("click", (e) => {
            const navItem = e.target.closest(".nav-item");
            if (navItem) {
                const page = navItem.dataset.page;
                const toolId = navItem.dataset.toolId;
                navigateTo(page, toolId);
            }

            // Category card clicks
            const catCard = e.target.closest(".category-card");
            if (catCard) {
                const catId = catCard.dataset.categoryId;
                const firstTool = Object.values(state.toolData.tools).find(t => t.category === catId);
                if (firstTool) navigateTo("tool", firstTool.id);
            }
        });

        // Tool actions
        $("#btnRunTool")?.addEventListener("click", runCurrentTool);
        $("#btnStopTool")?.addEventListener("click", stopCurrentJob);
        $("#btnClearOutput")?.addEventListener("click", clearOutput);
        $("#btnSaveSettings")?.addEventListener("click", saveSettings);
        $("#btnToggleSidebar")?.addEventListener("click", () => {
            $("#sidebar")?.classList.toggle("open");
        });
    }

    function navigateTo(page, toolId) {
        // Deactivate all nav items
        $$(".nav-item").forEach(n => n.classList.remove("active"));

        // Deactivate all pages
        $$(".page-panel").forEach(p => p.classList.remove("active"));

        state.currentPage = page;

        if (page === "tool" && toolId) {
            state.currentToolId = toolId;
            const navEl = $(`#nav-tool-${CSS.escape(toolId)}`);
            if (navEl) navEl.classList.add("active");
            buildToolPage(toolId);
            $("#page-tool")?.classList.add("active");

            const tool = state.toolData.tools[toolId];
            if (tool) {
                updateBreadcrumb(tool.name);
            }
        } else {
            const navEl = $(`#nav-${page}`);
            if (navEl) navEl.classList.add("active");
            const pageEl = $(`#page-${page}`);
            if (pageEl) pageEl.classList.add("active");

            const pageNames = { dashboard: "Dashboard", jobs: "Job History", settings: "Settings" };
            updateBreadcrumb(pageNames[page] || page);

            if (page === "jobs") refreshJobHistory();
            if (page === "settings") loadSettings();
        }
    }

    function updateBreadcrumb(text) {
        const el = $("#breadcrumbActive");
        if (el) el.textContent = text;
    }

    // =========================================================================
    // DASHBOARD
    // =========================================================================
    function buildDashboard() {
        if (!state.toolData) return;

        // Stats
        const tools = Object.values(state.toolData.tools);
        const externalTools = tools.filter(t => !t.builtin).length;
        const builtinTools = tools.filter(t => t.builtin).length;
        const categories = state.toolData.categories.length;

        const statsHtml = `
            <div class="stat-card">
                <div class="stat-icon">🛠️</div>
                <div class="stat-value">${externalTools}</div>
                <div class="stat-label">External Tools</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">⚡</div>
                <div class="stat-value">${builtinTools}</div>
                <div class="stat-label">Built-in Tools</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">📂</div>
                <div class="stat-value">${categories}</div>
                <div class="stat-label">Categories</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🚀</div>
                <div class="stat-value">${tools.length}</div>
                <div class="stat-label">Total Tools</div>
            </div>
        `;
        const statsEl = $("#dashboardStats");
        if (statsEl) statsEl.innerHTML = statsHtml;

        // Category cards
        let catHtml = "";
        for (const cat of state.toolData.categories) {
            const toolCount = tools.filter(t => t.category === cat.id).length;
            catHtml += `
                <div class="category-card" data-category-id="${escapeAttr(cat.id)}">
                    <div class="cat-icon">${cat.icon}</div>
                    <h3>${escapeHtml(cat.name)}</h3>
                    <p>${escapeHtml(cat.description)}</p>
                    <div class="cat-count">${toolCount} tool${toolCount !== 1 ? 's' : ''} available</div>
                </div>`;
        }
        const catEl = $("#dashboardCategories");
        if (catEl) catEl.innerHTML = catHtml;
    }

    // =========================================================================
    // TOOL PAGE — DYNAMIC FORM GENERATION
    // =========================================================================
    function buildToolPage(toolId) {
        const tool = state.toolData.tools[toolId];
        if (!tool) return;

        // Header
        const iconEl = $("#toolHeaderIcon");
        const nameEl = $("#toolHeaderName");
        const descEl = $("#toolHeaderDesc");
        if (iconEl) iconEl.textContent = tool.icon;
        if (nameEl) nameEl.textContent = tool.name;
        if (descEl) descEl.textContent = tool.description;

        // Form
        const formGrid = $("#toolFormGrid");
        if (!formGrid) return;

        let html = "";
        const toggleArgs = [];
        const nonToggleArgs = [];

        for (const arg of tool.args) {
            if (arg.type === "toggle") {
                toggleArgs.push(arg);
            } else {
                nonToggleArgs.push(arg);
            }
        }

        // Non-toggle inputs first
        for (const arg of nonToggleArgs) {
            html += renderFormField(arg, toolId);
        }

        // Toggles in a grouped section
        if (toggleArgs.length > 0) {
            html += `<div class="form-group full-width" style="margin-top: 8px;">
                <label class="form-label" style="margin-bottom: 4px;">Options</label>
                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 4px 16px;">`;
            for (const arg of toggleArgs) {
                const fieldId = `field-${toolId}-${arg.id}`;
                const checked = arg.default ? "checked" : "";
                html += `
                    <div class="toggle-container">
                        <span class="toggle-label-text">${escapeHtml(arg.label)}</span>
                        <label class="toggle-switch" title="${escapeAttr(arg.help || '')}">
                            <input type="checkbox" id="${escapeAttr(fieldId)}" data-arg-id="${escapeAttr(arg.id)}" ${checked}>
                            <span class="toggle-slider"></span>
                        </label>
                    </div>`;
            }
            html += `</div></div>`;
        }

        formGrid.innerHTML = html;

        // Reset output
        clearOutput();
        $("#builtinResultArea").innerHTML = "";
        setTerminalVisibility(!tool.builtin);

        // Reset buttons
        $("#btnRunTool").style.display = "";
        $("#btnRunTool").disabled = false;
        $("#btnRunTool").innerHTML = "<span>▶</span> Run Tool";
        $("#btnStopTool").style.display = "none";
    }

    function renderFormField(arg, toolId) {
        const fieldId = `field-${toolId}-${arg.id}`;
        const required = arg.required ? `<span class="required">*</span>` : "";

        let inputHtml = "";

        if (arg.type === "text") {
            inputHtml = `<input type="text" class="form-input" id="${escapeAttr(fieldId)}"
                data-arg-id="${escapeAttr(arg.id)}"
                placeholder="${escapeAttr(arg.placeholder || '')}"
                value="${escapeAttr(arg.default || '')}"
                ${arg.required ? 'required' : ''}>`;
        } else if (arg.type === "number") {
            inputHtml = `<input type="number" class="form-input" id="${escapeAttr(fieldId)}"
                data-arg-id="${escapeAttr(arg.id)}"
                value="${arg.default !== undefined ? arg.default : ''}"
                ${arg.min !== undefined ? `min="${arg.min}"` : ''}
                ${arg.max !== undefined ? `max="${arg.max}"` : ''}
                placeholder="${escapeAttr(arg.placeholder || '')}">`;
        } else if (arg.type === "select") {
            let options = (arg.options || []).map(opt =>
                `<option value="${escapeAttr(opt)}" ${opt === arg.default ? 'selected' : ''}>${escapeHtml(opt || '— none —')}</option>`
            ).join("");
            inputHtml = `<select class="form-select" id="${escapeAttr(fieldId)}" data-arg-id="${escapeAttr(arg.id)}">
                ${options}
            </select>`;
        }

        const helpHtml = arg.help ? `<div class="form-help">${escapeHtml(arg.help)}</div>` : "";

        return `
            <div class="form-group">
                <label class="form-label" for="${escapeAttr(fieldId)}">${escapeHtml(arg.label)} ${required}</label>
                ${inputHtml}
                ${helpHtml}
            </div>`;
    }

    function setTerminalVisibility(visible) {
        const tc = $("#terminalCard");
        if (tc) tc.style.display = visible ? "" : "none";
        const co = $("#btnClearOutput");
        if (co) co.style.display = visible ? "" : "none";
    }

    // =========================================================================
    // COLLECT FORM VALUES
    // =========================================================================
    function collectFormValues(toolId) {
        const tool = state.toolData.tools[toolId];
        if (!tool) return {};

        const params = {};
        for (const arg of tool.args) {
            const fieldId = `field-${toolId}-${arg.id}`;
            const el = document.getElementById(fieldId);
            if (!el) continue;

            if (arg.type === "toggle") {
                params[arg.id] = el.checked;
            } else if (arg.type === "number") {
                const val = el.value.trim();
                if (val !== "") params[arg.id] = Number(val);
            } else {
                const val = el.value.trim();
                if (val) params[arg.id] = val;
            }
        }
        return params;
    }

    // =========================================================================
    // RUN TOOL
    // =========================================================================
    async function runCurrentTool() {
        const toolId = state.currentToolId;
        if (!toolId) return;

        const tool = state.toolData.tools[toolId];
        if (!tool) return;

        // Validate required fields
        const params = collectFormValues(toolId);
        for (const arg of tool.args) {
            if (arg.required && !params[arg.id] && params[arg.id] !== 0) {
                showToast(`"${arg.label}" is required.`, "warning");
                const el = document.getElementById(`field-${toolId}-${arg.id}`);
                if (el) {
                    el.focus();
                    el.style.borderColor = "var(--accent-red)";
                    setTimeout(() => el.style.borderColor = "", 2000);
                }
                return;
            }
        }

        // Disable run button
        const runBtn = $("#btnRunTool");
        runBtn.disabled = true;
        runBtn.innerHTML = `<span class="spinner"></span> Running...`;

        try {
            const resp = await fetch("/api/run", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-OSINT-CSRF": state.csrfToken
                },
                body: JSON.stringify({ tool_id: toolId, params }),
            });

            const data = await resp.json();

            if (!resp.ok) {
                showToast(data.error || "Failed to start tool.", "error");
                runBtn.disabled = false;
                runBtn.innerHTML = "<span>▶</span> Run Tool";
                return;
            }

            // Built-in tool — show result immediately
            if (data.builtin) {
                runBtn.disabled = false;
                runBtn.innerHTML = "<span>▶</span> Run Tool";
                renderBuiltinResult(toolId, data.result);
                showToast(`${tool.name} completed.`, "success");
                return;
            }

            // External tool — start SSE streaming
            state.currentJobId = data.job_id;
            showToast(`${tool.name} started (Job: ${data.job_id})`, "info");

            // Show stop button
            $("#btnStopTool").style.display = "";
            clearOutput();
            setTerminalStatus("running", "RUNNING");

            startSSEStream(data.job_id, tool.name);

        } catch (err) {
            showToast("Error: " + err.message, "error");
            runBtn.disabled = false;
            runBtn.innerHTML = "<span>▶</span> Run Tool";
        }
    }

    // =========================================================================
    // SSE STREAMING
    // =========================================================================
    function startSSEStream(jobId, toolName) {
        // Close any existing stream
        if (state.eventSource) {
            state.eventSource.close();
        }

        const termBody = $("#terminalBody");
        if (!termBody) return;

        // Clear placeholder
        termBody.innerHTML = "";

        const termTitle = $("#terminalTitle");
        if (termTitle) termTitle.textContent = `${toolName} — Job ${jobId}`;

        state.eventSource = new EventSource(`/api/stream/${encodeURIComponent(jobId)}`);

        state.eventSource.onmessage = (event) => {
            try {
                const line = JSON.parse(event.data);
                if (line.type === "stdout" && line.text.startsWith("DATA_RESULT:")) {
                    const resultJson = line.text.substring(12);
                    try {
                        const result = JSON.parse(resultJson);
                        renderBuiltinResult(state.currentToolId, { result });
                    } catch (e) {
                        console.error("Failed to parse DATA_RESULT", e);
                    }
                } else {
                    appendTerminalLine(line.type, line.text);
                }
            } catch (e) {
                // ignore parse errors
            }
        };

        state.eventSource.addEventListener("status", (event) => {
            try {
                const info = JSON.parse(event.data);
                setTerminalStatus(info.status, info.status.toUpperCase());
            } catch (e) {
                // ignore
            }
        });

        state.eventSource.addEventListener("done", (event) => {
            state.eventSource.close();
            state.eventSource = null;

            try {
                const info = JSON.parse(event.data);
                setTerminalStatus(info.status, info.status.toUpperCase());

                const statusMsg = info.status === "completed" ? "completed successfully" : info.status;
                showToast(`${toolName} ${statusMsg}.`, info.status === "completed" ? "success" : "warning");
            } catch (e) {
                // ignore
            }

            resetRunButton();
        });

        state.eventSource.onerror = () => {
            state.eventSource.close();
            state.eventSource = null;
            setTerminalStatus("failed", "DISCONNECTED");
            resetRunButton();
        };
    }

    function appendTerminalLine(type, text) {
        const termBody = $("#terminalBody");
        if (!termBody) return;

        const lineEl = document.createElement("div");
        lineEl.className = `terminal-line ${type}`;

        const prefix = document.createElement("span");
        prefix.className = "line-prefix";
        prefix.textContent = type === "stderr" ? "⚠ " : "› ";

        lineEl.appendChild(prefix);
        lineEl.appendChild(document.createTextNode(text));
        termBody.appendChild(lineEl);

        // Auto-scroll
        termBody.scrollTop = termBody.scrollHeight;
    }

    function setTerminalStatus(status, label) {
        const el = $("#terminalStatus");
        if (!el) return;
        el.style.display = "";
        el.className = `terminal-status ${status}`;
        el.textContent = label;
    }

    function resetRunButton() {
        const runBtn = $("#btnRunTool");
        if (runBtn) {
            runBtn.disabled = false;
            runBtn.innerHTML = "<span>▶</span> Run Tool";
        }
        const stopBtn = $("#btnStopTool");
        if (stopBtn) stopBtn.style.display = "none";
    }

    // =========================================================================
    // STOP / CLEAR
    // =========================================================================
    async function stopCurrentJob() {
        if (!state.currentJobId) return;
        try {
            await fetch(`/api/stop/${encodeURIComponent(state.currentJobId)}`, {
                method: "POST",
                headers: { "X-OSINT-CSRF": state.csrfToken }
            });
            showToast("Job stop requested.", "info");
        } catch (err) {
            showToast("Failed to stop: " + err.message, "error");
        }
    }

    function clearOutput() {
        const termBody = $("#terminalBody");
        if (termBody) {
            termBody.innerHTML = `
                <div class="terminal-placeholder">
                    <div class="placeholder-icon">⌨️</div>
                    <div>Configure the tool above and click <strong>Run Tool</strong> to begin.</div>
                </div>`;
        }
        setTerminalStatus("", "");
        const statusEl = $("#terminalStatus");
        if (statusEl) statusEl.style.display = "none";

        const termTitle = $("#terminalTitle");
        if (termTitle) termTitle.textContent = "output";
    }

    // =========================================================================
    // BUILT-IN RESULTS RENDERING
    // =========================================================================
    function renderBuiltinResult(toolId, resultData) {
        const area = $("#builtinResultArea");
        if (!area) return;

        if (resultData.error) {
            area.innerHTML = `
                <div class="builtin-result-card">
                    <h3>❌ Error</h3>
                    <div class="result-pre">${escapeHtml(resultData.error)}</div>
                </div>`;
            return;
        }

        const result = resultData.result;
        let html = "";

        switch (toolId) {
            case "ip_geolocation":
                html = renderTable(result, [
                    ["IP", "query"], ["Country", "country"], ["Region", "regionName"],
                    ["City", "city"], ["ZIP", "zip"], ["Latitude", "lat"],
                    ["Longitude", "lon"], ["Timezone", "timezone"],
                    ["ISP", "isp"], ["Organization", "org"], ["AS", "as"],
                ]);
                break;

            case "whois_lookup":
                html = `<div class="result-pre">${escapeHtml(result)}</div>`;
                break;

            case "dns_lookup":
                html = Object.entries(result).map(([rtype, data]) =>
                    `<h4 style="color: var(--accent-cyan); margin: 12px 0 6px;">${escapeHtml(rtype)} Records</h4>
                     <div class="result-pre">${escapeHtml(data)}</div>`
                ).join("");
                break;

            case "http_headers":
                html = `<h4 style="color: var(--accent-green); margin-bottom: 8px;">Status: ${result.status_code}</h4>`;
                // Security analysis
                html += `<h4 style="color: var(--accent-cyan); margin: 12px 0 6px;">Security Header Analysis</h4>`;
                html += `<table class="result-table"><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>`;
                for (const [header, info] of Object.entries(result.security_analysis)) {
                    const tag = info.status === "present"
                        ? `<span class="result-tag present">✓ Present</span>`
                        : `<span class="result-tag missing">✗ Missing</span>`;
                    html += `<tr><td>${escapeHtml(header)}</td><td>${tag}</td><td>${escapeHtml(info.value || '—')}</td></tr>`;
                }
                html += `</tbody></table>`;
                // All headers
                html += `<h4 style="color: var(--accent-cyan); margin: 16px 0 6px;">All Response Headers</h4>`;
                html += renderTable(result.headers, Object.keys(result.headers).map(k => [k, k]));
                break;

            case "hash_tool":
                if (result.possible_types) {
                    // Identify mode
                    html = `<p style="margin-bottom: 8px;">Input length: <strong>${result.length}</strong> characters</p>`;
                    html += `<p>Possible types: <strong class="text-cyan">${escapeHtml(result.possible_types.join(", "))}</strong></p>`;
                } else {
                    // Generate mode
                    html = renderTable(result, Object.keys(result).map(k => [k, k]));
                }
                break;

            case "subdomain_finder":
                html = `<p style="margin-bottom: 8px;">Found <strong class="text-cyan">${result.count}</strong> subdomains for <strong>${escapeHtml(result.domain)}</strong></p>`;
                html += `<ul class="result-list">`;
                for (const sub of result.subdomains) {
                    html += `<li>${escapeHtml(sub)}</li>`;
                }
                html += `</ul>`;
                break;

            case "url_unshortener":
                html = `<p style="margin-bottom: 4px;">Hops: <strong class="text-cyan">${result.hops}</strong></p>`;
                html += `<p style="margin-bottom: 12px;">Final URL: <strong class="text-green">${escapeHtml(result.final)}</strong></p>`;
                html += `<h4 style="color: var(--accent-cyan); margin-bottom: 6px;">Redirect Chain</h4>`;
                html += `<ol class="result-list" style="list-style: decimal; padding-left: 20px;">`;
                for (const url of result.redirect_chain) {
                    html += `<li>${escapeHtml(url)}</li>`;
                }
                html += `</ol>`;
                break;

            case "tech_detector":
                html = `<p style="margin-bottom: 8px;">Detected <strong class="text-cyan">${result.count}</strong> technologies on <strong>${escapeHtml(result.url)}</strong></p>`;
                if (result.technologies.length > 0) {
                    html += `<table class="result-table"><thead><tr><th>Technology</th><th>Detail</th></tr></thead><tbody>`;
                    for (const t of result.technologies) {
                        html += `<tr><td><strong>${escapeHtml(t.tech)}</strong></td><td>${escapeHtml(t.detail)}</td></tr>`;
                    }
                    html += `</tbody></table>`;
                }
                break;

            default:
                html = `<div class="result-pre">${escapeHtml(JSON.stringify(result, null, 2))}</div>`;
        }

        area.innerHTML = `<div class="builtin-result-card"><h3>✅ Results</h3>${html}</div>`;
    }

    function renderTable(obj, mapping) {
        if (Array.isArray(mapping) && mapping.length > 0 && Array.isArray(mapping[0])) {
            // mapping is [[label, key], ...]
            let rows = mapping.map(([label, key]) => {
                const val = typeof obj === 'object' ? obj[key] : '';
                return `<tr><td><strong>${escapeHtml(label)}</strong></td><td>${escapeHtml(String(val ?? '—'))}</td></tr>`;
            }).join("");
            return `<table class="result-table"><tbody>${rows}</tbody></table>`;
        }
        return `<div class="result-pre">${escapeHtml(JSON.stringify(obj, null, 2))}</div>`;
    }

    // =========================================================================
    // JOB HISTORY
    // =========================================================================
    async function refreshJobHistory() {
        try {
            const resp = await fetch("/api/jobs");
            if (!resp.ok) return;
            state.jobs = await resp.json();
            renderJobHistory();
        } catch (e) {
            // silent
        }
    }

    function renderJobHistory() {
        const container = $("#jobHistoryList");
        if (!container) return;

        if (state.jobs.length === 0) {
            container.innerHTML = `
                <div class="terminal-placeholder">
                    <div class="placeholder-icon">📭</div>
                    <div>No jobs have been run yet.</div>
                </div>`;
            return;
        }

        let html = "";
        for (const job of state.jobs) {
            html += `
                <div class="job-item" data-job-id="${escapeAttr(job.job_id)}">
                    <div class="job-status-dot ${job.status}"></div>
                    <div class="job-info">
                        <div class="job-tool-name">${escapeHtml(job.tool_name)} <span class="text-muted" style="font-size: 0.7rem;">#${escapeHtml(job.job_id)}</span></div>
                        <div class="job-command-text">${escapeHtml(job.command)}</div>
                    </div>
                    <div class="job-time">${formatTime(job.started_at)}</div>
                </div>`;
        }
        container.innerHTML = html;
    }

    async function pollJobs() {
        try {
            const resp = await fetch("/api/jobs");
            if (resp.ok) {
                state.jobs = await resp.json();
                const running = state.jobs.filter(j => j.status === "running" || j.status === "starting").length;
                const badge = $("#runningJobsBadge");
                if (badge) {
                    if (running > 0) {
                        badge.textContent = running;
                        badge.style.display = "";
                    } else {
                        badge.style.display = "none";
                    }
                }
            }
        } catch (e) {
            // silent
        }
        setTimeout(pollJobs, 5000);
    }

    // =========================================================================
    // SETTINGS
    // =========================================================================
    async function loadSettings() {
        const grid = $("#settingsApiKeysGrid");
        if (!grid) return;

        try {
            const resp = await fetch("/api/settings");
            if (!resp.ok) return;
            const cfg = await resp.json();

            // Find all unique API key requirements from tool_configs
            const requiredKeys = new Set();
            Object.values(state.toolData.tools).forEach(t => {
                if (t.requires_api_key) requiredKeys.add(t.requires_api_key);
            });

            if (requiredKeys.size === 0) {
                grid.innerHTML = "<p class='text-muted'>No tools require API keys.</p>";
                return;
            }

            let html = "";
            requiredKeys.forEach(keyName => {
                const label = keyName.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
                const val = (cfg.api_keys && cfg.api_keys[keyName]) ? "••••••••" : "";
                html += `
                    <div class="form-group">
                        <label class="form-label">${escapeHtml(label)}</label>
                        <input type="password" class="form-input setting-api-key"
                            id="setting-${escapeAttr(keyName)}"
                            data-key-name="${escapeAttr(keyName)}"
                            placeholder="Enter ${escapeHtml(label)}..."
                            value="${escapeAttr(val)}"
                            autocomplete="off">
                    </div>`;
            });
            grid.innerHTML = html;
        } catch (e) {
            showToast("Failed to load settings.", "error");
        }
    }

    async function saveSettings() {
        const apiKeys = {};
        $$(".setting-api-key").forEach(el => {
            const name = el.dataset.keyName;
            const val = el.value.trim();
            if (val && val !== "••••••••") {
                apiKeys[name] = val;
            }
        });

        try {
            const resp = await fetch("/api/settings", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-OSINT-CSRF": state.csrfToken
                },
                body: JSON.stringify({ api_keys: apiKeys }),
            });
            if (resp.ok) {
                showToast("Settings saved.", "success");
                loadSettings(); // refresh to show masks
            } else {
                const data = await resp.json();
                showToast(data.error || "Failed to save settings.", "error");
            }
        } catch (err) {
            showToast("Error: " + err.message, "error");
        }
    }

    // =========================================================================
    // TOAST NOTIFICATIONS
    // =========================================================================
    function showToast(message, type = "info") {
        const container = $("#toastContainer");
        if (!container) return;

        const icons = { success: "✅", error: "❌", warning: "⚠️", info: "ℹ️" };
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.innerHTML = `<span>${icons[type] || "ℹ️"}</span><span>${escapeHtml(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add("removing");
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // =========================================================================
    // UTILITIES
    // =========================================================================
    function escapeHtml(str) {
        if (str === null || str === undefined) return "";
        const div = document.createElement("div");
        div.appendChild(document.createTextNode(String(str)));
        return div.innerHTML;
    }

    function escapeAttr(str) {
        if (str === null || str === undefined) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    }

    function formatTime(isoStr) {
        if (!isoStr) return "";
        try {
            const d = new Date(isoStr);
            return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        } catch (e) {
            return isoStr;
        }
    }

})();
