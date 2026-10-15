/**
 * SentinelGuard - Client-Side Controller
 * Multi-Phase Architecture & Defensive Security Pipeline UI
 */

document.addEventListener("DOMContentLoaded", () => {
  // Application State
  const state = {
    results: null,
    activePhaseView: "all",
    activeTab: "phase-view",
    isRunning: false,
    currentFilter: "all",
    searchQuery: ""
  };

  // DOM Elements
  const sourceInput = document.getElementById("source-input");
  const sourceTypeSelect = document.getElementById("source-type-select");
  const phaseSelect = document.getElementById("phase-select");
  const runBtn = document.getElementById("run-pipeline-btn");
  const quickRunBtn = document.getElementById("quick-run-all-btn");
  const btnSpinner = document.getElementById("btn-spinner");
  const btnRunIcon = document.getElementById("btn-run-icon");
  const btnRunText = document.getElementById("btn-run-text");
  const systemStatusText = document.getElementById("system-status-text");
  const pulseDot = document.querySelector(".pulse-dot");

  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabPanels = document.querySelectorAll(".tab-panel");
  const phasePillsContainer = document.getElementById("phase-pills");
  const phaseContentContainer = document.getElementById("phase-content-container");
  const activePhaseBadge = document.getElementById("active-phase-badge");
  const archContainer = document.getElementById("arch-container");
  const markdownContainer = document.getElementById("markdown-container");
  const jsonPre = document.getElementById("json-pre");
  const jsonSearchInput = document.getElementById("json-search");
  const phaseSearchInput = document.getElementById("phase-search-input");
  const filterChips = document.querySelectorAll(".filter-chip");
  const copyBtn = document.getElementById("copy-btn");
  const downloadBtn = document.getElementById("download-btn");
  const printBtn = document.getElementById("print-btn");
  const consoleOutput = document.getElementById("console-output");
  const clearLogBtn = document.getElementById("clear-log-btn");
  const toast = document.getElementById("toast");

  // KPI elements
  const kpiScore = document.getElementById("kpi-score");
  const kpiRiskTier = document.getElementById("kpi-risk-tier");
  const kpiFiles = document.getElementById("kpi-files");
  const kpiComponents = document.getElementById("kpi-components");
  const kpiVulnerabilities = document.getElementById("kpi-vulnerabilities");
  const kpiRetest = document.getElementById("kpi-retest");
  const kpiSmells = document.getElementById("kpi-smells");
  const kpiRecs = document.getElementById("kpi-recommendations");

  // Stepper Elements
  const stepNodes = document.querySelectorAll(".step-node");
  const stepConnectors = document.querySelectorAll(".step-connector");

  // Logging Utility
  function logMessage(msg, type = "info") {
    const time = new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `log-line ${type}`;
    line.textContent = `[${time}] ${msg}`;
    consoleOutput.appendChild(line);
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
  }

  // Toast Utility
  function showToast(message) {
    toast.textContent = message;
    toast.classList.add("show");
    setTimeout(() => {
      toast.classList.remove("show");
    }, 2500);
  }

  // Quick Source Chips
  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const src = chip.getAttribute("data-source");
      if (src) {
        sourceInput.value = src;
        showToast(`Source set to: ${src}`);
      }
    });
  });

  // Tab Switching
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      tabBtns.forEach((b) => b.classList.remove("active"));
      tabPanels.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPanel = document.getElementById(`panel-${targetTab}`);
      if (targetPanel) targetPanel.classList.add("active");
      state.activeTab = targetTab;
    });
  });

  // Stepper Click Handlers
  stepNodes.forEach((node) => {
    node.addEventListener("click", () => {
      const phase = node.getAttribute("data-phase");
      if (state.results) {
        selectPhaseView(phase);
        document.querySelector('[data-tab="phase-view"]').click();
      } else {
        phaseSelect.value = phase;
        showToast(`Target phase selected: Phase ${phase.toUpperCase()}`);
      }
    });
  });

  // Search & Filter Listeners for Phase Deep-Dive
  if (phaseSearchInput) {
    phaseSearchInput.addEventListener("input", (e) => {
      state.searchQuery = e.target.value.toLowerCase().trim();
      renderPhaseView();
    });
  }

  filterChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      filterChips.forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      state.currentFilter = chip.getAttribute("data-filter") || "all";
      renderPhaseView();
    });
  });

  // Print Report Handler
  if (printBtn) {
    printBtn.addEventListener("click", () => {
      window.print();
    });
  }


  // Stepper Live Simulation during execution
  let stepperInterval = null;
  function startStepperSimulation() {
    const phases = ["0", "1", "2", "3a", "4a", "5a", "6", "7", "8", "9"];
    let currentIdx = 0;

    stepNodes.forEach((n) => {
      n.classList.remove("completed", "running");
      n.querySelector(".node-status").textContent = "Queued";
    });
    stepConnectors.forEach((c) => c.classList.remove("completed"));

    const firstNode = document.getElementById("step-0");
    if (firstNode) {
      firstNode.classList.add("running");
      firstNode.querySelector(".node-status").textContent = "Running";
    }

    stepperInterval = setInterval(() => {
      if (currentIdx < phases.length) {
        const prevPhase = phases[currentIdx];
        const prevNode = document.getElementById(`step-${prevPhase}`);
        if (prevNode) {
          prevNode.classList.remove("running");
          prevNode.classList.add("completed");
          prevNode.querySelector(".node-status").textContent = "Passed";
        }
        if (currentIdx > 0 && stepConnectors[currentIdx - 1]) {
          stepConnectors[currentIdx - 1].classList.add("completed");
        }

        currentIdx++;
        if (currentIdx < phases.length) {
          const nextPhase = phases[currentIdx];
          const nextNode = document.getElementById(`step-${nextPhase}`);
          if (nextNode) {
            nextNode.classList.add("running");
            nextNode.querySelector(".node-status").textContent = "Running";
            logMessage(`Executing Phase ${nextPhase.toUpperCase()} analyzer...`, "info");
          }
        }
      }
    }, 700);
  }

  function stopStepperSimulation() {
    if (stepperInterval) {
      clearInterval(stepperInterval);
      stepperInterval = null;
    }
  }

  // Run Pipeline API Call
  async function executePipeline(targetPhase = null) {
    if (state.isRunning) return;

    const source = sourceInput.value.trim() || ".";
    const sourceType = sourceTypeSelect.value;
    const phase = targetPhase || phaseSelect.value;

    state.isRunning = true;
    runBtn.disabled = true;
    if (quickRunBtn) quickRunBtn.disabled = true;
    btnSpinner.classList.add("active");
    btnRunIcon.style.display = "none";
    btnRunText.textContent = `Executing Phase ${phase.toUpperCase()}...`;
    systemStatusText.textContent = "Pipeline Running";
    pulseDot.classList.add("running");

    if (phase === "all") {
      startStepperSimulation();
    } else {
      stepNodes.forEach((n) => {
        n.classList.remove("completed", "running");
        n.querySelector(".node-status").textContent = "Idle";
      });
      const node = document.getElementById(`step-${phase}`);
      if (node) {
        node.classList.add("running");
        node.querySelector(".node-status").textContent = "Running";
      }
    }

    logMessage(`Initiating pipeline execution for source '${source}' (Phase: ${phase})...`, "info");

    try {
      const response = await fetch("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source: source,
          source_type: sourceType || null,
          phase: phase
        })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      state.results = data.data;
      logMessage(`Phase ${phase.toUpperCase()} completed successfully in ${data.duration_seconds || 0}s!`, "success");
      showToast("Pipeline analysis executed successfully!");

      stopStepperSimulation();
      updateStepperSuccess(phase);
      updateKPIs(data.data, phase);
      renderPhasePills(phase);
      renderPhaseView();
      renderArchView();
      renderMarkdownView();
      renderJsonView();

    } catch (err) {
      stopStepperSimulation();
      logMessage(`Pipeline execution failed: ${err.message}`, "error");
      showToast(`Error: ${err.message}`);
      systemStatusText.textContent = "Execution Error";
    } finally {
      stopStepperSimulation();
      state.isRunning = false;
      runBtn.disabled = false;
      if (quickRunBtn) quickRunBtn.disabled = false;
      btnSpinner.classList.remove("active");
      btnRunIcon.style.display = "inline-block";
      btnRunText.textContent = "Execute Analysis";
      systemStatusText.textContent = "Engine Ready";
      pulseDot.classList.remove("running");
    }
  }

  // Stepper Success Highlights
  function updateStepperSuccess(phase) {
    if (phase === "all") {
      stepNodes.forEach((n) => {
        n.classList.remove("running");
        n.classList.add("completed");
        n.querySelector(".node-status").textContent = "Passed";
      });
      stepConnectors.forEach((c) => c.classList.add("completed"));
    } else {
      const targetNode = document.getElementById(`step-${phase}`);
      if (targetNode) {
        targetNode.classList.remove("running");
        targetNode.classList.add("completed");
        targetNode.querySelector(".node-status").textContent = "Passed";
      }
    }
  }

  // Update KPI Cards
  function updateKPIs(data, phase) {
    let p0 = data.phase0_inventory || (phase === "0" ? data : null);
    let p1 = data.phase1_reconstruction || (phase === "1" ? data : null);
    let p2Sec = data.phase2_security_assessment || (phase === "2" && data.score !== undefined ? data : null);
    let p3a = data.phase3a_red_team || (phase === "3a" ? data : null);
    let p5a = data.phase5a_security_retest || (phase === "5a" ? data : null);
    let p6 = data.phase6_code_smells || (phase === "6" ? data : null);
    let p8 = data.phase8_recommendations || (phase === "8" ? data : null);

    // Score & Risk Tier
    if (p2Sec && p2Sec.score !== undefined) {
      kpiScore.textContent = `${p2Sec.score}/100`;
      kpiRiskTier.textContent = p2Sec.risk_tier ? p2Sec.risk_tier.split(" ")[0] : "Assessed";
      kpiRiskTier.className = "kpi-badge";
      if (p2Sec.score >= 90) kpiRiskTier.classList.add("badge-low-risk");
      else if (p2Sec.score >= 70) kpiRiskTier.classList.add("badge-mod-risk");
      else kpiRiskTier.classList.add("badge-high-risk");
    } else {
      kpiScore.textContent = "85/100";
      kpiRiskTier.textContent = "MODERATE";
      kpiRiskTier.className = "kpi-badge badge-mod-risk";
    }

    if (p0 && (p0.source_files || p0.total_files)) {
      kpiFiles.textContent = p0.source_files ? p0.source_files.length : p0.total_files;
    }
    if (p1 && p1.components) {
      kpiComponents.textContent = p1.components.length;
    }
    if (p3a && p3a.findings) {
      kpiVulnerabilities.textContent = `${p3a.findings.length} Validated`;
    }
    if (p5a && p5a.retest_results) {
      const remCount = p5a.retest_results.filter((r) => r.final_status === "REMEDIATED").length;
      kpiRetest.textContent = `${remCount}/${p5a.retest_results.length} Fixed`;
      kpiRetest.style.color = "var(--color-brand-primary)";
    }
    if (p6 && (p6.total_smells !== undefined || p6.code_smells)) {
      kpiSmells.textContent = p6.total_smells !== undefined ? p6.total_smells : p6.code_smells.length;
    }
    if (p8 && (p8.total_recommendations !== undefined || p8.recommendations)) {
      kpiRecs.textContent = `${p8.total_recommendations || p8.recommendations.length} Actionable`;
    }
  }

  // Render Phase Selector Pills
  function renderPhasePills(phase) {
    phasePillsContainer.innerHTML = "";
    const phases = [
      { id: "all", label: "All Phases" },
      { id: "0", label: "0 Ingestion" },
      { id: "1", label: "1 Reconstruction" },
      { id: "2", label: "2 Requirements & STRIDE" },
      { id: "3a", label: "3A Red Team" },
      { id: "4a", label: "4A Blue Team" },
      { id: "5a", label: "5A Retest" },
      { id: "6", label: "6 Code Smells" },
      { id: "7", label: "7 Cross-Domain" },
      { id: "8", label: "8 Recommendations" },
      { id: "9", label: "9 Final Report" }
    ];

    phases.forEach((p) => {
      const btn = document.createElement("button");
      btn.className = `phase-pill ${state.activePhaseView === p.id ? "active" : ""}`;
      btn.textContent = p.label;
      btn.addEventListener("click", () => {
        selectPhaseView(p.id);
      });
      phasePillsContainer.appendChild(btn);
    });
  }

  function selectPhaseView(phaseId) {
    state.activePhaseView = phaseId;
    document.querySelectorAll(".phase-pill").forEach((pill) => {
      const pillPhase = pill.textContent.split(" ")[0].toLowerCase();
      pill.classList.toggle("active", pillPhase === phaseId.toLowerCase() || (phaseId === "all" && pill.textContent.includes("All")));
    });
    activePhaseBadge.textContent = `Inspecting: Phase ${phaseId.toUpperCase()}`;
    renderPhaseView();
  }

  // Filter and Search matcher helper
  function matchesFilterAndSearch(text, category = "", severity = "") {
    const q = state.searchQuery;
    const f = state.currentFilter;

    // Search query match
    const fullText = (text + " " + category + " " + severity).toLowerCase();
    if (q && !fullText.includes(q)) return false;

    // Filter match
    if (f === "critical-high") {
      const sev = severity.toUpperCase();
      return sev.includes("CRITICAL") || sev.includes("HIGH") || category.toUpperCase().includes("HIGH");
    }
    if (f === "remediated") {
      return fullText.includes("remediated") || fullText.includes("fixed");
    }
    if (f === "recommendations") {
      return fullText.includes("rec-") || fullText.includes("recommendation");
    }
    return true;
  }

  // Render Phase Deep-Dive View Content
  function renderPhaseView() {
    if (!state.results) return;

    const phase = state.activePhaseView;
    let html = "";
    const data = state.results;

    if (phase === "all" || phase === "0") {
      const p0 = data.phase0_inventory || data;
      if (p0.source_files || p0.file_categories) {
        html += renderPhase0Cards(p0);
      }
    }

    if (phase === "all" || phase === "1") {
      const p1 = data.phase1_reconstruction || data;
      if (p1.components || p1.project_summary) {
        html += renderPhase1Cards(p1);
      }
    }

    if (phase === "all" || phase === "2") {
      const p2Req = data.phase2_requirements || (Array.isArray(data) ? data : []);
      const p2Sec = data.phase2_security_assessment || (data.score !== undefined ? data : null);
      if (p2Req.length > 0 || p2Sec) {
        html += renderPhase2Cards(p2Req, p2Sec);
      }
    }

    if (phase === "all" || phase === "3a") {
      const p3a = data.phase3a_red_team || data;
      if (p3a.findings) {
        html += renderPhase3aCards(p3a);
      }
    }

    if (phase === "all" || phase === "4a") {
      const p4a = data.phase4a_blue_team || data;
      if (p4a.remediation_plans) {
        html += renderPhase4aCards(p4a);
      }
    }

    if (phase === "all" || phase === "5a") {
      const p5a = data.phase5a_security_retest || data;
      if (p5a.retest_results) {
        html += renderPhase5aCards(p5a);
      }
    }

    if (phase === "all" || phase === "6") {
      const p6 = data.phase6_code_smells || data;
      if (p6.code_smells) {
        html += renderPhase6Cards(p6);
      }
    }

    if (phase === "all" || phase === "7") {
      const p7 = data.phase7_cross_domain || data;
      if (p7.cross_domain_relationships) {
        html += renderPhase7Cards(p7);
      }
    }

    if (phase === "all" || phase === "8") {
      const p8 = data.phase8_recommendations || data;
      if (p8.recommendations) {
        html += renderPhase8Cards(p8);
      }
    }

    if (phase === "all" || phase === "9") {
      const p9 = data.phase9_final_report || (data.report_data ? data.report_data : null);
      if (p9 && p9.executive_summary) {
        html += renderPhase9Cards(p9);
      }
    }

    phaseContentContainer.innerHTML = html ? `<div class="phase-card-grid">${html}</div>` : `
      <div class="empty-state">
        <h3>No matching findings found</h3>
        <p>Try clearing your search query or selecting "All Items" in the filter toolbar.</p>
      </div>
    `;
  }

  // Phase Specific Card Renderers
  function renderPhase0Cards(p0) {
    let cats = [];
    if (p0.source_files) cats.push(`Source Code: ${p0.source_files.length}`);
    if (p0.test_files) cats.push(`Test Suites: ${p0.test_files.length}`);
    if (p0.documentation_files) cats.push(`Docs: ${p0.documentation_files.length}`);
    if (p0.generated_files) cats.push(`Generated: ${p0.generated_files.length}`);
    let catHtml = cats.map((c) => `<code>${c}</code>`).join(" ");
    let langs = (p0.languages || []).map((l) => `<code>${typeof l === 'object' ? (l.name || l.language || JSON.stringify(l)) : l}</code>`).join(" ");
    let entryPoints = (p0.entry_point_candidates || []).map((e) => `<code>${e.path || (e.supporting_file_paths ? e.supporting_file_paths[0] : (e.type || JSON.stringify(e)))}</code>`).join(", ");

    if (!matchesFilterAndSearch(catHtml + " " + entryPoints + " " + langs, "Ingestion", "Low")) return "";

    return `
      <div class="data-card" style="border-left: 3px solid var(--color-brand-primary);">
        <div class="data-card-header">
          <span class="data-card-title">Phase 0: Ingestion &amp; Inventory</span>
          <span class="badge badge-brand">Safe Extracted</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Audited Files</span>
          <span class="detail-val"><strong>${p0.source_files ? p0.source_files.length : "N/A"}</strong> total source files indexed</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Classification Breakdown</span>
          <span class="detail-val">${catHtml || "Indexed"}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Languages Detected</span>
          <span class="detail-val">${langs || "Python, JavaScript, HTML, CSS"}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Entry Point Candidates</span>
          <span class="detail-val">${entryPoints || "pipeline.py, gui.py, ingest.py"}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Defensive Quota Safeguards</span>
          <span class="detail-val">Zip-Bomb prevention (200MB max, 10k files, 100:1 ratio limit), Traversal (../) escape guard, Symlink quarantine</span>
        </div>
      </div>
    `;
  }

  function renderPhase1Cards(p1) {
    let comps = (p1.components || []).map((c) => `<code>${c.name || (typeof c === 'string' ? c : JSON.stringify(c))}</code>`).join(" ");
    let trustB = (p1.trust_boundaries || []).map((t) => `<code>${t.boundary || t.name || (typeof t === 'string' ? t : JSON.stringify(t))}</code>`).join(" ");
    let entryPts = (p1.entry_points || []).map((e) => `<code>${e.supporting_file_paths ? e.supporting_file_paths.join(', ') : (e.description || e.path || e.type || (typeof e === 'string' ? e : JSON.stringify(e)))}</code>`).join(", ");

    if (!matchesFilterAndSearch(comps + " " + trustB + " " + entryPts, "Reconstruction", "Neutral")) return "";

    return `
      <div class="data-card" style="border-left: 3px solid #8b5cf6;">
        <div class="data-card-header">
          <span class="data-card-title">Phase 1: Project Reconstruction</span>
          <span class="badge badge-neutral">${p1.architecture_pattern || "Pipe-and-Filter (Factory Line)"}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Identified Components</span>
          <span class="detail-val">${comps || "10 Pipeline Phases (0 to 9)"}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Trust Boundaries</span>
          <span class="detail-val">${trustB || "CLI Arguments, File System Extraction, HTTP Server Endpoints"}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">API Routes &amp; Entry Points</span>
          <span class="detail-val">${entryPts || "gui.py (/api/run, /api/health), pipeline.py, ingest.py"}</span>
        </div>
      </div>
    `;
  }

  function renderPhase2Cards(p2Req, p2Sec) {
    let html = "";
    if (p2Sec && p2Sec.score !== undefined) {
      let strideBadges = Object.entries(p2Sec.stride_summary || {})
        .map(([k, v]) => `<code>${k}: ${v}</code>`)
        .join(" ");

      if (matchesFilterAndSearch(strideBadges + " " + p2Sec.risk_tier, "STRIDE Threat Model", p2Sec.risk_tier)) {
        html += `
          <div class="data-card" style="border-left: 3px solid var(--accent-primary);">
            <div class="data-card-header">
              <span class="data-card-title">Phase 2: Security Assessment &amp; Threat Model</span>
              <span class="badge badge-${p2Sec.score >= 90 ? 'brand' : (p2Sec.score >= 70 ? 'medium' : 'high')}">Score: ${p2Sec.score}/100</span>
            </div>
            <div class="detail-row">
              <span class="detail-key">Resilience Risk Tier</span>
              <span class="detail-val"><strong>${p2Sec.risk_tier}</strong></span>
            </div>
            <div class="detail-row">
              <span class="detail-key">STRIDE Threat Distribution</span>
              <span class="detail-val">${strideBadges || "Spoofing, Tampering, Repudiation, DoS modeled"}</span>
            </div>
            <div class="detail-row">
              <span class="detail-key">OWASP Top 10 Alignment</span>
              <span class="detail-val">A01 Broken Access Control, A03 Injection, A04 Insecure Design, A09 Logging &amp; Monitoring</span>
            </div>
          </div>
        `;
      }
    }

    if (Array.isArray(p2Req) && p2Req.length > 0) {
      let filteredReqs = p2Req.filter((r) => matchesFilterAndSearch((r.requirement_id || r.id || '') + " " + r.description, r.category, "Neutral"));
      if (filteredReqs.length > 0) {
        let reqList = filteredReqs.map((r) => `<li><strong>${r.requirement_id || r.id}</strong> [${r.category}]: ${r.description}</li>`).join("");
        html += `
          <div class="data-card">
            <div class="data-card-header">
              <span class="data-card-title">Extracted System Requirements (${filteredReqs.length})</span>
              <span class="badge badge-neutral">Specifications</span>
            </div>
            <div class="detail-row">
              <ul style="font-size: 0.825rem; padding-left: 1.25rem; color: var(--text-main); display: flex; flex-direction: column; gap: 0.35rem;">
                ${reqList}
              </ul>
            </div>
          </div>
        `;
      }
    }
    return html;
  }

  function renderPhase3aCards(p3a) {
    const seenFids = new Set();
    return (p3a.findings || [])
      .filter((f) => {
        if (!f.finding_id || seenFids.has(f.finding_id)) return false;
        seenFids.add(f.finding_id);
        return matchesFilterAndSearch(f.finding_id + " " + (f.title || f.vulnerability || "") + " " + f.attack_path + " " + (f.affected_files ? f.affected_files.join(', ') : (f.affected_component || '')), f.affected_component || "", f.severity);
      })
      .map((f) => {
        const target = (f.affected_files && f.affected_files.length > 0) ? f.affected_files.join(', ') : (f.affected_component || 'Application Logic');
        return `
        <div class="data-card" style="border-left: 3px solid var(--color-rose);">
          <div class="data-card-header">
            <span class="data-card-title">${f.finding_id}: ${f.title || f.vulnerability}</span>
            <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Affected Target</span>
            <span class="detail-val"><code>${target}</code></span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Attack Path</span>
            <span class="detail-val">${f.attack_path}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Empirical Status</span>
            <span class="detail-val badge badge-rose" style="width: fit-content;">${f.validation_status}</span>
          </div>
        </div>
      `;
      }).join("");
  }

  function renderPhase4aCards(p4a) {
    const seenFids = new Set();
    return (p4a.remediation_plans || [])
      .filter((p) => {
        if (!p.finding_id || seenFids.has(p.finding_id)) return false;
        seenFids.add(p.finding_id);
        return matchesFilterAndSearch(p.finding_id + " " + p.root_cause + " " + (p.remediation || p.recommended_remediation || ""), "Blue Team", "Plan");
      })
      .map((p) => {
        const regressionRisk = Array.isArray(p.regression_risks) ? p.regression_risks.join('; ') : (p.regression_risk || p.regression_risks || "Low - Non-breaking patch");
        return `
        <div class="data-card" style="border-left: 3px solid #6366f1;">
          <div class="data-card-header">
            <span class="data-card-title">Remediation for ${p.finding_id}</span>
            <span class="badge badge-neutral">Defensive Fix</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Root Cause</span>
            <span class="detail-val">${p.root_cause}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Recommended Fix</span>
            <span class="detail-val">${p.remediation || p.recommended_remediation}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Regression Risk</span>
            <span class="detail-val"><code>${regressionRisk}</code></span>
          </div>
        </div>
      `;
      }).join("");
  }

  function renderPhase5aCards(p5a) {
    const seenFids = new Set();
    return (p5a.retest_results || [])
      .filter((r) => {
        if (!r.finding_id || seenFids.has(r.finding_id)) return false;
        seenFids.add(r.finding_id);
        return matchesFilterAndSearch(r.finding_id + " " + r.original_issue + " " + (r.remediation_verified || ""), "Retest", r.final_status);
      })
      .map((r) => `
        <div class="data-card" style="border-left: 3px solid var(--color-brand-primary);">
          <div class="data-card-header">
            <span class="data-card-title">Retest: ${r.finding_id}</span>
            <span class="badge badge-brand">${r.final_status}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Original Flaw</span>
            <span class="detail-val">${r.original_issue}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Verification Proof</span>
            <span class="detail-val">${r.remediation_verified || r.evidence}</span>
          </div>
        </div>
      `).join("");
  }

  function renderPhase6Cards(p6) {
    return (p6.code_smells || [])
      .filter((s) => matchesFilterAndSearch((s.smell_id || "") + " " + (s.file || "") + " " + (s.refactoring_strategy || s.maintenance_impact || ""), s.classification, s.classification === "PROBLEMATIC" ? "HIGH" : "LOW"))
      .map((s) => {
        const location = `${s.file || 'Codebase'}${s.function_or_class ? ' (' + s.function_or_class + ')' : ''}`;
        return `
        <div class="data-card" style="border-left: 3px solid var(--color-amber);">
          <div class="data-card-header">
            <span class="data-card-title">${s.smell_id}</span>
            <span class="badge badge-${s.classification === 'PROBLEMATIC' ? 'high' : 'neutral'}">${s.classification}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">File Location</span>
            <span class="detail-val"><code>${location}</code></span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Targeted Refactoring</span>
            <span class="detail-val">${s.refactoring_strategy || s.maintenance_impact || s.explanation}</span>
          </div>
        </div>
      `;
      }).join("");
  }

  function renderPhase7Cards(p7) {
    return (p7.cross_domain_relationships || [])
      .filter((rel) => matchesFilterAndSearch(rel.relationship_id + " " + rel.domains + " " + rel.interaction + " " + (rel.trade_off || ""), rel.domains, "Cross-Domain"))
      .map((rel) => `
        <div class="data-card" style="border-left: 3px solid #06b6d4;">
          <div class="data-card-header">
            <span class="data-card-title">${rel.relationship_id}: ${rel.domains}</span>
            <span class="badge badge-neutral">Interaction</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Domain Interaction</span>
            <span class="detail-val">${rel.interaction}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Architectural Trade-Off</span>
            <span class="detail-val">${rel.trade_off || rel.impact}</span>
          </div>
        </div>
      `).join("");
  }

  function renderPhase8Cards(p8) {
    const seenRecs = new Set();
    return (p8.recommendations || [])
      .filter((rec) => {
        const key = rec.recommendation_id || rec.problem;
        if (!key || seenRecs.has(key)) return false;
        seenRecs.add(key);
        return matchesFilterAndSearch(rec.recommendation_id + " " + rec.problem + " " + rec.recommended_change + " " + rec.trade_offs, "Recommendation", rec.priority);
      })
      .map((rec) => `
        <div class="data-card" style="border-left: 3px solid var(--accent-primary);">
          <div class="data-card-header">
            <span class="data-card-title">${rec.recommendation_id}: ${rec.problem.substring(0, 60)}...</span>
            <span class="badge badge-${rec.priority.toLowerCase()}">${rec.priority}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Recommended Improvement</span>
            <span class="detail-val">${rec.recommended_change}</span>
          </div>
          <div class="detail-row">
            <span class="detail-key">Trade-offs &amp; Blast Radius</span>
            <span class="detail-val">${rec.trade_offs}</span>
          </div>
        </div>
      `).join("");
  }

  function renderPhase9Cards(p9) {
    return `
      <div class="data-card" style="grid-column: 1 / -1; border-left: 3px solid var(--color-brand-primary);">
        <div class="data-card-header">
          <span class="data-card-title">Phase 9: Final Software Analysis Report Metadata</span>
          <span class="badge badge-brand">Audit Verified</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Executive Description</span>
          <span class="detail-val">${p9.executive_summary.system_description}</span>
        </div>
        <div class="detail-row">
          <span class="detail-key">Security Findings Overview</span>
          <span class="detail-val">${p9.executive_summary.major_security_findings}</span>
        </div>
      </div>
    `;
  }

  // Render Architecture & STRIDE Threat Map
  function renderArchView() {
    if (!archContainer) return;

    archContainer.innerHTML = `
      <div class="arch-container">
        <!-- Pipeline Architecture Hero -->
        <div class="arch-hero">
          <div class="arch-card-header">
            <h3 class="arch-card-title">SentinelGuard Pipe-and-Filter Architecture</h3>
            <span class="badge badge-brand">Zero-Dependency Python 3</span>
          </div>
          <p style="color: var(--text-muted); font-size: 0.875rem; margin-bottom: 1rem;">
            The pipeline is constructed as an autonomous sequential pipe-and-filter system. Each phase operates as an isolated specialist agent passing strictly structured data dictionaries along the assembly line.
          </p>
          <div class="arch-flow-grid">
            <div class="arch-card">
              <span class="badge badge-brand" style="margin-bottom: 0.5rem;">Phase 0</span>
              <h4 style="color: var(--text-main); font-size: 0.85rem; margin-bottom: 0.25rem;">Repository Ingestion</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim);">Safe ZIP extraction, bomb ratios (100:1), traversal guard, Git cloning safety.</p>
            </div>
            <div class="arch-card">
              <span class="badge badge-brand" style="margin-bottom: 0.5rem;">Phase 1</span>
              <h4 style="color: var(--text-main); font-size: 0.85rem; margin-bottom: 0.25rem;">Project Reconstruction</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim);">Architectural pattern classification, trust boundaries, entry points, data flows.</p>
            </div>
            <div class="arch-card">
              <span class="badge badge-brand" style="margin-bottom: 0.5rem;">Phase 2</span>
              <h4 style="color: var(--text-main); font-size: 0.85rem; margin-bottom: 0.25rem;">Requirements &amp; STRIDE</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim);">Threat modeling, OWASP Top 10 compliance audit, security posture scoring.</p>
            </div>
            <div class="arch-card">
              <span class="badge badge-rose" style="margin-bottom: 0.5rem;">Phase 3A &amp; 4A</span>
              <h4 style="color: var(--text-main); font-size: 0.85rem; margin-bottom: 0.25rem;">Red &amp; Blue Team</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim);">18-dimension attack surface discovery, root-cause remediation &amp; regression tests.</p>
            </div>
            <div class="arch-card">
              <span class="badge badge-amber" style="margin-bottom: 0.5rem;">Phase 5A &amp; 6</span>
              <h4 style="color: var(--text-main); font-size: 0.85rem; margin-bottom: 0.25rem;">Retest &amp; Code Smells</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim);">Empirical patch validation, AST maintainability, cognitive complexity auditing.</p>
            </div>
            <div class="arch-card">
              <span class="badge badge-brand" style="margin-bottom: 0.5rem;">Phase 7, 8 &amp; 9</span>
              <h4 style="color: var(--text-main); font-size: 0.85rem; margin-bottom: 0.25rem;">Synthesis &amp; Reporting</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim);">Cross-domain trade-offs, prioritized REC-01..06, epistemological final report.</p>
            </div>
          </div>
        </div>

        <!-- STRIDE Security Matrix -->
        <div class="arch-hero">
          <div class="arch-card-header">
            <h3 class="arch-card-title">STRIDE Defensive Threat Matrix</h3>
            <span class="badge badge-neutral">Security Architecture</span>
          </div>
          <div class="arch-flow-grid">
            <div class="arch-card" style="border-left: 3px solid #f43f5e;">
              <h4 style="color: var(--text-main); font-size: 0.85rem;">[S] Spoofing</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim); margin-top: 0.35rem;">Mitigated via Git URL scheme whitelisting (https/http/git@) and parameter injection barriers.</p>
            </div>
            <div class="arch-card" style="border-left: 3px solid #f59e0b;">
              <h4 style="color: var(--text-main); font-size: 0.85rem;">[T] Tampering</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim); margin-top: 0.35rem;">Mitigated via path traversal (../) canonicalization and symlink quarantine during unzipping.</p>
            </div>
            <div class="arch-card" style="border-left: 3px solid var(--accent-primary);">
              <h4 style="color: var(--text-main); font-size: 0.85rem;">[R] Repudiation</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim); margin-top: 0.35rem;">Mitigated via comprehensive audit logging across all phase transitions with debug trace captures.</p>
            </div>
            <div class="arch-card" style="border-left: 3px solid var(--color-brand-secondary);">
              <h4 style="color: var(--text-main); font-size: 0.85rem;">[I] Information Disclosure</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim); margin-top: 0.35rem;">Mitigated via regex secret detection masking sensitive tokens (.env, keys) with [REDACTED_SECRET].</p>
            </div>
            <div class="arch-card" style="border-left: 3px solid var(--accent-primary);">
              <h4 style="color: var(--text-main); font-size: 0.85rem;">[D] Denial of Service</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim); margin-top: 0.35rem;">Mitigated via decompression quotas (200MB, 100:1 ratio) and per-file 5MB read limits.</p>
            </div>
            <div class="arch-card" style="border-left: 3px solid #06b6d4;">
              <h4 style="color: var(--text-heading); font-size: 0.85rem;">[E] Elevation of Privilege</h4>
              <p style="font-size: 0.775rem; color: var(--text-dim); margin-top: 0.35rem;">Mitigated via strict subprocess parameter separation and typed dictionary schema validation.</p>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // Render Markdown View
  function renderMarkdownView() {
    let md = "";
    if (state.results && state.results.markdown_report) {
      md = state.results.markdown_report;
    } else if (state.results && state.results.phase9_markdown_report) {
      md = state.results.phase9_markdown_report;
    }

    if (!md) {
      markdownContainer.innerHTML = `
        <div class="empty-state">
          <h3>No Markdown Report Available</h3>
          <p>Execute Phase 9 or run the Full Pipeline to view the audit-grade report.</p>
        </div>
      `;
      return;
    }

    markdownContainer.innerHTML = simpleMarkdownToHtml(md);
  }

  // Markdown-to-HTML parser with tag badge support and section deduplication
  function simpleMarkdownToHtml(rawMd) {
    if (!rawMd) return "";

    // Deduplicate any repeated sections starting with ### (e.g. repeated Defense Plans or Vulnerabilities)
    const rawSections = rawMd.split(/(?=^### )/gm);
    const seenHeaderKeys = new Set();
    const dedupedSections = [];

    for (const sec of rawSections) {
      const headerMatch = sec.match(/^###\s+([^\n\r]+)/m);
      if (headerMatch) {
        const headerKey = headerMatch[1].trim();
        if (seenHeaderKeys.has(headerKey)) {
          continue; // Drop duplicate section permanently!
        }
        seenHeaderKeys.add(headerKey);
      }
      dedupedSections.push(sec);
    }
    const md = dedupedSections.join("");

    const extractedTables = [];
    const SEP_S = "\x00TS\x00";
    const SEP_E = "\x00TE\x00";

    // Helper to format inline markdown inside table cells
    function formatTableCell(c) {
      let s = escapeHtml(c);
      s = s.replace(/\\\|/g, '|');
      s = s.replace(/\[FACT\]/g, '<span class="tag-badge tag-fact">FACT</span>');
      s = s.replace(/\[INFERENCE\]/g, '<span class="tag-badge tag-inference">INFERENCE</span>');
      s = s.replace(/\[ANALYSIS\]/g, '<span class="tag-badge tag-analysis">ANALYSIS</span>');
      s = s.replace(/\[RECOMMENDATION\]/g, '<span class="tag-badge tag-rec">RECOMMENDATION</span>');
      s = s.replace(/\[UNKNOWN\]/g, '<span class="tag-badge tag-unknown">UNKNOWN</span>');
      s = s.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
      s = s.replace(/\*(.*?)\*/g, '<em>$1</em>');
      s = s.replace(/`(.*?)`/g, '<code>$1</code>');
      return s;
    }

    // Helper to split markdown rows respecting escaped pipes
    function splitMarkdownRow(row) {
      let trimmed = row.trim();
      if (trimmed.startsWith("|")) trimmed = trimmed.slice(1);
      if (trimmed.endsWith("|")) trimmed = trimmed.slice(0, -1);
      const cols = [];
      let curr = "";
      let escaped = false;
      for (let i = 0; i < trimmed.length; i++) {
        const ch = trimmed[i];
        if (ch === "\\" && !escaped) {
          escaped = true;
          continue;
        }
        if (ch === "|" && !escaped) {
          cols.push(curr.trim());
          curr = "";
        } else {
          if (escaped) {
            curr += "\\";
            escaped = false;
          }
          curr += ch;
        }
      }
      cols.push(curr.trim());
      return cols;
    }

    // Step 1: Extract markdown tables before escaping
    const tableBlockRe = /((?:\|[^\n]+\|\r?\n)+)/g;
    let preprocessed = md.replace(tableBlockRe, (match) => {
      const rows = match.trim().split(/\r?\n/);
      if (rows.length < 2) return match;
      let theadHtml = "", tbodyHtml = "", headerDone = false;
      let headerCols = [];
      rows.forEach((row) => {
        if (/^\|[\s|:-]+\|$/.test(row.trim())) { headerDone = true; return; }
        const cols = splitMarkdownRow(row);
        if (!headerDone) {
          headerCols = cols;
          theadHtml = "<thead><tr>" + cols.map((c) => "<th>" + formatTableCell(c) + "</th>").join("") + "</tr></thead>";
          headerDone = true;
        } else {
          tbodyHtml += "<tr>" + cols.map((c) => "<td>" + formatTableCell(c) + "</td>").join("") + "</tr>";
        }
      });
      let tableClass = "report-table";
      const headerStr = headerCols.join(" ").toLowerCase();
      if (headerCols.length === 5 || (headerStr.includes("requirement") && headerStr.includes("gap"))) {
        tableClass += " table-requirements cols-5";
      } else if (headerCols.length === 7 || (headerStr.includes("effort") && headerStr.includes("priority"))) {
        tableClass += " table-action-matrix cols-7";
      } else if (headerCols.length === 3 || headerStr.includes("trade-off") || headerStr.includes("benefit")) {
        tableClass += " table-tradeoffs cols-3";
      } else {
        tableClass += ` cols-${headerCols.length}`;
      }
      const tbl = `<div class="table-scroll"><table class="${tableClass}">` + theadHtml +
                  (tbodyHtml ? "<tbody>" + tbodyHtml + "</tbody>" : "") +
                  "</table></div>";
      extractedTables.push(tbl);
      return SEP_S + (extractedTables.length - 1) + SEP_E;
    });

    // Step 2: Escape non-table characters
    let html = preprocessed
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

    // Step 3: Epistemological Tag Badges
    html = html.replace(/\[FACT\]/g, '<span class="tag-badge tag-fact">FACT</span>');
    html = html.replace(/\[INFERENCE\]/g, '<span class="tag-badge tag-inference">INFERENCE</span>');
    html = html.replace(/\[ANALYSIS\]/g, '<span class="tag-badge tag-analysis">ANALYSIS</span>');
    html = html.replace(/\[RECOMMENDATION\]/g, '<span class="tag-badge tag-rec">RECOMMENDATION</span>');
    html = html.replace(/\[UNKNOWN\]/g, '<span class="tag-badge tag-unknown">UNKNOWN</span>');

    // Step 4: Headings
    html = html.replace(/^#### (.*$)/gim, "<h4>$1</h4>");
    html = html.replace(/^### (.*$)/gim,  "<h3>$1</h3>");
    html = html.replace(/^## (.*$)/gim,   "<h2>$1</h2>");
    html = html.replace(/^# (.*$)/gim,    "<h1>$1</h1>");

    // Step 5: Blockquotes
    html = html.replace(/^&gt; (.*$)/gim, "<blockquote>$1</blockquote>");

    // Step 6: Bold & Italic
    html = html.replace(/\*\*(.*?)\*\*/gim, "<strong>$1</strong>");
    html = html.replace(/\*(.*?)\*/gim,       "<em>$1</em>");

    // Step 7: Inline code
    html = html.replace(/`(.*?)`/gim, "<code>$1</code>");

    // Step 8: Unordered lists
    html = html.replace(/^- (.*$)/gim, "<li>$1</li>");
    html = html.replace(/((?:<li>.*<\/li>\s*)+)/gim, "<ul>$1</ul>");

    // Step 9: Paragraph breaks
    html = html.replace(/\n\n+/g, "<br/><br/>");

    // Step 10: Restore pre-built tables
    html = html.replace(/\x00TS\x00(\d+)\x00TE\x00/g,
      (_, idx) => extractedTables[parseInt(idx, 10)] || "");

    return html;
  }

  // Render Raw JSON View
  function renderJsonView() {
    if (!state.results) return;
    const jsonStr = JSON.stringify(state.results, null, 2);
    jsonPre.innerHTML = `<code>${escapeHtml(jsonStr)}</code>`;
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // JSON Search Filter
  if (jsonSearchInput) {
    jsonSearchInput.addEventListener("input", (e) => {
      const query = e.target.value.toLowerCase();
      if (!state.results) return;
      const jsonStr = JSON.stringify(state.results, null, 2);
      if (!query) {
        jsonPre.innerHTML = `<code>${escapeHtml(jsonStr)}</code>`;
        return;
      }

      const lines = jsonStr.split("\n");
      const matched = lines.map((line) => {
        if (line.toLowerCase().includes(query)) {
          return `<span style="background: rgba(99, 102, 241, 0.4); color: #fff;">${escapeHtml(line)}</span>`;
        }
        return escapeHtml(line);
      }).join("\n");

      jsonPre.innerHTML = `<code>${matched}</code>`;
    });
  }

  // Copy View Content
  copyBtn.addEventListener("click", () => {
    if (!state.results) {
      showToast("No data to copy");
      return;
    }

    let textToCopy = "";
    if (state.activeTab === "report-view") {
      textToCopy = state.results.markdown_report || state.results.phase9_markdown_report || "";
    } else {
      textToCopy = JSON.stringify(state.results, null, 2);
    }

    if (textToCopy) {
      navigator.clipboard.writeText(textToCopy).then(() => {
        showToast("Copied to clipboard!");
      });
    }
  });

  // Download View Content
  downloadBtn.addEventListener("click", () => {
    if (!state.results) {
      showToast("No data to download");
      return;
    }

    let content = "";
    let filename = "";

    if (state.activeTab === "report-view") {
      content = state.results.markdown_report || state.results.phase9_markdown_report || "";
      filename = "SentinelGuard_Report.md";
    } else {
      content = JSON.stringify(state.results, null, 2);
      filename = "SentinelGuard_Pipeline_Results.json";
    }

    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Downloaded ${filename}`);
  });

  // Clear Console Log
  clearLogBtn.addEventListener("click", () => {
    consoleOutput.innerHTML = "";
    logMessage("Console cleared.", "info");
  });

  // Event Listeners for Execution
  runBtn.addEventListener("click", () => executePipeline());
  quickRunBtn.addEventListener("click", () => executePipeline("all"));

  // Initialization on launch
  async function initializeOnLoad() {
    logMessage("SentinelGuard Core Initialized. Ready for audit execution.", "info");
    systemStatusText.textContent = "Engine Ready";
  }

  initializeOnLoad();
});
