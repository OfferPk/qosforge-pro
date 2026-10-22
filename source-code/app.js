/**
 * QoSForge Pro (v1.0.0) - Main Application Controller
 */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const presetSelect = document.getElementById("presetSelect");
  const dscpSelect = document.getElementById("dscpSelect");
  const ecnSelect = document.getElementById("ecnSelect");
  const cirInput = document.getElementById("cirInput");
  const bcInput = document.getElementById("bcInput");
  const beInput = document.getElementById("beInput");
  const lineRateInput = document.getElementById("lineRateInput");

  // Auditor inputs
  const trustBoundaryCheck = document.getElementById("trustBoundaryCheck");
  const priorityQueueCheck = document.getElementById("priorityQueueCheck");
  const priorityPolicedCheck = document.getElementById("priorityPolicedCheck");
  const priorityPctInput = document.getElementById("priorityPctInput");
  const wredCheck = document.getElementById("wredCheck");
  const ecnCheck = document.getElementById("ecnCheck");
  const controlPlaneCheck = document.getElementById("controlPlaneCheck");
  const scavengerCheck = document.getElementById("scavengerCheck");
  const shapingCheck = document.getElementById("shapingCheck");
  const mssClampingCheck = document.getElementById("mssClampingCheck");
  const telemetryCheck = document.getElementById("telemetryCheck");

  // Output elements
  const rawTosDisplay = document.getElementById("rawTosDisplay");
  const dscpNameDisplay = document.getElementById("dscpNameDisplay");
  const ecnNameDisplay = document.getElementById("ecnNameDisplay");
  const cosDisplay = document.getElementById("cosDisplay");

  const auditScoreDisplay = document.getElementById("auditScoreDisplay");
  const auditGradeBadge = document.getElementById("auditGradeBadge");
  const auditListContainer = document.getElementById("auditListContainer");

  const calcBcRecDisplay = document.getElementById("calcBcRecDisplay");
  const calcTcDisplay = document.getElementById("calcTcDisplay");
  const calcDrainDisplay = document.getElementById("calcDrainDisplay");

  const simTableBody = document.getElementById("simTableBody");
  const hexdumpDisplay = document.getElementById("hexdumpDisplay");
  const configOutput = document.getElementById("configOutput");
  const platformSelect = document.getElementById("platformSelect");

  const btnDownloadPcap = document.getElementById("btnDownloadPcap");
  const btnRunSimulation = document.getElementById("btnRunSimulation");
  const btnCopyConfig = document.getElementById("btnCopyConfig");

  // Tab navigation
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const pane = document.getElementById(targetId);
      if (pane) pane.classList.add("active");
    });
  });

  // Populate DSCP dropdown
  for (const [code, info] of Object.entries(QoSProtocolEngine.DSCP_TABLE)) {
    const opt = document.createElement("option");
    opt.value = code;
    opt.textContent = `${info.name} (DSCP ${code})`;
    if (code === "46") opt.selected = true;
    dscpSelect.appendChild(opt);
  }

  // Populate ECN dropdown
  for (const [code, info] of Object.entries(QoSProtocolEngine.ECN_TABLE)) {
    const opt = document.createElement("option");
    opt.value = code;
    opt.textContent = `${info.name}`;
    if (code === "3") opt.selected = true; // CE default
    ecnSelect.appendChild(opt);
  }

  function getFormConfig() {
    return {
      trust_boundary_enforced: trustBoundaryCheck.checked,
      priority_queue_enabled: priorityQueueCheck.checked,
      priority_policed: priorityPolicedCheck.checked,
      priority_bandwidth_percent: parseInt(priorityPctInput.value, 10) || 0,
      cir_kbps: parseInt(cirInput.value, 10) || 100000,
      bc_bytes: parseInt(bcInput.value, 10) || 312500,
      be_bytes: parseInt(beInput.value, 10) || 625000,
      wred_enabled: wredCheck.checked,
      ecn_enabled: ecnCheck.checked,
      shaping_used: shapingCheck.checked,
      control_plane_protected: controlPlaneCheck.checked,
      scavenger_throttled: scavengerCheck.checked,
      tcp_mss_clamping: mssClampingCheck.checked,
      telemetry_enabled: telemetryCheck.checked
    };
  }

  function loadPreset(key) {
    const p = QoSSecurityAuditor.PRESETS[key];
    if (!p) return;

    cirInput.value = p.cir_kbps;
    bcInput.value = p.bc_bytes;
    beInput.value = p.be_bytes;

    trustBoundaryCheck.checked = p.trust_boundary_enforced;
    priorityQueueCheck.checked = p.priority_queue_enabled;
    priorityPolicedCheck.checked = p.priority_policed;
    priorityPctInput.value = p.priority_bandwidth_percent;
    wredCheck.checked = p.wred_enabled;
    ecnCheck.checked = p.ecn_enabled;
    controlPlaneCheck.checked = p.control_plane_protected;
    scavengerCheck.checked = p.scavenger_throttled;
    shapingCheck.checked = p.shaping_used;
    mssClampingCheck.checked = p.tcp_mss_clamping;
    telemetryCheck.checked = p.telemetry_enabled;

    updateAll();
  }

  function updateAll() {
    const dscp = parseInt(dscpSelect.value, 10);
    const ecn = parseInt(ecnSelect.value, 10);
    const tosByte = ((dscp & 0x3F) << 2) | (ecn & 0x03);

    // 1. Dissect ToS
    const dissected = QoSProtocolEngine.dissectToS(tosByte);
    rawTosDisplay.textContent = `${dissected.raw_tos_hex} (0b${dissected.raw_tos_bin})`;
    dscpNameDisplay.textContent = `${dissected.dscp_name} (${dissected.dscp_class})`;
    ecnNameDisplay.textContent = `${dissected.ecn_name}: ${dissected.ecn_desc}`;
    cosDisplay.textContent = `CoS / IP Prec: ${dissected.cos_8021p}`;

    // 2. Token Bucket Calculations
    const cir = parseInt(cirInput.value, 10) || 100000;
    const bc = parseInt(bcInput.value, 10) || 312500;
    const be = parseInt(beInput.value, 10) || 625000;
    const lineRate = parseInt(lineRateInput.value, 10) || 1000;

    const tb = QoSProtocolEngine.calculateTokenBucket(cir, bc, be, lineRate);
    calcBcRecDisplay.textContent = `${tb.rec_bc_bytes.toLocaleString()} Bytes`;
    calcTcDisplay.textContent = `${tb.tc_ms} ms`;
    calcDrainDisplay.textContent = `${tb.buffer_drain_time_ms} ms`;

    // 3. Security Audit
    const cfg = getFormConfig();
    const auditRes = QoSSecurityAuditor.audit(cfg);
    auditScoreDisplay.textContent = `${auditRes.score}/100`;
    auditGradeBadge.textContent = `Grade ${auditRes.grade}`;
    auditGradeBadge.className = `pill ${auditRes.score >= 80 ? 'pill-green' : auditRes.score >= 60 ? 'pill-yellow' : 'pill-red'}`;

    auditListContainer.innerHTML = "";
    auditRes.findings.forEach(f => {
      const item = document.createElement("div");
      item.className = `audit-item ${f.passed ? 'pass' : 'fail'}`;
      item.innerHTML = `
        <div class="audit-icon">${f.passed ? '✓' : '✗'}</div>
        <div class="audit-details">
          <h4>${f.title} (${f.weight} pts)</h4>
          <p>${f.notes}</p>
        </div>
      `;
      auditListContainer.appendChild(item);
    });

    // 4. Generate Packet & Hex Dump
    const packetBytes = QoSProtocolEngine.forgeQoSPacket(dscp, ecn);
    hexdumpDisplay.textContent = QoSProtocolEngine.formatHexDump(packetBytes);

    // 5. Synthesize Config
    const platform = platformSelect.value;
    configOutput.textContent = QoSConfigSynthesizer.synthesize(platform, cfg);

    // 6. Update visualizer
    runSimulation();
  }

  function runSimulation() {
    const cir = parseInt(cirInput.value, 10) || 100000;
    const bc = parseInt(bcInput.value, 10) || 312500;
    const be = parseInt(beInput.value, 10) || 625000;

    const packetSizes = [1500, 1500, 1500, 1500, 1500, 1500, 64, 1500];
    const arrivalIntervalsMs = [0.0, 0.1, 0.1, 0.1, 0.2, 0.2, 0.05, 0.2];

    const simResults = QoSProtocolEngine.simulatePolicer(cir, bc, be, packetSizes, arrivalIntervalsMs);
    simTableBody.innerHTML = "";

    simResults.forEach(p => {
      const tr = document.createElement("tr");
      const isGreen = p.color.includes("GREEN");
      const isYellow = p.color.includes("YELLOW");
      const pillClass = isGreen ? "pill-green" : isYellow ? "pill-yellow" : "pill-red";

      tr.innerHTML = `
        <td><strong>#${p.packet_id}</strong></td>
        <td>${p.arrival_time_ms} ms</td>
        <td>${p.size_bytes} B</td>
        <td>${p.tc_remaining.toLocaleString()} B</td>
        <td><span class="pill ${pillClass}">${p.color}</span></td>
        <td>${p.action}</td>
      `;
      simTableBody.appendChild(tr);
    });

    // Update gauge levels
    const lastResult = simResults[simResults.length - 1];
    const waterC = document.getElementById("waterBucketC");
    const waterE = document.getElementById("waterBucketE");
    if (waterC && bc > 0) {
      const pctC = Math.max(0, Math.min(100, (lastResult.tc_remaining / bc) * 100));
      waterC.style.height = `${pctC}%`;
    }
    if (waterE && be > 0) {
      const pctE = Math.max(0, Math.min(100, (lastResult.te_remaining / be) * 100));
      waterE.style.height = `${pctE}%`;
    }
  }

  // Event Listeners
  presetSelect.addEventListener("change", (e) => loadPreset(e.target.value));
  dscpSelect.addEventListener("change", updateAll);
  ecnSelect.addEventListener("change", updateAll);
  platformSelect.addEventListener("change", updateAll);

  [cirInput, bcInput, beInput, lineRateInput, priorityPctInput].forEach(inp => {
    inp.addEventListener("input", updateAll);
  });

  [
    trustBoundaryCheck, priorityQueueCheck, priorityPolicedCheck,
    wredCheck, ecnCheck, controlPlaneCheck, scavengerCheck,
    shapingCheck, mssClampingCheck, telemetryCheck
  ].forEach(chk => {
    chk.addEventListener("change", updateAll);
  });

  if (btnRunSimulation) {
    btnRunSimulation.addEventListener("click", runSimulation);
  }

  if (btnDownloadPcap) {
    btnDownloadPcap.addEventListener("click", () => {
      const dscp = parseInt(dscpSelect.value, 10);
      const ecn = parseInt(ecnSelect.value, 10);
      const pkt = QoSProtocolEngine.forgeQoSPacket(dscp, ecn);
      const pcapData = QoSProtocolEngine.buildPcap([pkt]);
      const blob = new Blob([pcapData], { type: "application/vnd.tcpdump.pcap" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `qosforge_dscp${dscp}_ecn${ecn}.pcap`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  if (btnCopyConfig) {
    btnCopyConfig.addEventListener("click", () => {
      navigator.clipboard.writeText(configOutput.textContent).then(() => {
        const originalText = btnCopyConfig.textContent;
        btnCopyConfig.textContent = "Copied!";
        setTimeout(() => { btnCopyConfig.textContent = originalText; }, 2000);
      });
    });
  }

  // Initial load
  loadPreset("enterprise_campus");
});
