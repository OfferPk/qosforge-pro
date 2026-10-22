/**
 * QoSForge Pro (v1.0.0) - 10-Point Zero-Trust QoS Security & Performance Auditor
 */

const QoSSecurityAuditor = (() => {
  const PRESETS = {
    enterprise_campus: {
      name: "Enterprise Campus & Unified Communications (VoIP EF + Video AF41)",
      trust_boundary_enforced: true,
      trust_device: "cisco-phone",
      priority_queue_enabled: true,
      priority_bandwidth_percent: 25,
      priority_policed: true,
      cir_kbps: 100000,
      bc_bytes: 312500,
      be_bytes: 625000,
      wred_enabled: true,
      ecn_enabled: true,
      shaping_used: true,
      control_plane_protected: true,
      scavenger_throttled: true,
      tcp_mss_clamping: true,
      telemetry_enabled: true
    },
    financial_lowlatency: {
      name: "Financial Low-Latency Trading Desk (Market Data Priority + ECN + Microburst Shield)",
      trust_boundary_enforced: true,
      trust_device: "none",
      priority_queue_enabled: true,
      priority_bandwidth_percent: 30,
      priority_policed: true,
      cir_kbps: 10000000,
      bc_bytes: 12500000,
      be_bytes: 25000000,
      wred_enabled: true,
      ecn_enabled: true,
      shaping_used: false,
      control_plane_protected: true,
      scavenger_throttled: true,
      tcp_mss_clamping: true,
      telemetry_enabled: true
    },
    vulnerable_fifo: {
      name: "Vulnerable Legacy FIFO (Bufferbloat, No Trust Boundary, Unpoliced Priority)",
      trust_boundary_enforced: false,
      trust_device: "untrusted_blind",
      priority_queue_enabled: false,
      priority_bandwidth_percent: 0,
      priority_policed: false,
      cir_kbps: 50000,
      bc_bytes: 1500,
      be_bytes: 0,
      wred_enabled: false,
      ecn_enabled: false,
      shaping_used: false,
      control_plane_protected: false,
      scavenger_throttled: false,
      tcp_mss_clamping: false,
      telemetry_enabled: false
    }
  };

  function audit(cfg) {
    const findings = [];
    let score = 0;

    // 1. Trust Boundary
    if (cfg.trust_boundary_enforced) {
      score += 10;
      findings.push({
        id: "trust_boundary",
        title: "Trust Boundary Ingress Filtering",
        passed: true,
        weight: 10,
        notes: "Access ports untrusted; DSCP re-marking prevents rogue clients from injecting DSCP EF (46) or CS6/CS7."
      });
    } else {
      findings.push({
        id: "trust_boundary",
        title: "Trust Boundary Ingress Filtering",
        passed: false,
        weight: 10,
        notes: "CRITICAL: Access ports trust incoming DSCP blindly! Attackers can inject DSCP EF (46) to hijack priority queues."
      });
    }

    // 2. Strict Priority Queue Policed
    if (cfg.priority_queue_enabled) {
      if (cfg.priority_policed) {
        score += 10;
        findings.push({
          id: "priority_policed",
          title: "Priority Queue (LLQ) Policed",
          passed: true,
          weight: 10,
          notes: "Strict priority queue bounded by policer to prevent starvation of data & routing queues."
        });
      } else {
        findings.push({
          id: "priority_policed",
          title: "Priority Queue (LLQ) Policed",
          passed: false,
          weight: 10,
          notes: "CRITICAL: Priority queue has no policer! A runaway audio stream or UDP flood will completely starve routing and data traffic."
        });
      }
    } else {
      findings.push({
        id: "priority_policed",
        title: "Priority Queue (LLQ) Policed",
        passed: false,
        weight: 10,
        notes: "No priority queuing configured (all traffic shares default FIFO buffer)."
      });
    }

    // 3. Priority Bandwidth Proportion Limit (<= 33%)
    const pPct = cfg.priority_bandwidth_percent || 0;
    if (pPct > 0 && pPct <= 33) {
      score += 10;
      findings.push({
        id: "priority_ratio",
        title: "Priority Bandwidth Ratio",
        passed: true,
        weight: 10,
        notes: `Priority queue configured at safe ${pPct}% of link capacity (<= 33% standard practice).`
      });
    } else if (pPct > 33) {
      findings.push({
        id: "priority_ratio",
        title: "Priority Bandwidth Ratio",
        passed: false,
        weight: 10,
        notes: `WARNING: Priority allocation is ${pPct}%, exceeding Cisco/IETF 33% safety ceiling and risking queue starvation.`
      });
    } else {
      findings.push({
        id: "priority_ratio",
        title: "Priority Bandwidth Ratio",
        passed: false,
        weight: 10,
        notes: "No dedicated bandwidth guarantee for voice/telepresence."
      });
    }

    // 4. Committed Burst (Bc) Sizing
    const cir = cfg.cir_kbps || 1000;
    const bc = cfg.bc_bytes || 0;
    const minSafeBc = Math.max(2250, Math.floor((cir * 1000 / 8.0) * 0.010));
    if (bc >= minSafeBc) {
      score += 10;
      findings.push({
        id: "bc_sizing",
        title: "Committed Burst (Bc) Sizing",
        passed: true,
        weight: 10,
        notes: `Bc (${bc} bytes) satisfies minimum burst criteria (${minSafeBc} bytes) to absorb microbursts without false drops.`
      });
    } else {
      findings.push({
        id: "bc_sizing",
        title: "Committed Burst (Bc) Sizing",
        passed: false,
        weight: 10,
        notes: `HIGH RISK: Bc (${bc} bytes) is too small! Will drop legitimate TCP packets during microbursts even under 30% average load.`
      });
    }

    // 5. WRED Congestion Avoidance
    if (cfg.wred_enabled) {
      score += 10;
      findings.push({
        id: "wred_enabled",
        title: "WRED Congestion Avoidance",
        passed: true,
        weight: 10,
        notes: "Weighted Random Early Detection enabled; prevents TCP global synchronization and bufferbloat."
      });
    } else {
      findings.push({
        id: "wred_enabled",
        title: "WRED Congestion Avoidance",
        passed: false,
        weight: 10,
        notes: "Buffer uses pure tail-drop FIFO; vulnerable to TCP global synchronization and severe latency spikes."
      });
    }

    // 6. Explicit Congestion Notification (ECN)
    if (cfg.ecn_enabled) {
      score += 10;
      findings.push({
        id: "ecn_enabled",
        title: "Explicit Congestion Notification (ECN)",
        passed: true,
        weight: 10,
        notes: "ECN marking (CE 11) enabled, allowing endpoints to back off transmission without retransmission drop latency."
      });
    } else {
      findings.push({
        id: "ecn_enabled",
        title: "Explicit Congestion Notification (ECN)",
        passed: false,
        weight: 10,
        notes: "ECN disabled; routers drop packets instead of signaling congestion in IP header."
      });
    }

    // 7. Control Plane Protection
    if (cfg.control_plane_protected) {
      score += 10;
      findings.push({
        id: "control_plane",
        title: "Control Plane Protocol Protection",
        passed: true,
        weight: 10,
        notes: "Routing protocols (OSPF, BGP, BFD) mapped to CS6/CS7 with dedicated bandwidth guarantee."
      });
    } else {
      findings.push({
        id: "control_plane",
        title: "Control Plane Protocol Protection",
        passed: false,
        weight: 10,
        notes: "HIGH RISK: Routing protocol hellos share best-effort queue and will flap during network congestion."
      });
    }

    // 8. Scavenger / Bulk Traffic Throttling
    if (cfg.scavenger_throttled) {
      score += 10;
      findings.push({
        id: "scavenger",
        title: "Scavenger / Bulk Traffic Throttling",
        passed: true,
        weight: 10,
        notes: "P2P and background downloads assigned low drop thresholds and throttled to prevent resource monopolization."
      });
    } else {
      findings.push({
        id: "scavenger",
        title: "Scavenger / Bulk Traffic Throttling",
        passed: false,
        weight: 10,
        notes: "No scavenger policy; bulk background transfers compete equally with business transactions."
      });
    }

    // 9. Shaping Discipline on Egress
    if (cfg.shaping_used) {
      score += 10;
      findings.push({
        id: "shaping",
        title: "Egress Traffic Shaping (vs. Hard Policing)",
        passed: true,
        weight: 10,
        notes: "Traffic shaping buffers egress bursts smoothly, preserving TCP window growth."
      });
    } else if (cfg.cir_kbps >= 10000000) {
      score += 10;
      findings.push({
        id: "shaping",
        title: "Egress Traffic Shaping (vs. Hard Policing)",
        passed: true,
        weight: 10,
        notes: "Ultra low latency line-rate forwarding deliberately bypasses shaping buffers for ultra-low latency."
      });
    } else {
      findings.push({
        id: "shaping",
        title: "Egress Traffic Shaping (vs. Hard Policing)",
        passed: false,
        weight: 10,
        notes: "Hard policing on egress interface will trigger out-of-order drops and collapse TCP throughput."
      });
    }

    // 10. TCP MSS Clamping & Telemetry
    if (cfg.tcp_mss_clamping && cfg.telemetry_enabled) {
      score += 10;
      findings.push({
        id: "mss_telemetry",
        title: "TCP MSS Clamping & Telemetry Visibility",
        passed: true,
        weight: 10,
        notes: "MSS clamping active to prevent tunnel fragmentation; queue drop counters monitored via telemetry."
      });
    } else if (cfg.tcp_mss_clamping || cfg.telemetry_enabled) {
      score += 5;
      findings.push({
        id: "mss_telemetry",
        title: "TCP MSS Clamping & Telemetry Visibility",
        passed: false,
        weight: 10,
        notes: "Partially configured: Enable both TCP MSS clamping and streaming drop telemetry."
      });
    } else {
      findings.push({
        id: "mss_telemetry",
        title: "TCP MSS Clamping & Telemetry Visibility",
        passed: false,
        weight: 10,
        notes: "Missing MSS clamping and telemetry; silent packet fragmentation and untracked queue drops will occur."
      });
    }

    const grade = score >= 95 ? "A+" : score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";

    return {
      score,
      grade,
      findings
    };
  }

  return {
    PRESETS,
    audit
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = QoSSecurityAuditor;
}
