/**
 * QoSForge Pro (v1.0.0) - Multi-Platform Configuration Synthesizer
 * Generates production-ready QoS configs for Cisco, Juniper, Arista, and Linux.
 */

const QoSConfigSynthesizer = (() => {
  function generateCiscoIOSXE(cfg) {
    const cirBps = (cfg.cir_kbps || 100000) * 1000;
    const bcBytes = cfg.bc_bytes || 312500;
    const beBytes = cfg.be_bytes || 625000;
    const pPct = cfg.priority_bandwidth_percent || 25;

    return `! ============================================================
! Cisco IOS-XE Modular QoS CLI (MQC) Production Template
! Synthesized by QoSForge Pro (v1.0.0)
! Target Profile: ${cfg.name || "Custom Edge"}
! ============================================================
!
! --- Step 1: Define Traffic Class-Maps (RFC 2474 / RFC 2597 / RFC 3246) ---
class-map match-any CM-VOICE-EF
 match ip dscp ef
 match ip dscp voice-admit
 match cos 5
!
class-map match-any CM-VIDEO-INTERACTIVE
 match ip dscp af41 af42 af43
 match cos 4
!
class-map match-any CM-CALL-SIGNALING
 match ip dscp cs3 af31
 match cos 3
!
class-map match-any CM-ROUTING-CONTROL
 match ip dscp cs6 cs7
 match cos 6 7
!
class-map match-any CM-SCAVENGER
 match ip dscp cs1
 match cos 1
!
! --- Step 2: Build Modular Policy-Map (LLQ + CBWFQ + WRED / ECN) ---
policy-map PM-QOS-EDGE-EGRESS
 class CM-VOICE-EF
  priority percent ${pPct}
  police ${Math.floor(cirBps / 4)} ${Math.floor(bcBytes / 4)} ${Math.floor(beBytes / 4)} conform-action transmit exceed-action drop violate-action drop
 class CM-VIDEO-INTERACTIVE
  bandwidth percent 20
  random-detect dscp-based
  random-detect ecn
 class CM-CALL-SIGNALING
  bandwidth percent 5
 class CM-ROUTING-CONTROL
  bandwidth percent 5
 class CM-SCAVENGER
  bandwidth percent 1
 class class-default
  bandwidth percent 40
  random-detect dscp-based
  random-detect ecn
!
! --- Step 3: Ingress Trust Boundary & Re-marking Policy ---
policy-map PM-INGRESS-TRUST-ENFORCE
 class CM-VOICE-EF
  set dscp ef
 class CM-ROUTING-CONTROL
  set dscp cs6
 class class-default
  set dscp default
!
! --- Step 4: Apply to Interfaces ---
interface GigabitEthernet0/0/1
 description Uplink to WAN / Core
 shape average ${cirBps} ${bcBytes * 8} ${beBytes * 8}
 service-policy output PM-QOS-EDGE-EGRESS
 ip tcp adjust-mss 1360
!
interface GigabitEthernet0/0/2
 description Access Port to Endpoints
 service-policy input PM-INGRESS-TRUST-ENFORCE`;
  }

  function generateCiscoNXOS(cfg) {
    const pPct = cfg.priority_bandwidth_percent || 25;
    return `! ============================================================
! Cisco Nexus NX-OS Data Center QoS Architecture
! Synthesized by QoSForge Pro (v1.0.0)
! ============================================================
!
! --- Step 1: Ingress Queuing Class-Map ---
class-map type queuing match-any c-out-priority
  match cos 5
  match dscp 46
class-map type queuing match-any c-out-video
  match cos 4
  match dscp 34
!
! --- Step 2: Egress Queuing Policy (LLQ + DWRR) ---
policy-map type queuing p-out-queuing
  class type queuing c-out-priority
    priority level 1
  class type queuing c-out-video
    bandwidth percent 25
  class type queuing class-default
    bandwidth percent ${100 - pPct - 25}
    random-detect threshold minimum 40 kbytes maximum 80 kbytes drop-probability 20 weight 1
    random-detect ecn
!
! --- Step 3: System-level Policy Application ---
system qos
  service-policy type queuing output p-out-queuing`;
  }

  function generateJuniperJunos(cfg) {
    const cirBps = (cfg.cir_kbps || 100000) * 1000;
    const pPct = cfg.priority_bandwidth_percent || 25;

    return `# ============================================================
# Juniper Junos Class of Service (CoS) Production Hierarchy
# Synthesized by QoSForge Pro (v1.0.0)
# ============================================================
class-of-service {
    forwarding-classes {
        class voice-ef queue-num 0 priority strict-high;
        class video-af41 queue-num 1 priority high;
        class signaling-cs3 queue-num 2 priority medium-high;
        class network-control queue-num 3 priority strict-high;
        class best-effort queue-num 4 priority low;
        class scavenger-cs1 queue-num 5 priority low;
    }
    classifiers {
        dscp CLASSIFIER-DSCP-V4 {
            forwarding-class voice-ef {
                loss-priority low code-points 101110;
            }
            forwarding-class video-af41 {
                loss-priority low code-points 100010;
                loss-priority medium code-points 100100;
            }
            forwarding-class network-control {
                loss-priority low code-points [ 110000 111000 ];
            }
            forwarding-class best-effort {
                loss-priority low code-points 000000;
            }
        }
    }
    drop-profiles {
        DROP-PROFILE-WRED-ECN {
            interpolate {
                fill-level [ 40 80 ];
                drop-probability [ 0 25 ];
            }
        }
    }
    schedulers {
        SCHED-VOICE {
            transmit-rate percent ${pPct};
            buffer-size percent 10;
            priority strict-high;
        }
        SCHED-DATA-ECN {
            transmit-rate percent 40;
            buffer-size percent 40;
            drop-profile-map loss-priority any protocol non-tcp drop-profile DROP-PROFILE-WRED-ECN;
            explicit-congestion-notification;
        }
    }
    scheduler-maps {
        SMAP-EDGE-QOS {
            forwarding-class voice-ef scheduler SCHED-VOICE;
            forwarding-class best-effort scheduler SCHED-DATA-ECN;
        }
    }
    interfaces {
        ge-0/0/0 {
            scheduler-map SMAP-EDGE-QOS;
            shaping-rate ${cirBps};
            unit 0 {
                classifiers {
                    dscp CLASSIFIER-DSCP-V4;
                }
            }
        }
    }
}`;
  }

  function generateAristaEOS(cfg) {
    return `! ============================================================
! Arista EOS Enterprise QoS & Traffic Management
! Synthesized by QoSForge Pro (v1.0.0)
! ============================================================
!
! --- Step 1: DSCP to Traffic-Class Mapping ---
qos map dscp 46 to traffic-class 7
qos map dscp 34 to traffic-class 5
qos map dscp 48 56 to traffic-class 6
qos map dscp 0 to traffic-class 0
!
! --- Step 2: Strict Priority & ECN Configuration ---
qos profile ENTERPRISE-QOS-PROFILE
  tx-queue 7
    priority strict
  tx-queue 5
    bandwidth percent 25
  tx-queue 0
    bandwidth percent 50
    ecn enable
!
! --- Step 3: Apply to Uplink Interfaces ---
interface Ethernet1
  qos profile ENTERPRISE-QOS-PROFILE`;
  }

  function generateLinuxTC(cfg) {
    const cirKbps = cfg.cir_kbps || 100000;
    const pPct = cfg.priority_bandwidth_percent || 25;
    const voiceRate = Math.max(1000, Math.floor((cirKbps * pPct) / 100));
    const dataRate = Math.max(1000, Math.floor((cirKbps * 50) / 100));

    return `#!/usr/bin/env bash
# ============================================================
# Linux Traffic Control (tc) HTB + FQ_CoDel / CAKE QoS Script
# Synthesized by QoSForge Pro (v1.0.0)
# ============================================================
set -euo pipefail
IFACE="eth0"
TOTAL_RATE="${cirKbps}kbit"
VOICE_RATE="${voiceRate}kbit"
DATA_RATE="${dataRate}kbit"

# Clear existing root qdisc
tc qdisc del dev "$IFACE" root 2>/dev/null || true

# Create HTB root qdisc
tc qdisc add dev "$IFACE" root handle 1: htb default 30
tc class add dev "$IFACE" parent 1: classid 1:1 htb rate "$TOTAL_RATE" ceil "$TOTAL_RATE"

# Class 1:10 (Strict Priority VoIP EF / DSCP 46)
tc class add dev "$IFACE" parent 1:1 classid 1:10 htb rate "$VOICE_RATE" ceil "$TOTAL_RATE" prio 1

# Class 1:20 (Interactive Video AF41)
tc class add dev "$IFACE" parent 1:1 classid 1:20 htb rate "$DATA_RATE" ceil "$TOTAL_RATE" prio 2

# Class 1:30 (Default Best Effort with FQ_CoDel + ECN to eliminate bufferbloat)
tc class add dev "$IFACE" parent 1:1 classid 1:30 htb rate "$DATA_RATE" ceil "$TOTAL_RATE" prio 3
tc qdisc add dev "$IFACE" parent 1:30 handle 30: fq_codel ecn

# Filter matching DSCP EF (TOS 0xb8 = 184 / 0x46<<2)
tc filter add dev "$IFACE" parent 1:0 protocol ip prio 1 u32 \\
  match ip tos 0xb8 0xfc flowid 1:10

# Filter matching DSCP AF41 (TOS 0x88 = 136 / 0x22<<2)
tc filter add dev "$IFACE" parent 1:0 protocol ip prio 2 u32 \\
  match ip tos 0x88 0xfc flowid 1:20

echo "[+] QoSForge: HTB and FQ_CoDel active on $IFACE ($TOTAL_RATE)"`;
  }

  function synthesize(platform, cfg) {
    switch (platform) {
      case "cisco_iosxe":
        return generateCiscoIOSXE(cfg);
      case "cisco_nxos":
        return generateCiscoNXOS(cfg);
      case "juniper_junos":
        return generateJuniperJunos(cfg);
      case "arista_eos":
        return generateAristaEOS(cfg);
      case "linux_tc":
        return generateLinuxTC(cfg);
      default:
        return generateCiscoIOSXE(cfg);
    }
  }

  return {
    generateCiscoIOSXE,
    generateCiscoNXOS,
    generateJuniperJunos,
    generateAristaEOS,
    generateLinuxTC,
    synthesize
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = QoSConfigSynthesizer;
}
