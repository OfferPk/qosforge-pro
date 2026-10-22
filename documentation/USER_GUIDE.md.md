# QoSForge Pro (v1.0.0) — Operations & DevSecOps User Manual

## 1\. Quick Start

### 1.1 Web Studio

Open `source-code/index.html` in any modern web browser (Chrome, Firefox, Safari, Edge).

* Zero external build dependencies, no npm install, 100% client-side privacy.  
* Select an industry preset from the top bar to inspect pre-tuned configurations.  
* Modify CIR, Bc, Be, and priority percentages in real-time.  
* Export binary `.pcap` files directly from the browser.

### 1.2 Standalone Python CLI Tool

The DevSecOps CLI tool is located at `build/qosforge-cli.py`. Requirements: Standard Python 3.6+ with zero third-party packages.

\# Make executable

chmod \+x build/qosforge-cli.py

\# Dissect a raw ToS byte (e.g., DSCP EF \+ ECN CE \= 0xBB)

./build/qosforge-cli.py dissect \--tos 0xbb

\# Dissect by DSCP and ECN values

./build/qosforge-cli.py dissect \--dscp 46 \--ecn 3

\# Execute 10-Point Zero-Trust Architecture Audit

./build/qosforge-cli.py audit \--preset enterprise\_campus

\# Run audit in CI/CD mode with strict exit code gating

./build/qosforge-cli.py audit \--preset enterprise\_campus \--strict

\# Calculate Token Bucket Parameters

./build/qosforge-cli.py calculate \--cir 100000 \--bc 312500 \--line-rate 1000

\# Simulate Token Bucket Packet Processing over a burst

./build/qosforge-cli.py simulate \--cir 100000 \--bc 312500 \--be 625000

\# Forge a valid binary PCAP packet capture with exact DSCP & ECN

./build/qosforge-cli.py pcap \--dscp 46 \--ecn 3 \-o voip\_ef\_ecn.pcap \--hexdump

\# Synthesize Multi-Platform Configurations

./build/qosforge-cli.py synthesize \--platform cisco\_iosxe \--preset enterprise\_campus

./build/qosforge-cli.py synthesize \--platform juniper\_junos \--preset enterprise\_campus

./build/qosforge-cli.py synthesize \--platform linux\_tc \--preset enterprise\_campus

---

## 2\. DevSecOps CI/CD Integration

Integrate QoS policy validation into GitHub Actions or GitLab CI to ensure zero misconfigurations reach production:

name: QoS & Traffic Engineering Policy Lint

on: \[push, pull\_request\]

jobs:

  qos-audit:

    runs-on: ubuntu-latest

    steps:

      \- uses: actions/checkout@v4

      \- name: Set up Python

        uses: actions/setup-python@v5

        with:

          python-version: '3.11'

      \- name: Validate QoS Policy Spec

        run: |

          python3 build/qosforge-cli.py audit \--config configs/production-edge.json \--strict

---

## 3\. Supported Platforms & Synthesizer Output

1. **Cisco IOS-XE (Modular QoS CLI \- MQC)**:  
   - Complete `class-map`, `policy-map`, and `service-policy` hierarchies.  
   - Strict priority LLQ with embedded policing.  
   - WRED `random-detect dscp-based` and `random-detect ecn`.  
   - Ingress trust boundary re-marking.  
2. **Cisco Nexus NX-OS**:  
   - `type queuing` class-maps and policy-maps.  
   - DWRR bandwidth distribution and WRED buffer thresholds.  
3. **Juniper Junos (CoS)**:  
   - `forwarding-classes`, `classifiers`, `drop-profiles`, and `schedulers`.  
   - `scheduler-maps` with strict-high voice scheduling.  
4. **Arista EOS**:  
   - `qos map dscp to traffic-class`.  
   - `qos profile` with strict priority and ECN.  
5. **Linux `tc` (Traffic Control)**:  
   - HTB hierarchical token bucket with FQ\_CoDel / CAKE active queue management.