# QoSForge Pro (v1.0.0) — Technical Architecture & Protocol Engineering Manual

## 1\. System Overview

**QoSForge Pro** is a carrier-grade and enterprise network traffic engineering suite implementing:

* **IETF RFC 2474**: Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers.  
* **IETF RFC 2597**: Assured Forwarding (AF) PHB Group (AF11–AF43).  
* **IETF RFC 3246**: An Expedited Forwarding (EF) Per-Hop Behavior (PHB).  
* **IETF RFC 5865**: A Differentiated Services Code Point (DSCP) for Capacity-Admitted Traffic (Voice-Admit / VA).  
* **IETF RFC 2697**: A Single Rate Three Color Marker (srTCM) Token Bucket Algorithm.  
* **IETF RFC 2698**: A Two Rate Three Color Marker (trTCM) Token Bucket Algorithm.  
* **IETF RFC 3168**: The Addition of Explicit Congestion Notification (ECN) to IP.

       \+-------------------------------------------------------------+

       |               Ingress Ethernet Frame                        |

       |  \[Ethernet II: Dst MAC | Src MAC | EtherType: 0x0800 IPv4\]  |

       \+-------------------------------------------------------------+

                                      |

                                      v

       \+-------------------------------------------------------------+

       |          IPv4 Header: Type of Service (ToS) Byte             |

       |                                                             |

       |  Bit 0   1   2   3   4   5       6          7               |

       | \+---+---+---+---+---+---+    \+-------+--------------+       |

       | |       DSCP (6 bits)   |    |      ECN (2 bits)    |       |

       | |      Codepoint 0..63  |    | 00: Not-ECT  01: ECT1|       |

       | \+---+---+---+---+---+---+    | 10: ECT0     11: CE  |       |

       |   \\\_\_\_\_\_\_\_\_\_\_\_/              \+-------+--------------+       |

       |    IP Precedence (Bits 0..2)                                |

       \+-------------------------------------------------------------+

                                      |

                 \+--------------------+--------------------+

                 |                                         |

                 v                                         v

   \+-----------------------------+           \+-----------------------------+

   |   RFC 2697 srTCM Policer    |           |   RFC 3168 WRED / ECN       |

   |                             |           |                             |

   | CIR: Committed Inf. Rate    |           | Min Threshold (Queue Pkts)  |

   | Bc:  Committed Burst (Bytes)|           | Max Threshold (Queue Pkts)  |

   | Be:  Excess Burst (Bytes)   |           | P\_max: Mark Probability     |

   |                             |           |                             |

   | Green:  Conform (Tc \>= B)   |           | Avg Queue \< Min: 0% Drop    |

   | Yellow: Exceed  (Te \>= B)   |           | Min \<= Avg \< Max: ECN CE    |

   | Red:    Violate (Drop)      |           | Avg \>= Max: Tail Drop       |

   \+-----------------------------+           \+-----------------------------+

---

## 2\. Mathematical Formalisms

### 2.1 RFC 2697 Single-Rate Three-Color Marker (srTCM)

Given:

* CIR (Committed Information Rate in bytes/second): \$R \= \\frac{\\text{CIR}\_{\\text{kbps}} \\times 1000}{8}\$  
* \$B\_c\$ (Committed Burst in bytes)  
* \$B\_e\$ (Excess Burst in bytes)  
* Time elapsed since last packet arrival: \$\\Delta t\$

The token replenishment in Bucket \$C\$ (\$T\_c\$) and Bucket \$E\$ (\$T\_e\$) is governed by: \$\$\\Delta \\text{tokens} \= R \\times \\Delta t\$\$ \$\$T\_c' \= \\min(B\_c, T\_c \+ \\Delta \\text{tokens})\$\$ \$\$\\text{overflow} \= \\max(0, T\_c \+ \\Delta \\text{tokens} \- B\_c)\$\$ \$\$T\_e' \= \\min(B\_e, T\_e \+ \\text{overflow})\$\$

For an incoming packet of size \$B\$ bytes:

1. **Conform (Green)**: If \$T\_c' \- B \\ge 0\$: \$\$T\_c \\leftarrow T\_c' \- B, \\quad T\_e \\leftarrow T\_e'\$\$  
2. **Exceed (Yellow)**: Else if \$T\_e' \- B \\ge 0\$: \$\$T\_c \\leftarrow T\_c', \\quad T\_e \\leftarrow T\_e' \- B\$\$  
3. **Violate (Red)**: Else: \$\$\\text{Packet is dropped or remarked to Scavenger/CS1}\$\$

### 2.2 Sizing Committed Burst (\$B\_c\$) to Avoid Microburst Drops

To prevent false-positive drops during normal TCP window ramp-up and microbursts, \$B\_c\$ must satisfy: \$\$B\_c \\ge \\max\\left(1.5 \\times \\text{MTU}, \\frac{\\text{CIR}}{8} \\times 0.025\\right)\$\$ Where \$0.025\$ represents a 25ms absorption window. Sizing \$B\_c\$ below 10ms causes packet drops even under moderate 30% average link utilization.

### 2.3 WRED & Explicit Congestion Notification (ECN) Probability

Active Queue Management monitors average queue depth using an Exponential Weighted Moving Average (EWMA): \$\$\\text{avg}*k \= (1 \- 2^{-n}) \\cdot \\text{avg}*{k-1} \+ 2^{-n} \\cdot q\_{\\text{instant}}\$\$ The drop/marking probability \$P\_b\$ within the active zone (\$q\_{\\min} \\le \\text{avg} \< q\_{\\max}\$) is: \$\$P\_b \= P\_{\\max} \\cdot \\left(\\frac{\\text{avg} \- q\_{\\min}}{q\_{\\max} \- q\_{\\min}}\\right)\$\$ If ECN is enabled, packets with ECN field `01` or `10` (ECT) are remarked to `11` (CE) without dropping, allowing the TCP sender to halve its congestion window (\$cwnd\$) without triggering RTO retransmission timeout latency.

---

## 3\. Zero-Trust QoS Security Architecture

1. **Trust Boundary Ingress Enforcement**: Default switchports must treat all connected access devices as untrusted, resetting or re-marking incoming DSCP/CoS to CS0/0 to prevent malicious prioritization.  
2. **Strict Priority (LLQ) Policer Ceiling**: Low-Latency Queuing must always be paired with an ingress/egress policer (capped at \$\\le 33%\$ of link bandwidth) to eliminate control-plane routing starvation.  
3. **Control-Plane Bandwidth Reservation**: BGP (TCP 179), OSPF (Protocol 89), and BFD (UDP 3784\) must be mapped to DSCP CS6/CS7 with guaranteed non-congested bandwidth.  
4. **Scavenger Class Throttling**: Bulk file transfers and background P2P must be assigned DSCP CS1 with aggressive WRED drop curves.  
5. **Path MTU & MSS Clamping**: WAN/VPN interfaces must clamp TCP MSS to 1360 bytes to prevent fragmentation within QoS queues.