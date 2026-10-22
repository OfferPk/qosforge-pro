/**
 * QoSForge Pro (v1.0.0) - QoS & DiffServ Protocol Engine
 * Standards: IETF RFC 2474, RFC 2597, RFC 3246, RFC 2697, RFC 2698, RFC 3168
 */

const QoSProtocolEngine = (() => {
  const DSCP_TABLE = {
    0: { name: "CS0 / Default", class: "Best Effort", desc: "Standard unclassified traffic (FIFO default)" },
    8: { name: "CS1 / Scavenger", class: "Scavenger", desc: "Background file transfers, torrents, low priority" },
    10: { name: "AF11", class: "Assured Forwarding 1", desc: "Class 1, Low Drop Probability" },
    12: { name: "AF12", class: "Assured Forwarding 1", desc: "Class 1, Medium Drop Probability" },
    14: { name: "AF13", class: "Assured Forwarding 1", desc: "Class 1, High Drop Probability" },
    16: { name: "CS2", class: "Class Selector 2", desc: "OAM / Network Operations & Management" },
    18: { name: "AF21", class: "Assured Forwarding 2", desc: "Class 2, Low Drop Probability (Transactional Data)" },
    20: { name: "AF22", class: "Assured Forwarding 2", desc: "Class 2, Medium Drop Probability" },
    22: { name: "AF23", class: "Assured Forwarding 2", desc: "Class 2, High Drop Probability" },
    24: { name: "CS3", class: "Class Selector 3", desc: "Call Signaling (SIP, H.323, SCCP)" },
    26: { name: "AF31", class: "Assured Forwarding 3", desc: "Class 3, Low Drop Probability (Mission Critical Apps)" },
    28: { name: "AF32", class: "Assured Forwarding 3", desc: "Class 3, Medium Drop Probability" },
    30: { name: "AF33", class: "Assured Forwarding 3", desc: "Class 3, High Drop Probability" },
    32: { name: "CS4", class: "Class Selector 4", desc: "Streaming Video / Surveillance" },
    34: { name: "AF41", class: "Assured Forwarding 4", desc: "Class 4, Low Drop Probability (Interactive Video / Zoom / Teams)" },
    36: { name: "AF42", class: "Assured Forwarding 4", desc: "Class 4, Medium Drop Probability (Interactive Video)" },
    38: { name: "AF43", class: "Assured Forwarding 4", desc: "Class 4, High Drop Probability" },
    40: { name: "CS5", class: "Class Selector 5", desc: "Broadcast Video" },
    44: { name: "VA / Voice-Admit", class: "Voice Admit", desc: "RFC 5865 Admitted VoIP Audio" },
    46: { name: "EF / Expedited Forwarding", class: "Expedited Forwarding", desc: "RFC 3246 Low Delay, Low Jitter VoIP Audio" },
    48: { name: "CS6", class: "Class Selector 6", desc: "IP Routing Control (OSPF, BGP, EIGRP, BFD)" },
    56: { name: "CS7", class: "Class Selector 7", desc: "Link-layer Control / Critical Network Infrastructure" }
  };

  const ECN_TABLE = {
    0: { name: "Not-ECT (00)", desc: "Not ECN-Capable Transport (RFC 3168)" },
    1: { name: "ECT(1) (01)", desc: "ECN-Capable Transport (Nonce sum or experimental)" },
    2: { name: "ECT(0) (10)", desc: "ECN-Capable Transport (Standard TCP/IP endpoints)" },
    3: { name: "CE (11)", desc: "Congestion Encountered (Router experienced congestion; endpoint must back off)" }
  };

  // CRC32 Lookup Table for Ethernet FCS
  const CRC32_TABLE = (() => {
    let c;
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      c = n;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c >>> 0;
    }
    return table;
  })();

  function computeCRC32(bytes) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) {
      crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ bytes[i]) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function computeIPChecksum(bytes) {
    let sum = 0;
    const len = bytes.length;
    for (let i = 0; i < len; i += 2) {
      const b1 = bytes[i];
      const b2 = (i + 1 < len) ? bytes[i + 1] : 0;
      sum += (b1 << 8) | b2;
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (~sum) & 0xFFFF;
  }

  function dissectToS(tosInt) {
    const tos = tosInt & 0xFF;
    const dscp = (tos >> 2) & 0x3F;
    const ecn = tos & 0x03;
    const ipprec = (dscp >> 3) & 0x07;
    const cos = ipprec;

    const dscpInfo = DSCP_TABLE[dscp] || {
      name: `DSCP ${dscp} (Custom)`,
      class: "Custom",
      desc: "Standard unassigned or custom local DiffServ marking"
    };

    const ecnInfo = ECN_TABLE[ecn] || {
      name: `ECN ${ecn}`,
      desc: "Unknown ECN status"
    };

    return {
      raw_tos_hex: "0x" + tos.toString(16).toUpperCase().padStart(2, "0"),
      raw_tos_bin: tos.toString(2).padStart(8, "0"),
      dscp_decimal: dscp,
      dscp_binary: dscp.toString(2).padStart(6, "0"),
      dscp_name: dscpInfo.name,
      dscp_class: dscpInfo.class,
      dscp_desc: dscpInfo.desc,
      ecn_decimal: ecn,
      ecn_binary: ecn.toString(2).padStart(2, "0"),
      ecn_name: ecnInfo.name,
      ecn_desc: ecnInfo.desc,
      ip_precedence: ipprec,
      cos_8021p: cos
    };
  }

  function calculateTokenBucket(cirKbps, bcBytes = null, beBytes = null, lineRateMbps = 1000) {
    const cirBps = cirKbps * 1000;
    const cirBpsBytes = cirBps / 8.0;

    const recBcBytes = Math.max(2250, Math.floor((cirBps / 8.0) * 0.025));
    const finalBc = (!bcBytes || bcBytes <= 0) ? recBcBytes : bcBytes;

    const recBeBytes = Math.max(finalBc, finalBc * 2);
    const finalBe = (!beBytes || beBytes < 0) ? recBeBytes : beBytes;

    const tcMs = (cirBps > 0) ? ((finalBc * 8.0) / cirBps) * 1000.0 : 0.0;
    const bufferDrainTimeMs = (finalBc * 8.0 / (lineRateMbps * 1000000.0)) * 1000.0;

    return {
      cir_kbps: cirKbps,
      cir_bps: cirBps,
      cir_Bps: cirBpsBytes,
      bc_bytes: finalBc,
      rec_bc_bytes: recBcBytes,
      be_bytes: finalBe,
      rec_be_bytes: recBeBytes,
      tc_ms: Math.round(tcMs * 100) / 100,
      buffer_drain_time_ms: Math.round(bufferDrainTimeMs * 10000) / 10000
    };
  }

  function simulatePolicer(cirKbps, bcBytes, beBytes, packetSizes, arrivalIntervalsMs) {
    const cirBps = (cirKbps * 1000.0) / 8.0;
    let tc = parseFloat(bcBytes);
    let te = parseFloat(beBytes);

    const results = [];
    let currentTimeMs = 0.0;

    for (let i = 0; i < packetSizes.length; i++) {
      const pktSize = packetSizes[i];
      const intervalMs = arrivalIntervalsMs[i] || 0.0;
      currentTimeMs += intervalMs;

      // Refill
      const tokensAdded = (intervalMs / 1000.0) * cirBps;
      tc += tokensAdded;
      if (tc > bcBytes) {
        const overflow = tc - bcBytes;
        tc = parseFloat(bcBytes);
        te += overflow;
        if (te > beBytes) {
          te = parseFloat(beBytes);
        }
      }

      let color, action;
      if (tc >= pktSize) {
        color = "GREEN (Conform)";
        tc -= pktSize;
        action = "Transmit unaltered";
      } else if (te >= pktSize) {
        color = "YELLOW (Exceed)";
        te -= pktSize;
        action = "Re-mark / Transmit (Exceed)";
      } else {
        color = "RED (Violate)";
        action = "Drop packet";
      }

      results.push({
        packet_id: i + 1,
        arrival_time_ms: Math.round(currentTimeMs * 100) / 100,
        size_bytes: pktSize,
        tc_remaining: Math.round(tc * 10) / 10,
        te_remaining: Math.round(te * 10) / 10,
        color: color,
        action: action
      });
    }

    return results;
  }

  function calculateWred(minTh, maxTh, maxProbPct = 10.0, currentAvg = 50) {
    let finalMaxTh = maxTh;
    if (minTh >= maxTh) {
      finalMaxTh = minTh + 20;
    }

    let dropProb = 0.0;
    let status = "";

    if (currentAvg < minTh) {
      dropProb = 0.0;
      status = "No Drop (Green Zone)";
    } else if (currentAvg >= finalMaxTh) {
      dropProb = 100.0;
      status = "Tail Drop / 100% Drop (Red Zone)";
    } else {
      const fraction = (currentAvg - minTh) / (finalMaxTh - minTh);
      dropProb = fraction * maxProbPct;
      status = `Early Random Drop (${Math.round(dropProb * 100) / 100}% prob) or ECN Mark CE`;
    }

    return {
      min_th_pkts: minTh,
      max_th_pkts: finalMaxTh,
      max_prob_pct: maxProbPct,
      current_avg_pkts: currentAvg,
      calculated_drop_prob_pct: Math.round(dropProb * 100) / 100,
      status: status
    };
  }

  function forgeQoSPacket(dscp = 46, ecn = 3, srcIp = "192.168.1.10", dstIp = "10.0.0.1", srcMac = "00:1a:2b:3c:4d:5e", dstMac = "00:aa:bb:cc:dd:ee") {
    const parseMac = (mac) => mac.replace(/[^0-9A-Fa-f]/g, "").match(/.{2}/g).map(x => parseInt(x, 16));
    const parseIp = (ip) => ip.split(".").map(x => parseInt(x, 10));

    const smacBytes = parseMac(srcMac);
    const dmacBytes = parseMac(dstMac);
    const sipBytes = parseIp(srcIp);
    const dipBytes = parseIp(dstIp);

    const tosByte = ((dscp & 0x3F) << 2) | (ecn & 0x03);

    // IPv4 Header (20 bytes)
    const ipHeader = new Uint8Array(20);
    ipHeader[0] = 0x45; // Version 4, IHL 5
    ipHeader[1] = tosByte;
    ipHeader[2] = 0x00; ipHeader[3] = 0x28; // Total Length: 40 bytes (20 IP + 20 TCP)
    ipHeader[4] = 0x5a; ipHeader[5] = 0x2b; // Identification
    ipHeader[6] = 0x40; ipHeader[7] = 0x00; // Flags: Don't Fragment (DF=1)
    ipHeader[8] = 64;   // TTL
    ipHeader[9] = 6;    // Protocol: TCP
    ipHeader[10] = 0x00; ipHeader[11] = 0x00; // Checksum placeholder
    ipHeader.set(sipBytes, 12);
    ipHeader.set(dipBytes, 16);

    const ipChk = computeIPChecksum(ipHeader);
    ipHeader[10] = (ipChk >> 8) & 0xFF;
    ipHeader[11] = ipChk & 0xFF;

    // TCP Header (20 bytes)
    const tcpHeader = new Uint8Array(20);
    tcpHeader[0] = 0x13; tcpHeader[1] = 0xc4; // Src Port: 5060 (SIP / VoIP)
    tcpHeader[2] = 0x13; tcpHeader[3] = 0xc4; // Dst Port: 5060
    tcpHeader[4] = 0x10; tcpHeader[5] = 0x00; tcpHeader[6] = 0x00; tcpHeader[7] = 0x01; // Seq
    tcpHeader[8] = 0; tcpHeader[9] = 0; tcpHeader[10] = 0; tcpHeader[11] = 0; // Ack
    tcpHeader[12] = 0x50; // Data Offset 5 (20 bytes)
    tcpHeader[13] = 0x02; // SYN Flag
    tcpHeader[14] = 0xfa; tcpHeader[15] = 0xf0; // Window Size (64240)
    tcpHeader[16] = 0x00; tcpHeader[17] = 0x00; // Checksum placeholder
    tcpHeader[18] = 0x00; tcpHeader[19] = 0x00; // Urgent Pointer

    // Ethernet II Header (14 bytes)
    const ethHeader = new Uint8Array(14);
    ethHeader.set(dmacBytes, 0);
    ethHeader.set(smacBytes, 6);
    ethHeader[12] = 0x08; ethHeader[13] = 0x00; // EtherType: IPv4

    // Assemble payload
    let rawFrame = new Uint8Array(14 + 20 + 20);
    rawFrame.set(ethHeader, 0);
    rawFrame.set(ipHeader, 14);
    rawFrame.set(tcpHeader, 34);

    // Minimum Ethernet frame payload is 46 bytes (total frame 60 bytes without FCS)
    if (rawFrame.length < 60) {
      const padded = new Uint8Array(60);
      padded.set(rawFrame, 0);
      rawFrame = padded;
    }

    // Append 4-byte CRC32 FCS
    const fcs = computeCRC32(rawFrame);
    const wireFrame = new Uint8Array(rawFrame.length + 4);
    wireFrame.set(rawFrame, 0);
    wireFrame[rawFrame.length] = fcs & 0xFF;
    wireFrame[rawFrame.length + 1] = (fcs >> 8) & 0xFF;
    wireFrame[rawFrame.length + 2] = (fcs >> 16) & 0xFF;
    wireFrame[rawFrame.length + 3] = (fcs >> 24) & 0xFF;

    return wireFrame;
  }

  function buildPcap(packetsArray) {
    // 24-byte PCAP Global Header
    const globalHdr = new Uint8Array(24);
    const view = new DataView(globalHdr.buffer);
    view.setUint32(0, 0xa1b2c3d4, true); // Magic Number
    view.setUint16(4, 2, true);          // Major Version 2
    view.setUint16(6, 4, true);          // Minor Version 4
    view.setInt32(8, 0, true);           // ThisZone
    view.setUint32(12, 0, true);         // SigFigs
    view.setUint32(16, 65535, true);     // SnapLen
    view.setUint32(20, 1, true);         // Network: Ethernet (1)

    const now = Date.now();
    const tsSec = Math.floor(now / 1000);
    const tsUsec = (now % 1000) * 1000;

    let totalLen = 24;
    for (const pkt of packetsArray) {
      const capLen = pkt.length > 4 ? pkt.length - 4 : pkt.length;
      totalLen += 16 + capLen;
    }

    const pcapBytes = new Uint8Array(totalLen);
    pcapBytes.set(globalHdr, 0);
    let offset = 24;

    for (const pkt of packetsArray) {
      const wireLen = pkt.length;
      const capLen = wireLen > 4 ? wireLen - 4 : wireLen;
      const pktHdr = new Uint8Array(16);
      const pktView = new DataView(pktHdr.buffer);
      pktView.setUint32(0, tsSec, true);
      pktView.setUint32(4, tsUsec, true);
      pktView.setUint32(8, capLen, true);
      pktView.setUint32(12, wireLen, true);

      pcapBytes.set(pktHdr, offset);
      offset += 16;
      pcapBytes.set(pkt.subarray(0, capLen), offset);
      offset += capLen;
    }

    return pcapBytes;
  }

  function formatHexDump(uint8Arr) {
    const lines = [];
    for (let i = 0; i < uint8Arr.length; i += 16) {
      const chunk = uint8Arr.subarray(i, Math.min(i + 16, uint8Arr.length));
      let hexPart = "";
      let asciiPart = "";
      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          hexPart += chunk[j].toString(16).padStart(2, "0") + " ";
          const byte = chunk[j];
          asciiPart += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : ".";
        } else {
          hexPart += "   ";
        }
      }
      lines.push(`${i.toString(16).padStart(4, "0")}   ${hexPart} |${asciiPart}|`);
    }
    return lines.join("\n");
  }

  return {
    DSCP_TABLE,
    ECN_TABLE,
    dissectToS,
    calculateTokenBucket,
    simulatePolicer,
    calculateWred,
    forgeQoSPacket,
    buildPcap,
    formatHexDump
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = QoSProtocolEngine;
}
