# Network Traffic Anomaly Detector

A Python-based **Network Traffic Anomaly Detection** system designed for Blue Team / SOC operations. This tool simulates an anomaly-based Intrusion Detection System (IDS) by capturing network traffic, extracting security-relevant features, learning normal traffic behavior, and detecting anomalous or suspicious activity.


## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [How It Works](#how-it-works)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Example Alerts](#example-alerts)
- [Security Use Cases](#security-use-cases)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Contributing](#contributing)

---

## Overview

This Network Traffic Anomaly Detector is designed to:

1. **Capture Traffic** - Live capture from network interfaces or offline analysis of PCAP files
2. **Extract Features** - Aggregate packets into flows and compute security-relevant metrics
3. **Learn Behavior** - Train on normal traffic to establish a baseline
4. **Detect Anomalies** - Identify traffic patterns that deviate from the norm
5. **Generate Alerts** - Produce SOC-style alerts with severity classification

The system uses **machine learning** (Isolation Forest algorithm) for unsupervised anomaly detection, meaning it doesn't require labeled attack data to function.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Network Traffic Anomaly Detector                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐       │
│   │   CAPTURE    │     │   FEATURES   │     │    MODEL     │       │
│   │   MODULE     │────▶│   MODULE     │────▶│   MODULE     │       │
│   │              │     │              │     │              │       │
│   │ • Live Cap   │     │ • Flow Agg   │     │ • Isolation  │       │
│   │ • PCAP Read  │     │ • Feature    │     │   Forest     │       │
│   │ • Parsing    │     │   Extraction │     │ • Scoring    │       │
│   └──────────────┘     └──────────────┘     └──────────────┘       │
│          │                                          │               │
│          │         ┌────────────────────┐           │               │
│          │         │      CONFIG        │           │               │
│          └────────▶│   Thresholds &     │◀──────────┘               │
│                    │   Parameters       │                           │
│                    └────────────────────┘                           │
│                              │                                      │
│                              ▼                                      │
│                    ┌────────────────────┐                           │
│                    │      ALERTS        │                           │
│                    │  • Console (SOC)   │                           │
│                    │  • Log File        │                           │
│                    │  • JSON Export     │                           │
│                    └────────────────────┘                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Input**: Network packets (live capture or PCAP file)
2. **Parsing**: Extract IP, ports, protocol, size, timestamp
3. **Aggregation**: Group packets by source IP into flows
4. **Feature Extraction**: Compute per-flow security metrics
5. **Anomaly Detection**: Score flows using Isolation Forest
6. **Alerting**: Generate SOC-style alerts for anomalies

---

## How It Works

### Anomaly Detection with Isolation Forest

This tool uses the **Isolation Forest** algorithm for unsupervised anomaly detection. Here's how it works:

#### The Concept

Isolation Forest is based on a simple observation: **anomalies are few and different**. This makes them easier to isolate than normal points.

#### The Algorithm

1. **Build Random Trees**: Create multiple decision trees that randomly split data
2. **Measure Isolation**: Count how many splits are needed to isolate each point
3. **Score Anomalies**: Points that isolate quickly (fewer splits) are more anomalous
4. **Classify**: Compare scores to thresholds to flag anomalies

#### Why It's Effective for Network Security

| Advantage | Explanation |
|-----------|-------------|
| **Unsupervised** | Doesn't need labeled attack data |
| **Efficient** | O(n log n) complexity handles large volumes |
| **Explainable** | Intuitive isolation-based reasoning |
| **Adaptive** | Learns from any network environment |

#### Scoring Interpretation

| Score Range | Classification |
|-------------|----------------|
| 0.0 - 0.3 | Normal traffic |
| 0.3 - 0.5 | Slightly unusual |
| 0.5 - 0.7 | Suspicious |
| 0.7 - 0.9 | Highly anomalous |
| 0.9 - 1.0 | Definitely anomalous |

---

## Features

### Traffic Collection
- ✅ Live capture from network interfaces (requires admin/root)
- ✅ Offline analysis of PCAP files
- ✅ Packet parsing (IP, TCP, UDP, ICMP)
- ✅ Timestamp and size extraction

### Feature Engineering
- ✅ Packet count per source IP
- ✅ Byte volume per flow
- ✅ Flow duration
- ✅ Unique destination ports per IP (port scan detection)
- ✅ Unique destination IPs (reconnaissance detection)
- ✅ Protocol distribution ratios (TCP/UDP/ICMP)
- ✅ Packets per second (flood detection)
- ✅ SYN count (SYN flood detection)

### Anomaly Detection
- ✅ Isolation Forest algorithm
- ✅ Training on normal traffic baseline
- ✅ Anomaly scoring (0-1 scale)
- ✅ Binary classification (normal/anomalous)
- ✅ Model persistence (save/load)

### Alerting & Reporting
- ✅ SOC-style console output with colors
- ✅ Severity classification (LOW/MEDIUM/HIGH)
- ✅ Automatic alert reason determination
- ✅ Text log file output
- ✅ JSON export for integration

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Administrator/root privileges (for live capture only)

### Step 1: Clone or Download

```bash
# If using git
git clone <repository-url>
cd network-anomaly-detector

# Or download and extract the ZIP
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on Linux/Mac
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install scapy pandas scikit-learn numpy
```

Or using requirements.txt:

```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
python main.py --help
```

---

## Usage

### Demo Mode (Recommended for First Run)

Run the demo mode to see the tool in action without special permissions:

```bash
python main.py --demo
```

This generates synthetic traffic with embedded anomalies to demonstrate detection capabilities.

### Offline Analysis (PCAP Files)

Analyze a captured network traffic file:

```bash
python main.py --mode offline --pcap /path/to/capture.pcap
```

### Live Capture

Capture and analyze live network traffic (requires admin/root):

```bash
# Windows (Run as Administrator)
python main.py --mode live --interface "Ethernet" --count 1000

# Linux (with sudo)
sudo python main.py --mode live --interface eth0 --count 1000
```

### Train Baseline Model

Train the detector on known-good traffic:

```bash
python main.py --mode offline --pcap normal_traffic.pcap --train
```

### List Available Interfaces

```bash
python main.py --list-interfaces
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--mode` | `live` or `offline` capture mode |
| `--demo` | Run demo with synthetic traffic |
| `--pcap, -p` | Path to PCAP file for offline analysis |
| `--interface, -i` | Network interface for live capture |
| `--count, -c` | Number of packets to capture |
| `--timeout, -t` | Capture timeout in seconds |
| `--filter, -f` | BPF filter (e.g., "tcp port 80") |
| `--train` | Train model on current traffic |
| `--output, -o` | Output format: `text`, `json`, `both` |
| `--list-interfaces` | Show available network interfaces |

---

## Example Alerts

### Console Output

```
╔══════════════════════════════════════════════════════════════╗
║     Network Traffic Anomaly Detector                         ║
║     Blue Team / SOC Security Tool                            ║
╚══════════════════════════════════════════════════════════════╝

============================================================
   SECURITY ALERTS - Network Traffic Anomaly Detector
============================================================

[HIGH] 2025-01-14 22:41:10
Possible Port Scan Detected (contacted 120 unique ports)
Source IP: 10.0.0.100
Unique Ports Contacted: 120
Packets/Second: 250.0
Anomaly Score: 0.95

[HIGH] 2025-01-14 22:41:12
High Data Volume (2.38 MB transferred)
Source IP: 192.168.1.200
Bytes Transferred: 2,500,000
Anomaly Score: 0.88

[MEDIUM] 2025-01-14 22:41:15
Unusual ICMP Activity (90% ICMP packets) | Network Reconnaissance (25 unique destinations)
Source IP: 172.16.0.50
Packets/Second: 200.0
Anomaly Score: 0.72

============================================================
Total Alerts: 3
  HIGH: 2
  MEDIUM: 1
============================================================
```

### JSON Output

```json
{
  "timestamp": "2025-01-14 22:41:10",
  "severity": "HIGH",
  "source_ip": "10.0.0.100",
  "description": "Possible Port Scan Detected (contacted 120 unique ports)",
  "anomaly_score": 0.95,
  "details": {
    "packet_count": 500,
    "byte_volume": 50000,
    "unique_dst_ports": 120,
    "unique_dst_ips": 1,
    "packets_per_second": 250.0
  }
}
```

---



*Built for Blue Team / SOC operations training and education.*

