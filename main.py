#!/usr/bin/env python3

import sys
import os
import argparse
from datetime import datetime
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from capture.capture_packets import (
    capture_live,
    read_pcap,
    generate_sample_packets,
    get_available_interfaces
)
from features.extract_features import (
    create_feature_dataframe,
    print_flow_summary,
    get_feature_columns
)
from model.anomaly_model import (
    AnomalyDetector,
    generate_alert,
    print_alerts,
    save_alerts
)


def print_banner():
    banner = """
+==============================================================+
|     Network Traffic Anomaly Detector                         |
|     Blue Team / SOC Security Tool                            |
+==============================================================+
|  Modes: live | offline | demo                                |
|  Use --help for usage information                            |
+==============================================================+
    """
    print(banner)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Network Traffic Anomaly Detector - Blue Team / SOC Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run demo mode (synthetic traffic)
    python main.py --demo
    
    # Analyze a PCAP file
    python main.py --mode offline --pcap traffic.pcap
    
    # Live capture from interface
    python main.py --mode live --interface eth0 --count 500
    
    # Train baseline model from normal traffic
    python main.py --mode offline --pcap normal.pcap --train
    
    # List available interfaces
    python main.py --list-interfaces
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['live', 'offline'],
        help='Capture mode: live (real-time) or offline (PCAP file)'
    )
    
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run in demo mode with synthetic traffic (no privileges needed)'
    )
    
    parser.add_argument(
        '--interface', '-i',
        help='Network interface for live capture (e.g., eth0, wlan0)'
    )
    
    parser.add_argument(
        '--count', '-c',
        type=int,
        default=config.DEFAULT_CAPTURE_COUNT,
        help=f'Number of packets to capture (default: {config.DEFAULT_CAPTURE_COUNT})'
    )
    
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=config.DEFAULT_CAPTURE_TIMEOUT,
        help=f'Capture timeout in seconds (default: {config.DEFAULT_CAPTURE_TIMEOUT})'
    )
    
    parser.add_argument(
        '--filter', '-f',
        help='BPF filter for packet capture (e.g., "tcp", "port 80")'
    )
    
    parser.add_argument(
        '--pcap', '-p',
        help='Path to PCAP file for offline analysis'
    )
    
    parser.add_argument(
        '--train',
        action='store_true',
        help='Train the model on current traffic as baseline'
    )
    
    parser.add_argument(
        '--model-path',
        help='Path to save/load the trained model'
    )
    
    parser.add_argument(
        '--output', '-o',
        choices=['text', 'json', 'both'],
        default='both',
        help='Output format for alerts (default: both)'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress informational output, show only alerts'
    )
    
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )
    
    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> bool:
    if args.demo:
        return True
    
    if args.list_interfaces:
        return True
    
    if not args.mode:
        print("[ERROR] Please specify --mode (live/offline) or --demo")
        return False
    
    if args.mode == 'offline' and not args.pcap:
        print("[ERROR] Offline mode requires --pcap argument")
        return False
    
    if args.pcap and not os.path.exists(args.pcap):
        print(f"[ERROR] PCAP file not found: {args.pcap}")
        return False
    
    return True


def run_demo_mode() -> List[Dict[str, Any]]:
    import numpy as np
    import pandas as pd
    
    print("\n[DEMO] Running in demonstration mode")
    print("[DEMO] Generating synthetic network traffic...\n")
    
    print("[DEMO] Step 1: Generating normal baseline traffic...")
    normal_packets = generate_sample_packets(config.DEMO_NORMAL_FLOWS * 10)
    normal_df = create_feature_dataframe(normal_packets, min_packets=1)
    
    print("\n[DEMO] Step 2: Training anomaly detection model...")
    detector = AnomalyDetector()
    detector.fit(normal_df)
    
    print("\n[DEMO] Step 3: Generating test traffic with anomalies...")
    
    np.random.seed(int(datetime.now().timestamp()) % 10000)
    
    test_packets = generate_sample_packets(50)
    test_df = create_feature_dataframe(test_packets, min_packets=1)
    
    anomaly_patterns = [
        {
            'src_ip': '10.0.0.100',
            'packet_count': 500,
            'byte_volume': 50000,
            'flow_duration': 2.0,
            'unique_dst_ports': 120,
            'unique_dst_ips': 1,
            'tcp_ratio': 0.95,
            'udp_ratio': 0.05,
            'icmp_ratio': 0.0,
            'avg_packet_size': 100,
            'packets_per_second': 250,
            'syn_count': 490,
            'first_seen': datetime.now(),
            'last_seen': datetime.now()
        },
        {
            'src_ip': '192.168.1.200',
            'packet_count': 200,
            'byte_volume': 2500000,
            'flow_duration': 30.0,
            'unique_dst_ports': 1,
            'unique_dst_ips': 1,
            'tcp_ratio': 1.0,
            'udp_ratio': 0.0,
            'icmp_ratio': 0.0,
            'avg_packet_size': 12500,
            'packets_per_second': 6.67,
            'syn_count': 1,
            'first_seen': datetime.now(),
            'last_seen': datetime.now()
        },
        {
            'src_ip': '172.16.0.50',
            'packet_count': 1000,
            'byte_volume': 64000,
            'flow_duration': 5.0,
            'unique_dst_ports': 3,
            'unique_dst_ips': 25,
            'tcp_ratio': 0.1,
            'udp_ratio': 0.0,
            'icmp_ratio': 0.9,
            'avg_packet_size': 64,
            'packets_per_second': 200,
            'syn_count': 0,
            'first_seen': datetime.now(),
            'last_seen': datetime.now()
        }
    ]
    
    anomaly_df = pd.DataFrame(anomaly_patterns)
    
    for col in anomaly_df.columns:
        if col not in test_df.columns:
            test_df[col] = None
    
    test_df = pd.concat([test_df, anomaly_df], ignore_index=True)
    
    print("\n[DEMO] Step 4: Analyzing traffic patterns...")
    print_flow_summary(test_df)
    
    print("[DEMO] Step 5: Running anomaly detection...")
    scores, predictions = detector.predict(test_df)
    
    alerts = []
    for idx in range(len(test_df)):
        if predictions[idx] == -1:
            features = test_df.iloc[idx].to_dict()
            alert = generate_alert(features, scores[idx])
            alerts.append(alert)
    
    return alerts


def run_offline_mode(
    pcap_path: str,
    train: bool = False,
    model_path: str = None
) -> List[Dict[str, Any]]:
    print(f"\n[INFO] Running offline analysis on: {pcap_path}")
    
    packets = read_pcap(pcap_path)
    
    if not packets:
        print("[ERROR] No packets read from PCAP file")
        return []
    
    df = create_feature_dataframe(packets)
    
    if df.empty:
        print("[ERROR] No flows extracted from traffic")
        return []
    
    print_flow_summary(df)
    
    detector = AnomalyDetector()
    
    if train:
        print("[INFO] Training model on current traffic as baseline...")
        detector.fit(df)
        if config.AUTO_SAVE_MODEL:
            detector.save_model(model_path)
        print("[INFO] Model trained. Future traffic will be compared to this baseline.")
        return []
    else:
        model_file = model_path or config.MODEL_SAVE_PATH
        if os.path.exists(model_file):
            print(f"[INFO] Loading trained model from {model_file}")
            detector.load_model(model_file)
        else:
            print("[WARNING] No trained model found. Using current traffic as baseline.")
            print("[INFO] For better detection, train on known-good traffic first.")
            detector.fit(df)
    
    scores, predictions = detector.predict(df)
    
    alerts = []
    for idx in range(len(df)):
        if predictions[idx] == -1:
            features = df.iloc[idx].to_dict()
            alert = generate_alert(features, scores[idx])
            alerts.append(alert)
    
    return alerts


def run_live_mode(
    interface: str = None,
    count: int = None,
    timeout: int = None,
    bpf_filter: str = None,
    train: bool = False,
    model_path: str = None
) -> List[Dict[str, Any]]:
    print(f"\n[INFO] Running live capture mode")
    print("[INFO] This requires administrator/root privileges")
    
    packets = capture_live(
        interface=interface,
        count=count,
        timeout=timeout,
        bpf_filter=bpf_filter
    )
    
    if not packets:
        print("[ERROR] No packets captured")
        return []
    
    df = create_feature_dataframe(packets)
    
    if df.empty:
        print("[ERROR] No flows extracted from captured traffic")
        return []
    
    print_flow_summary(df)
    
    detector = AnomalyDetector()
    
    if train:
        print("[INFO] Training model on captured traffic as baseline...")
        detector.fit(df)
        if config.AUTO_SAVE_MODEL:
            detector.save_model(model_path)
        print("[INFO] Model trained and saved.")
        return []
    else:
        model_file = model_path or config.MODEL_SAVE_PATH
        if os.path.exists(model_file):
            detector.load_model(model_file)
        else:
            print("[WARNING] No trained model. Using captured traffic as baseline.")
            detector.fit(df)
    
    scores, predictions = detector.predict(df)
    
    alerts = []
    for idx in range(len(df)):
        if predictions[idx] == -1:
            features = df.iloc[idx].to_dict()
            alert = generate_alert(features, scores[idx])
            alerts.append(alert)
    
    return alerts


def main():
    print_banner()
    
    args = parse_arguments()
    
    if args.list_interfaces:
        print("\n[INFO] Available network interfaces:")
        interfaces = get_available_interfaces()
        if interfaces:
            for iface in interfaces:
                print(f"  - {iface}")
        else:
            print("  No interfaces found (Scapy may not be installed)")
        return 0
    
    if not validate_arguments(args):
        print("\nUse --help for usage information")
        return 1
    
    alerts = []
    
    try:
        if args.demo:
            alerts = run_demo_mode()
        
        elif args.mode == 'offline':
            alerts = run_offline_mode(
                pcap_path=args.pcap,
                train=args.train,
                model_path=args.model_path
            )
        
        elif args.mode == 'live':
            alerts = run_live_mode(
                interface=args.interface,
                count=args.count,
                timeout=args.timeout,
                bpf_filter=args.filter,
                train=args.train,
                model_path=args.model_path
            )
        
        print_alerts(alerts)
        
        if alerts:
            save_alerts(alerts, format=args.output)
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n[INFO] Interrupted by user")
        return 130
        
    except Exception as e:
        print(f"\n[ERROR] An error occurred: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
