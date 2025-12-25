import sys
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("[WARNING] pandas is not installed. Install with: pip install pandas")

import config


def aggregate_flows(packets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    if not packets:
        print("[WARNING] No packets to aggregate")
        return {}
    
    flows = defaultdict(list)
    
    for packet in packets:
        src_ip = packet.get('src_ip')
        if src_ip:
            flows[src_ip].append(packet)
    
    print(f"[INFO] Aggregated {len(packets)} packets into {len(flows)} flows")
    return dict(flows)


def compute_flow_features(
    src_ip: str, 
    packets: List[Dict[str, Any]]
) -> Dict[str, Any]:
    if not packets:
        return None
    
    total_bytes = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    syn_count = 0
    
    dst_ports = set()
    dst_ips = set()
    
    timestamps = []
    
    for pkt in packets:
        total_bytes += pkt.get('size', 0)
        
        protocol = pkt.get('protocol', '')
        if protocol == 'TCP':
            tcp_count += 1
            if 'S' in pkt.get('flags', ''):
                syn_count += 1
        elif protocol == 'UDP':
            udp_count += 1
        elif protocol == 'ICMP':
            icmp_count += 1
        
        dst_port = pkt.get('dst_port', 0)
        if dst_port > 0:
            dst_ports.add(dst_port)
        
        dst_ip = pkt.get('dst_ip')
        if dst_ip:
            dst_ips.add(dst_ip)
        
        ts = pkt.get('timestamp')
        if ts:
            timestamps.append(ts)
    
    packet_count = len(packets)
    
    flow_duration = 0.0
    if len(timestamps) >= 2:
        timestamps.sort()
        duration = timestamps[-1] - timestamps[0]
        if isinstance(duration, timedelta):
            flow_duration = duration.total_seconds()
        else:
            flow_duration = float(duration)
    
    if flow_duration < 0.001:
        flow_duration = 0.001
    
    tcp_ratio = tcp_count / packet_count if packet_count > 0 else 0
    udp_ratio = udp_count / packet_count if packet_count > 0 else 0
    icmp_ratio = icmp_count / packet_count if packet_count > 0 else 0
    
    avg_packet_size = total_bytes / packet_count if packet_count > 0 else 0
    
    packets_per_second = packet_count / flow_duration
    
    max_dst_port = max(dst_ports) if dst_ports else 0
    min_dst_port = min(dst_ports) if dst_ports else 0
    
    features = {
        'src_ip': src_ip,
        'packet_count': packet_count,
        'byte_volume': total_bytes,
        'flow_duration': round(flow_duration, 3),
        'packets_per_second': round(packets_per_second, 2),
        'unique_dst_ports': len(dst_ports),
        'unique_dst_ips': len(dst_ips),
        'tcp_ratio': round(tcp_ratio, 3),
        'udp_ratio': round(udp_ratio, 3),
        'icmp_ratio': round(icmp_ratio, 3),
        'avg_packet_size': round(avg_packet_size, 2),
        'syn_count': syn_count,
        'max_dst_port': max_dst_port,
        'min_dst_port': min_dst_port,
        'first_seen': min(timestamps) if timestamps else None,
        'last_seen': max(timestamps) if timestamps else None
    }
    
    return features


def create_feature_dataframe(
    packets: List[Dict[str, Any]],
    min_packets: int = None
) -> 'pd.DataFrame':
    if not PANDAS_AVAILABLE:
        print("[ERROR] pandas is required for feature extraction")
        print("[INFO] Install with: pip install pandas")
        return None
    
    min_packets = min_packets or config.MIN_PACKETS_PER_FLOW
    
    flows = aggregate_flows(packets)
    
    if not flows:
        print("[WARNING] No flows to analyze")
        return pd.DataFrame()
    
    feature_list = []
    skipped = 0
    
    for src_ip, flow_packets in flows.items():
        if len(flow_packets) < min_packets:
            skipped += 1
            continue
        
        features = compute_flow_features(src_ip, flow_packets)
        if features:
            feature_list.append(features)
    
    if skipped > 0:
        print(f"[INFO] Skipped {skipped} flows with < {min_packets} packets")
    
    df = pd.DataFrame(feature_list)
    
    print(f"[INFO] Created feature DataFrame with {len(df)} flows")
    print(f"[INFO] Features: {list(df.columns)}")
    
    return df


def get_feature_columns() -> List[str]:
    return [
        'packet_count',
        'byte_volume',
        'flow_duration',
        'unique_dst_ports',
        'unique_dst_ips',
        'tcp_ratio',
        'udp_ratio',
        'icmp_ratio',
        'avg_packet_size',
        'packets_per_second',
        'syn_count'
    ]


def normalize_features(df: 'pd.DataFrame') -> 'pd.DataFrame':
    if not PANDAS_AVAILABLE:
        return df
    
    feature_cols = get_feature_columns()
    df_normalized = df.copy()
    
    for col in feature_cols:
        if col in df.columns:
            min_val = df[col].min()
            max_val = df[col].max()
            
            if max_val - min_val > 0:
                df_normalized[col] = (df[col] - min_val) / (max_val - min_val)
            else:
                df_normalized[col] = 0.0
    
    return df_normalized


def print_flow_summary(df: 'pd.DataFrame') -> None:
    if df is None or df.empty:
        print("[INFO] No flows to summarize")
        return
    
    print("\n" + "=" * 60)
    print("FLOW FEATURE SUMMARY")
    print("=" * 60)
    
    print(f"\nTotal Flows Analyzed: {len(df)}")
    
    print(f"\nPacket Volume:")
    print(f"  Total Packets: {df['packet_count'].sum():,}")
    print(f"  Total Bytes: {df['byte_volume'].sum():,}")
    print(f"  Avg Packets/Flow: {df['packet_count'].mean():.1f}")
    
    print(f"\nDestination Diversity:")
    print(f"  Max Unique Ports (single flow): {df['unique_dst_ports'].max()}")
    print(f"  Max Unique IPs (single flow): {df['unique_dst_ips'].max()}")
    
    print(f"\nProtocol Distribution (avg ratios):")
    print(f"  TCP: {df['tcp_ratio'].mean()*100:.1f}%")
    print(f"  UDP: {df['udp_ratio'].mean()*100:.1f}%")
    print(f"  ICMP: {df['icmp_ratio'].mean()*100:.1f}%")
    
    print(f"\nTraffic Rate:")
    print(f"  Max Packets/Second: {df['packets_per_second'].max():.1f}")
    print(f"  Avg Packets/Second: {df['packets_per_second'].mean():.1f}")
    
    print("=" * 60 + "\n")


if __name__ == "__main__":
    print("=" * 60)
    print("Feature Extraction Module Test")
    print("=" * 60)
    
    from capture.capture_packets import generate_sample_packets
    
    sample_packets = generate_sample_packets(50)
    
    df = create_feature_dataframe(sample_packets)
    
    if df is not None and not df.empty:
        print_flow_summary(df)
        
        print("\nSample Flow Features:")
        print(df[['src_ip', 'packet_count', 'unique_dst_ports', 
                  'tcp_ratio', 'packets_per_second']].head())
    
    print("\n[INFO] Feature extraction module loaded successfully")
