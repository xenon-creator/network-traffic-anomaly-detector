import sys
import os
from datetime import datetime
from typing import List, Dict, Optional, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from scapy.all import (
        sniff,
        rdpcap,
        IP,
        TCP,
        UDP,
        ICMP,
        Ether,
        conf,
        get_if_list
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy is not installed. Install with: pip install scapy")

import config


def get_available_interfaces() -> List[str]:
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is required for interface listing")
        return []
    
    try:
        interfaces = get_if_list()
        return interfaces
    except Exception as e:
        print(f"[ERROR] Failed to get interfaces: {e}")
        return []


def validate_interface(interface: str) -> bool:
    available = get_available_interfaces()
    if interface not in available:
        print(f"[ERROR] Interface '{interface}' not found.")
        print(f"[INFO] Available interfaces: {', '.join(available)}")
        return False
    return True


def validate_pcap_file(filepath: str) -> bool:
    if not os.path.exists(filepath):
        print(f"[ERROR] PCAP file not found: {filepath}")
        return False
    
    if not os.path.isfile(filepath):
        print(f"[ERROR] Path is not a file: {filepath}")
        return False
    
    valid_extensions = ['.pcap', '.pcapng', '.cap']
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in valid_extensions:
        print(f"[WARNING] Unusual file extension: {ext}")
        print(f"[INFO] Expected extensions: {', '.join(valid_extensions)}")
    
    return True


def parse_packet(packet: Any) -> Optional[Dict[str, Any]]:
    if not packet.haslayer(IP):
        return None
    
    try:
        ip_layer = packet[IP]
        
        packet_data = {
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'src_port': 0,
            'dst_port': 0,
            'protocol': 'UNKNOWN',
            'protocol_num': ip_layer.proto,
            'size': len(packet),
            'timestamp': datetime.fromtimestamp(float(packet.time)),
            'flags': ''
        }
        
        packet_data['protocol'] = config.PROTOCOL_MAP.get(
            ip_layer.proto, 
            f"PROTO_{ip_layer.proto}"
        )
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_data['src_port'] = tcp_layer.sport
            packet_data['dst_port'] = tcp_layer.dport
            packet_data['flags'] = str(tcp_layer.flags)
        
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_data['src_port'] = udp_layer.sport
            packet_data['dst_port'] = udp_layer.dport
        
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            packet_data['flags'] = f"type={icmp_layer.type}"
        
        return packet_data
        
    except Exception as e:
        print(f"[WARNING] Failed to parse packet: {e}")
        return None


def capture_live(
    interface: Optional[str] = None,
    count: int = None,
    timeout: int = None,
    bpf_filter: str = None
) -> List[Dict[str, Any]]:
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is required for live capture")
        print("[INFO] Install with: pip install scapy")
        return []
    
    count = count or config.DEFAULT_CAPTURE_COUNT
    timeout = timeout or config.DEFAULT_CAPTURE_TIMEOUT
    bpf_filter = bpf_filter or config.DEFAULT_BPF_FILTER
    interface = interface or config.DEFAULT_INTERFACE
    
    if interface and not validate_interface(interface):
        return []
    
    print(f"[INFO] Starting live capture...")
    print(f"[INFO] Interface: {interface or 'default'}")
    print(f"[INFO] Max packets: {count}")
    print(f"[INFO] Timeout: {timeout}s")
    if bpf_filter:
        print(f"[INFO] BPF Filter: {bpf_filter}")
    
    try:
        raw_packets = sniff(
            iface=interface,
            count=count,
            timeout=timeout,
            filter=bpf_filter if bpf_filter else None,
            store=True
        )
        
        print(f"[INFO] Captured {len(raw_packets)} raw packets")
        
        parsed_packets = []
        for pkt in raw_packets:
            parsed = parse_packet(pkt)
            if parsed:
                parsed_packets.append(parsed)
        
        print(f"[INFO] Successfully parsed {len(parsed_packets)} IP packets")
        return parsed_packets
        
    except PermissionError:
        print("[ERROR] Permission denied for packet capture")
        print("[INFO] Try running with administrator/root privileges")
        print("[INFO] On Windows: Run as Administrator")
        print("[INFO] On Linux: Use sudo or set CAP_NET_RAW capability")
        return []
        
    except OSError as e:
        print(f"[ERROR] OS error during capture: {e}")
        if "No such device" in str(e):
            print("[INFO] Check that the interface name is correct")
        return []
        
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
        return []


def read_pcap(filepath: str) -> List[Dict[str, Any]]:
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is required for PCAP reading")
        print("[INFO] Install with: pip install scapy")
        return []
    
    if not validate_pcap_file(filepath):
        return []
    
    print(f"[INFO] Reading PCAP file: {filepath}")
    
    try:
        raw_packets = rdpcap(filepath)
        print(f"[INFO] Loaded {len(raw_packets)} raw packets from file")
        
        parsed_packets = []
        parse_errors = 0
        
        for pkt in raw_packets:
            parsed = parse_packet(pkt)
            if parsed:
                parsed_packets.append(parsed)
            else:
                parse_errors += 1
        
        print(f"[INFO] Successfully parsed {len(parsed_packets)} IP packets")
        if parse_errors > 0:
            print(f"[INFO] Skipped {parse_errors} non-IP packets")
        
        return parsed_packets
        
    except Exception as e:
        print(f"[ERROR] Failed to read PCAP file: {e}")
        return []


def generate_sample_packets(count: int = 100) -> List[Dict[str, Any]]:
    import random
    from datetime import timedelta
    
    print(f"[INFO] Generating {count} sample packets for demonstration")
    
    sample_src_ips = [
        '192.168.1.100', '192.168.1.101', '192.168.1.102',
        '10.0.0.50', '10.0.0.51', '172.16.0.10'
    ]
    
    sample_dst_ips = [
        '8.8.8.8', '1.1.1.1', '93.184.216.34',
        '192.168.1.1', '10.0.0.1'
    ]
    
    protocols = ['TCP', 'UDP', 'ICMP']
    protocol_nums = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
    
    common_ports = [80, 443, 22, 53, 8080, 3389, 25, 110, 143]
    
    packets = []
    base_time = datetime.now()
    
    for i in range(count):
        proto = random.choice(protocols)
        
        packet = {
            'src_ip': random.choice(sample_src_ips),
            'dst_ip': random.choice(sample_dst_ips),
            'src_port': random.randint(49152, 65535) if proto != 'ICMP' else 0,
            'dst_port': random.choice(common_ports) if proto != 'ICMP' else 0,
            'protocol': proto,
            'protocol_num': protocol_nums[proto],
            'size': random.randint(64, 1500),
            'timestamp': base_time + timedelta(seconds=i * 0.1),
            'flags': 'S' if proto == 'TCP' else ''
        }
        packets.append(packet)
    
    print(f"[INFO] Generated {len(packets)} sample packets")
    return packets


if __name__ == "__main__":
    print("=" * 60)
    print("Capture Module Test")
    print("=" * 60)
    
    print("\n[TEST] Available network interfaces:")
    interfaces = get_available_interfaces()
    for iface in interfaces:
        print(f"  - {iface}")
    
    print("\n[TEST] Sample packet generation:")
    sample = generate_sample_packets(5)
    for pkt in sample:
        print(f"  {pkt['src_ip']}:{pkt['src_port']} -> "
              f"{pkt['dst_ip']}:{pkt['dst_port']} "
              f"[{pkt['protocol']}] {pkt['size']} bytes")
    
    print("\n[INFO] Capture module loaded successfully")
