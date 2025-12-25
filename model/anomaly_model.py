import sys
import os
import json
import pickle
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import pandas as pd
    import numpy as np
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("[WARNING] pandas/numpy not installed")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[WARNING] scikit-learn is not installed. Install with: pip install scikit-learn")

import config


class AnomalyDetector:
    
    def __init__(
        self,
        contamination: float = None,
        random_state: int = None,
        n_estimators: int = 100
    ):
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required. Install with: pip install scikit-learn")
        
        contamination = contamination or config.CONTAMINATION_FACTOR
        random_state = random_state if random_state is not None else config.RANDOM_STATE
        
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            max_samples='auto',
            random_state=random_state,
            n_jobs=-1
        )
        
        self.scaler = StandardScaler()
        
        self.is_fitted = False
        self.feature_columns = self._get_feature_columns()
        
        print(f"[INFO] Initialized AnomalyDetector")
        print(f"[INFO] Contamination: {contamination}, Estimators: {n_estimators}")
    
    def _get_feature_columns(self) -> List[str]:
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
    
    def _prepare_features(
        self, 
        df: 'pd.DataFrame', 
        fit_scaler: bool = False
    ) -> np.ndarray:
        available_cols = [c for c in self.feature_columns if c in df.columns]
        
        if len(available_cols) < len(self.feature_columns):
            missing = set(self.feature_columns) - set(available_cols)
            print(f"[WARNING] Missing features: {missing}")
        
        X = df[available_cols].copy()
        
        X = X.fillna(0)
        
        X = X.replace([np.inf, -np.inf], 0)
        
        if fit_scaler:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def fit(self, df: 'pd.DataFrame') -> 'AnomalyDetector':
        if df is None or df.empty:
            print("[ERROR] Cannot train on empty DataFrame")
            return self
        
        print(f"[INFO] Training anomaly detector on {len(df)} flows...")
        
        X = self._prepare_features(df, fit_scaler=True)
        
        self.model.fit(X)
        self.is_fitted = True
        
        print("[INFO] Training complete!")
        print(f"[INFO] Model can now detect traffic that deviates from this baseline")
        
        return self
    
    def predict(
        self, 
        df: 'pd.DataFrame'
    ) -> Tuple[np.ndarray, np.ndarray]:
        if not self.is_fitted:
            print("[ERROR] Model not trained. Call fit() first.")
            return np.array([]), np.array([])
        
        if df is None or df.empty:
            return np.array([]), np.array([])
        
        X = self._prepare_features(df, fit_scaler=False)
        
        predictions = self.model.predict(X)
        
        raw_scores = self.model.decision_function(X)
        
        scores = self._normalize_scores(raw_scores)
        
        anomaly_count = np.sum(predictions == -1)
        print(f"[INFO] Analyzed {len(df)} flows, found {anomaly_count} anomalies")
        
        return scores, predictions
    
    def _normalize_scores(self, raw_scores: np.ndarray) -> np.ndarray:
        shifted = -raw_scores
        
        min_val = shifted.min()
        max_val = shifted.max()
        
        if max_val - min_val > 0:
            normalized = (shifted - min_val) / (max_val - min_val)
        else:
            normalized = np.zeros_like(shifted)
        
        return normalized
    
    def save_model(self, filepath: str = None) -> bool:
        filepath = filepath or config.MODEL_SAVE_PATH
        
        if not self.is_fitted:
            print("[ERROR] Cannot save untrained model")
            return False
        
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_columns': self.feature_columns
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            print(f"[INFO] Model saved to {filepath}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to save model: {e}")
            return False
    
    def load_model(self, filepath: str = None) -> bool:
        filepath = filepath or config.MODEL_SAVE_PATH
        
        if not os.path.exists(filepath):
            print(f"[ERROR] Model file not found: {filepath}")
            return False
        
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_columns = model_data.get('feature_columns', self._get_feature_columns())
            self.is_fitted = True
            
            print(f"[INFO] Model loaded from {filepath}")
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            return False


def classify_severity(
    score: float, 
    features: Dict[str, Any]
) -> str:
    unique_ports = features.get('unique_dst_ports', 0)
    byte_volume = features.get('byte_volume', 0)
    packets_per_second = features.get('packets_per_second', 0)
    
    if (score > config.ANOMALY_THRESHOLD_HIGH or 
        unique_ports > config.PORT_SCAN_THRESHOLD_HIGH or
        byte_volume > config.HIGH_VOLUME_THRESHOLD or
        packets_per_second > config.HIGH_RATE_THRESHOLD):
        return "HIGH"
    
    if (score > config.ANOMALY_THRESHOLD_MEDIUM or
        unique_ports > config.PORT_SCAN_THRESHOLD_MEDIUM):
        return "MEDIUM"
    
    return "LOW"


def determine_alert_reason(features: Dict[str, Any]) -> str:
    unique_ports = features.get('unique_dst_ports', 0)
    unique_ips = features.get('unique_dst_ips', 0)
    byte_volume = features.get('byte_volume', 0)
    pps = features.get('packets_per_second', 0)
    syn_count = features.get('syn_count', 0)
    icmp_ratio = features.get('icmp_ratio', 0)
    packet_count = features.get('packet_count', 0)
    
    reasons = []
    
    if unique_ports > config.PORT_SCAN_THRESHOLD_HIGH:
        reasons.append(f"Possible Port Scan Detected (contacted {unique_ports} unique ports)")
    elif unique_ports > config.PORT_SCAN_THRESHOLD_MEDIUM:
        reasons.append(f"Suspicious Port Activity ({unique_ports} unique ports)")
    
    if byte_volume > config.HIGH_VOLUME_THRESHOLD:
        mb = byte_volume / (1024 * 1024)
        reasons.append(f"High Data Volume ({mb:.2f} MB transferred)")
    
    if pps > config.HIGH_RATE_THRESHOLD:
        reasons.append(f"High Traffic Rate ({pps:.1f} packets/second)")
    
    if syn_count > 0 and packet_count > 0:
        syn_ratio = syn_count / packet_count
        if syn_ratio > 0.8 and syn_count > 10:
            reasons.append(f"Possible SYN Flood ({syn_count} SYN packets)")
    
    if unique_ips > 10:
        reasons.append(f"Network Reconnaissance ({unique_ips} unique destinations)")
    
    if icmp_ratio > 0.5 and packet_count > 10:
        reasons.append(f"Unusual ICMP Activity ({icmp_ratio*100:.0f}% ICMP packets)")
    
    if not reasons:
        reasons.append("Unusual Traffic Pattern Detected")
    
    return " | ".join(reasons)


def generate_alert(
    features: Dict[str, Any],
    score: float,
    timestamp: datetime = None
) -> Dict[str, Any]:
    timestamp = timestamp or datetime.now()
    severity = classify_severity(score, features)
    reason = determine_alert_reason(features)
    
    alert = {
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'severity': severity,
        'source_ip': features.get('src_ip', 'Unknown'),
        'description': reason,
        'anomaly_score': round(score, 3),
        'details': {
            'packet_count': features.get('packet_count', 0),
            'byte_volume': features.get('byte_volume', 0),
            'unique_dst_ports': features.get('unique_dst_ports', 0),
            'unique_dst_ips': features.get('unique_dst_ips', 0),
            'packets_per_second': features.get('packets_per_second', 0),
            'flow_duration': features.get('flow_duration', 0),
            'tcp_ratio': features.get('tcp_ratio', 0),
            'udp_ratio': features.get('udp_ratio', 0),
            'icmp_ratio': features.get('icmp_ratio', 0)
        },
        'first_seen': str(features.get('first_seen', '')),
        'last_seen': str(features.get('last_seen', ''))
    }
    
    return alert


def format_alert_console(alert: Dict[str, Any]) -> str:
    severity = alert['severity']
    severity_info = config.SEVERITY_LEVELS.get(severity, config.SEVERITY_LEVELS['LOW'])
    
    if config.ENABLE_COLORED_OUTPUT:
        color = severity_info['color']
        reset = config.COLOR_RESET
    else:
        color = ''
        reset = ''
    
    lines = [
        f"\n{color}{severity_info['prefix']} {alert['timestamp']}{reset}",
        f"{alert['description']}",
        f"Source IP: {alert['source_ip']}",
    ]
    
    details = alert['details']
    
    if details['unique_dst_ports'] > 1:
        lines.append(f"Unique Ports Contacted: {details['unique_dst_ports']}")
    
    if details['byte_volume'] > 10000:
        lines.append(f"Bytes Transferred: {details['byte_volume']:,}")
    
    if details['packets_per_second'] > 10:
        lines.append(f"Packets/Second: {details['packets_per_second']:.1f}")
    
    lines.append(f"Anomaly Score: {alert['anomaly_score']:.2f}")
    
    return '\n'.join(lines)


def save_alerts(
    alerts: List[Dict[str, Any]],
    filepath: str = None,
    format: str = 'both'
) -> bool:
    if not alerts:
        print("[INFO] No alerts to save")
        return True
    
    success = True
    
    os.makedirs('reports', exist_ok=True)
    
    if format in ['text', 'both']:
        log_path = filepath or config.ALERTS_LOG_PATH
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                for alert in alerts:
                    f.write(f"\n[{alert['severity']}] {alert['timestamp']}\n")
                    f.write(f"{alert['description']}\n")
                    f.write(f"Source IP: {alert['source_ip']}\n")
                    f.write(f"Anomaly Score: {alert['anomaly_score']}\n")
                    f.write(f"Details: {json.dumps(alert['details'])}\n")
                    f.write("-" * 60 + "\n")
            print(f"[INFO] Alerts appended to {log_path}")
        except Exception as e:
            print(f"[ERROR] Failed to write log file: {e}")
            success = False
    
    if format in ['json', 'both']:
        json_path = config.ALERTS_JSON_PATH
        try:
            existing_alerts = []
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    existing_alerts = json.load(f)
            
            existing_alerts.extend(alerts)
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(existing_alerts, f, indent=2, default=str)
            print(f"[INFO] Alerts saved to {json_path}")
        except Exception as e:
            print(f"[ERROR] Failed to write JSON file: {e}")
            success = False
    
    return success


def print_alerts(alerts: List[Dict[str, Any]]) -> None:
    if not alerts:
        print("\n[INFO] No anomalies detected - all traffic appears normal")
        return
    
    print("\n" + "=" * 60)
    print("   SECURITY ALERTS - Network Traffic Anomaly Detector")
    print("=" * 60)
    
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    sorted_alerts = sorted(alerts, key=lambda x: severity_order.get(x['severity'], 3))
    
    for alert in sorted_alerts:
        print(format_alert_console(alert))
    
    print("\n" + "=" * 60)
    print(f"Total Alerts: {len(alerts)}")
    
    for sev in ['HIGH', 'MEDIUM', 'LOW']:
        count = sum(1 for a in alerts if a['severity'] == sev)
        if count > 0:
            print(f"  {sev}: {count}")
    
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import numpy as np
    
    print("=" * 60)
    print("Anomaly Detection Module Test")
    print("=" * 60)
    
    print("\n[TEST] Creating synthetic training data...")
    np.random.seed(42)
    
    n_normal = 100
    normal_data = {
        'src_ip': [f'192.168.1.{i % 10}' for i in range(n_normal)],
        'packet_count': np.random.normal(50, 10, n_normal).astype(int),
        'byte_volume': np.random.normal(5000, 1000, n_normal),
        'flow_duration': np.random.normal(10, 2, n_normal),
        'unique_dst_ports': np.random.randint(1, 5, n_normal),
        'unique_dst_ips': np.random.randint(1, 3, n_normal),
        'tcp_ratio': np.random.uniform(0.7, 0.9, n_normal),
        'udp_ratio': np.random.uniform(0.1, 0.2, n_normal),
        'icmp_ratio': np.random.uniform(0, 0.1, n_normal),
        'avg_packet_size': np.random.normal(500, 100, n_normal),
        'packets_per_second': np.random.normal(5, 2, n_normal),
        'syn_count': np.random.randint(0, 5, n_normal)
    }
    df_normal = pd.DataFrame(normal_data)
    
    print("[TEST] Creating synthetic anomalies...")
    
    n_anomaly = 5
    anomaly_data = {
        'src_ip': [f'10.0.0.{i}' for i in range(n_anomaly)],
        'packet_count': [500, 200, 100, 300, 150],
        'byte_volume': [500000, 100000, 50000, 2000000, 75000],
        'flow_duration': [5, 1, 2, 10, 3],
        'unique_dst_ports': [100, 50, 30, 5, 80],
        'unique_dst_ips': [20, 10, 5, 50, 15],
        'tcp_ratio': [0.9, 0.95, 0.5, 0.3, 0.8],
        'udp_ratio': [0.05, 0.02, 0.3, 0.6, 0.1],
        'icmp_ratio': [0.05, 0.03, 0.2, 0.1, 0.1],
        'avg_packet_size': [100, 50, 800, 1500, 60],
        'packets_per_second': [100, 200, 50, 150, 50],
        'syn_count': [400, 180, 10, 5, 100]
    }
    df_anomaly = pd.DataFrame(anomaly_data)
    
    print("\n[TEST] Training anomaly detector...")
    detector = AnomalyDetector()
    detector.fit(df_normal)
    
    print("\n[TEST] Running detection on mixed data...")
    df_test = pd.concat([df_normal, df_anomaly], ignore_index=True)
    scores, predictions = detector.predict(df_test)
    
    alerts = []
    for idx in range(len(df_test)):
        if predictions[idx] == -1:
            features = df_test.iloc[idx].to_dict()
            alert = generate_alert(features, scores[idx])
            alerts.append(alert)
    
    print_alerts(alerts)
    
    print("[INFO] Anomaly detection module loaded successfully")
