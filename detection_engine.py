from sklearn.ensemble import IsolationForest
import numpy as np
from scapy.all import ARP

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.arp_cache = {} # To track ARP mappings
        self.anomaly_model_trained = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features.get('tcp_flags') == 'S' and
                    features.get('packet_rate', 0) > 10
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features.get('packet_size', 0) < 100 and
                    features.get('packet_rate', 0) > 5
                )
            },
            'udp_flood': {
                'condition': lambda features: (
                    features.get('protocol_number') == 17 and # UDP
                    features.get('packet_rate', 0) > 20
                )
            },
            'null_scan': {
                'condition': lambda features: (
                    features.get('tcp_flags') == '' and # No TCP flags set
                    features.get('packet_size', 0) < 100
                )
            },
            'fin_scan': {
                'condition': lambda features: (
                    features.get('tcp_flags') == 'F' and # FIN flag set
                    features.get('packet_size', 0) < 100
                )
            },
            'xmas_scan': {
                'condition': lambda features: (
                    features.get('tcp_flags') == 'PSH|URG|FIN' and # PSH, URG, FIN flags set
                    features.get('packet_size', 0) < 100
                )
            },
            'potential_brute_force_ssh': {
                'condition': lambda features: (
                    features.get('destination_port') == 22 and
                    features.get('packet_rate', 0) > 3 and # Multiple connection attempts to SSH
                    features.get('tcp_flags') == 'S'
                )
            },
            'potential_dns_tunneling': {
                'condition': lambda features: (
                    features.get('protocol_number') == 17 and # UDP
                    features.get('destination_port') == 53 and
                    features.get('packet_size', 0) > 512 # Unusual size for standard DNS
                )
            },
            'suspicious_small_udp_high_rate': {
                'condition': lambda features: (
                    features.get('protocol_number') == 17 and
                    features.get('packet_size', 0) < 64 and
                    features.get('packet_rate', 0) > 50 # Could be indicative of some control channel
                )
            }
        }

    def process_arp(self, packet):
        if ARP in packet and packet[ARP].op == 1: # ARP Request
            ip_src = packet[ARP].psrc
            mac_src = packet[ARP].hwsrc
            if ip_src in self.arp_cache and self.arp_cache[ip_src] != mac_src:
                return {
                    'type': 'signature',
                    'rule': 'potential_arp_spoofing',
                    'confidence': 0.95,
                    'details': f"Possible ARP spoofing detected: IP {ip_src} has changed MAC from {self.arp_cache[ip_src]} to {mac_src}"
                }
            self.arp_cache[ip_src] = mac_src
        return None

    def detect_threats(self, features, packet=None):
        threats = []

        # Signature-based detection on TCP/UDP
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 0.9
                })

        # Anomaly-based detection
        if self.anomaly_model_trained and all(key in features for key in ['packet_size', 'packet_rate', 'byte_rate', 'protocol_number']):
            feature_vector = np.array([[
                features['packet_size'],
                features['packet_rate'],
                features['byte_rate'],
                features['protocol_number']
            ]])
            anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
            if anomaly_score < -0.5:
                threats.append({
                    'type': 'anomaly',
                    'score': anomaly_score,
                    'confidence': min(0.8, abs(anomaly_score))
                })

        # ARP Spoofing Detection
        if packet and ARP in packet:
            arp_threat = self.process_arp(packet)
            if arp_threat:
                threats.append(arp_threat)

        return threats

    def train_anomaly_detector(self, normal_traffic_data):
        if normal_traffic_data:
            training_array = np.array([[
                data.get('packet_size', 0),
                data.get('packet_rate', 0),
                data.get('byte_rate', 0),
                data.get('protocol_number', 0)
            ] for data in normal_traffic_data if all(key in data for key in ['packet_size', 'packet_rate', 'byte_rate', 'protocol_number'])])
            if training_array.size > 0:
                self.anomaly_detector.fit(training_array)
                self.anomaly_model_trained = True
                print("[DetectionEngine] Anomaly detector trained.")
            else:
                print("[DetectionEngine] No valid training data for anomaly detector.")
        else:
            print("[DetectionEngine] No normal traffic data provided for training.")

if __name__ == '__main__':
    # Example usage
    engine = DetectionEngine()
    features_syn_flood = {'tcp_flags': 'S', 'packet_rate': 15}
    threats = engine.detect_threats(features_syn_flood)
    print(f"[DetectionEngine] Threats for SYN flood: {threats}")
