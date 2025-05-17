from collections import defaultdict
from scapy.all import IP, TCP, UDP

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            sport = packet.sport if hasattr(packet, 'sport') else 0
            dport = packet.dport if hasattr(packet, 'dport') else 0
            proto_num = packet[IP].proto if IP in packet else 0
            proto_name = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "Other")

            flow_key = (ip_src, ip_dst, sport, dport, proto_name)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats, proto_name, proto_num)
        return None

    def extract_features(self, packet, stats, proto_name, proto_num):
        duration = stats['last_time'] - stats['start_time'] if stats['start_time'] and stats['last_time'] else 1e-9
        packet_rate = stats['packet_count'] / duration if duration > 0 else 0
        byte_rate = stats['byte_count'] / duration if duration > 0 else 0
        packet_size = len(packet)
        tcp_flags = packet[TCP].flags if TCP in packet else ""
        window_size = packet[TCP].window if TCP in packet else 0

        return {
            'packet_size': packet_size,
            'flow_duration': duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': tcp_flags,
            'window_size': window_size,
            'protocol_name': proto_name,
            'protocol_number': proto_num,
            'destination_port': packet.dport if hasattr(packet, 'dport') else None
        }

if __name__ == '__main__':
    # Example usage
    from scapy.all import IP, TCP
    analyzer = TrafficAnalyzer()
    packet1 = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(dport=80, flags="S")
    packet1.time = 1.0
    features1 = analyzer.analyze_packet(packet1)
    print(f"[TrafficAnalyzer] Features 1: {features1}")
    packet2 = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(dport=80, flags="A")
    packet2.time = 2.0
    features2 = analyzer.analyze_packet(packet2)
    print(f"[TrafficAnalyzer] Features 2: {features2}")
