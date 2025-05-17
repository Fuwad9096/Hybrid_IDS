from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from scapy.all import IP, ARP
import queue
import threading

# --- Database Configuration ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'your_user',
    'password': 'your_password',
    'database': 'cryptosafedb'
}

# --- Encryption Key ---
from cryptography.fernet import Fernet
ENCRYPTION_KEY = Fernet.generate_key()
print(f"[hybrid_ids.py] Encryption Key: {ENCRYPTION_KEY.decode()}")

class IntrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem(DB_CONFIG)
        self.interface = interface
        self.normal_traffic_data = []
        self.known_hosts = {} # IP: host_id
        self.known_protocols = {} # name: protocol_id

        # Initialize known protocols (we'll fetch from DB later in a real app)
        self._populate_protocols()
        self._populate_severities()
        self._populate_event_types()

    def _populate_protocols(self):
        protocols = self.alert_system.fetch_protocols()
        for proto in protocols:
            self.known_protocols[proto['name']] = proto['id']
        if not self.known_protocols:
            # Default if DB is empty
            self.known_protocols['TCP'] = 1
            self.known_protocols['UDP'] = 2
            self.known_protocols['Other'] = 3

    def _get_protocol_id(self, proto_name, proto_number):
        if proto_name in self.known_protocols:
            return self.known_protocols[proto_name]
        else:
            proto_id = self.alert_system.insert_protocol(proto_name, proto_number)
            self.known_protocols[proto_name] = proto_id
            return proto_id

    def _populate_severities(self):
        self.severity_map = self.alert_system.fetch_severities()
        if not self.severity_map:
            self.severity_map = {
                'low': 1,
                'medium': 2,
                'high': 3,
                'critical': 4
            }
        else:
            self.severity_map = {item['level']: item['id'] for item in self.severity_map}

    def _get_severity_id(self, severity_level):
        return self.severity_map.get(severity_level.lower(), 1) # Default to low

    def _populate_event_types(self):
        self.event_type_map = self.alert_system.fetch_event_types()
        if not self.event_type_map:
            self.event_type_map = {
                'intrusion_detection': 1
            }
        else:
            self.event_type_map = {item['name']: item['id'] for item in self.event_type_map}

    def _get_event_type_id(self, event_name):
        return self.event_type_map.get(event_name, 1) # Default

    async def _get_host_id(self, ip_address, mac_address=None, hostname=None, timestamp=None):
        if ip_address in self.known_hosts:
            return self.known_hosts[ip_address]
        else:
            host_id = await self.alert_system.insert_host(ip_address, mac_address, hostname, timestamp)
            if host_id:
                self.known_hosts[ip_address] = host_id
                return host_id
            else:
                # Fallback if insertion fails
                host = await self.alert_system.fetch_host_by_ip(ip_address)
                if host:
                    self.known_hosts[ip_address] = host['id']
                    return host['id']
                return None

    def collect_normal_traffic(self, count=100):
        print(f"[*] Collecting {count} normal traffic packets for training...")
        capture = PacketCapture()
        capture.start_capture(self.interface)
        collected_count = 0
        while collected_count < count:
            try:
                packet = capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    self.normal_traffic_data.append(features)
                    collected_count += 1
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("[!] Normal traffic collection interrupted.")
                break
        capture.stop()
        print(f"[*] Collected {len(self.normal_traffic_data)} packets for training.")
        self.detection_engine.train_anomaly_detector(self.normal_traffic_data)

    def start(self):
        print(f"[*] Starting IDS on interface {self.interface}")
        self.collect_normal_traffic(count=200)
        self.packet_capture.start_capture(self.interface)

        async def process_packets():
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    features = self.traffic_analyzer.analyze_packet(packet)
                    threats = []
                    if features:
                        threats.extend(self.detection_engine.detect_threats(features, packet))
                    elif ARP in packet:
                        arp_threat = self.detection_engine.process_arp(packet)
                        if arp_threat:
                            threats.append(arp_threat)

                    if threats:
                        packet_info = {}
                        src_ip = None
                        dst_ip = None
                        src_mac = None
                        dst_mac = None
                        proto_name = None
                        proto_num = None
                        sport = None
                        dport = None
                        timestamp = datetime.now()

                        if IP in packet:
                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst
                            sport = packet.sport if hasattr(packet, 'sport') else None
                            dport = packet.dport if hasattr(packet, 'dport') else None
                            proto_num = packet[IP].proto if IP in packet else None
                            proto_name = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "Other")
                            packet_info['source_ip'] = src_ip
                            packet_info['destination_ip'] = dst_ip
                            packet_info['sport'] = sport
                            packet_info['dport'] = dport
                            packet_info['protocol_name'] = proto_name
                        elif ARP in packet:
                            src_ip = packet[ARP].psrc
                            dst_ip = packet[ARP].pdst
                            src_mac = packet[ARP].hwsrc
                            dst_mac = packet[ARP].hwdst
                            packet_info['source_ip_arp'] = src_ip
                            packet_info['dest_ip_arp'] = dst_ip
                            packet_info['source_mac'] = src_mac
                            packet_info['dest_mac'] = dst_mac

                        src_host_id = await self._get_host_id(src_ip, src_mac if ARP in packet else None, timestamp=timestamp)
                        dst_host_id = await self._get_host_id(dst_ip, dst_mac if ARP in packet else None, timestamp=timestamp)
                        protocol_id = self._get_protocol_id(proto_name, proto_num if IP in packet else None)

                        for threat in threats:
                            severity = self.alert_system._map_confidence_to_severity(threat.get('confidence', 0.5))
                            severity_id = self._get_severity_id(severity)
                            event_type_id = self._get_event_type_id("intrusion_detection") # Assuming all our threats are this type
                            alert_rule_name = threat.get('rule')
                            alert_rule = await self.alert_system.fetch_alert_rule_by_name(alert_rule_name)
                            alert_rule_id = alert_rule['id'] if alert_rule else None
                            detection_method = threat.get('type', 'unknown')

                            await self.alert_system.process_alert(
                                threat=threat,
                                packet_info=packet_info,
                                src_host_id=src_host_id,
                                dst_host_id=dst_host_id,
                                protocol_id=protocol_id,
                                severity_id=severity_id,
                                event_type_id=event_type_id,
                                alert_rule_id=alert_rule_id,
                                detection_method=detection_method
                            )

                except queue.Empty:
                    continue
                except KeyboardInterrupt:
                    print("[*] Stopping IDS...")
                    self.packet_capture.stop()
                    break

        import asyncio
        asyncio.run(process_packets())

if __name__ == "__main__":
    ids = IntrusionDetectionSystem(interface="eth0") # Replace with your network interface
    ids.start()
