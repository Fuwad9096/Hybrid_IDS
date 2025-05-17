from scapy.all import sniff
import threading
import queue

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if hasattr(packet, 'haslayer') and (packet.haslayer('IP') and (packet.haslayer('TCP') or packet.haslayer('UDP'))) or packet.haslayer('ARP'):
            self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

if __name__ == '__main__':
    # Example usage (you'd typically run this from hybrid_ids.py)
    capture = PacketCapture()
    print("[PacketCapture] Starting capture (Ctrl+C to stop)...")
    capture.start_capture("eth0")
    try:
        while True:
            packet = capture.packet_queue.get(timeout=1)
            print(f"[PacketCapture] Captured: {packet.summary()}")
    except KeyboardInterrupt:
        print("[PacketCapture] Stopping capture.")
        capture.stop()
