from scapy.all import IP, TCP, UDP, Ether, ARP, send
import time

def test_ids(interface="lo"):
    test_packets = [
        # Normal traffic
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / UDP(sport=1235, dport=53),

        # SYN flood
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),

        # Port scan
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),

        # UDP flood
        IP(src="172.16.0.1", dst="192.168.1.3") / UDP(sport=3456, dport=53) / ("A"*50),
        IP(src="172.16.0.2", dst="192.168.1.3") / UDP(sport=3457, dport=53) / ("B"*50),
        IP(src="172.16.0.3", dst="192.168.1.3") / UDP(sport=3458, dport=53) / ("C"*50),

        # Null scan
        IP(src="192.168.1.150", dst="192.168.1.2") / TCP(dport=80, flags=""),

        # FIN scan
        IP(src="192.168.1.151", dst="192.168.1.2") / TCP(dport=80, flags="F"),

        # Xmas scan
        IP(src="192.168.1.152", dst="192.168.1.2") / TCP(dport=80, flags="PSH|URG|FIN"),

        # Potential brute force SSH
        IP(src="192.168.1.200", dst="192.168.1.5") / TCP(sport=1111, dport=22, flags="S"),
        IP(src="192.168.1.201", dst="192.168.1.5") / TCP(sport=1112, dport=22, flags="S"),
        IP(src="192.168.1.202", dst="192.168.1.5") / TCP(sport=1113, dport=22, flags="S"),
        IP(src="192.168.1.203", dst="192.168.1.5") / TCP(sport=1114, dport=22, flags="S"),

        # Potential DNS Tunneling (large DNS response)
        IP(src="192.168.1.5", dst="192.168.1.20") / UDP(sport=53, dport=1050) / ("A" * 600),

        # Suspicious small UDP high rate (simulating C2)
        IP(src="10.0.0.10", dst="192.168.1.30") / UDP(sport=5000, dport=6000) / ("\x01"),
        IP(src="10.0.0.10", dst="192.168.1.30") / UDP(sport=5000, dport=6000) / ("\x02"),
        IP(src="10.0.0.10", dst="192.168.1.30") / UDP(sport=5000, dport=6000) / ("\x03"),

        # ARP Spoofing simulation
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="192.168.1.10", hwsrc="00:aa:bb:cc:dd:ee", pdst="192.168.1.1", hwdst="00:ff:ff:ff:ff:ff"),
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(psrc="192.168.1.10", hwsrc="00:99:88:77:66:55", pdst="192.168.1.1", hwdst="00:ff:ff:ff:ff:ff") # Different MAC for the same IP
    ]

    print("Sending test packets...")
    for packet in test_packets:
        send(packet, iface=interface, verbose=False)
        time.sleep(0.1)
    print("Test packets sent.")

if __name__ == "__main__":
    test_ids(interface="lo") # Use 'eth0' or your network interface if not testing locally
