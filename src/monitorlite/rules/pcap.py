from scapy.all import IP, TCP, wrpcap

packets = [IP(src="192.168.1.100", dst="192.168.1.1")/TCP() for _ in range(50)]
wrpcap("pcaps/sample.pcap", packets)
print("Sample pcap created at pcaps/sample.pcap")
