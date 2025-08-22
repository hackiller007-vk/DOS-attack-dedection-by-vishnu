from scapy.all import sniff

def capture_packets(interface="lo", count=0):
    """Capture packets from the given interface."""
    return sniff(iface=interface, count=count)
