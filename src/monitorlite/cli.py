import argparse
from monitorlite import capture, detection, logger

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", default="rules/example-basic.yml")
    parser.add_argument("--iface", default="lo")
    args = parser.parse_args()

    rules = detection.load_rules(args.rules)
    print(f"[+] Loaded rules: {rules}")

    print(f"[+] Capturing packets on {args.iface}...")
    packets = capture.capture_packets(args.iface)

    for pkt in packets:
        alert = detection.detect(pkt, rules)
        if alert:
            logger.log_event(alert)
            print(f"[ALERT] {alert}")

if __name__ == "__main__":
    main()
