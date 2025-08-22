import yaml

def load_rules(rule_file="rules/example-basic.yml"):
    with open(rule_file) as f:
        return yaml.safe_load(f)

def detect(packet, rules):
    for rule in rules["rules"]:
        if packet.haslayer("IP"):
            ip = packet["IP"].src
            if ip == rule["src_ip"]:
                return {
                    "rule": rule["description"],
                    "src_ip": ip
                }
    return None
