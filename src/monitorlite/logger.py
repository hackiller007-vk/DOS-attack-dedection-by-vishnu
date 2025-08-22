import json
import os
from datetime import datetime

LOG_FILE = "logs/eve.json"

def log_event(event):
    os.makedirs("logs", exist_ok=True)
    event["timestamp"] = datetime.utcnow().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
