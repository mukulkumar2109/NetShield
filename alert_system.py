import json
import os
from datetime import datetime

class AlertSystem:
    def __init__(self, base_dir="alerts"):
        self.base_dir = base_dir
        self.normal_alerts_file = os.path.join(base_dir, "alerts_output.txt")
        self.critical_alerts_file = os.path.join(base_dir, "critical_alerts.txt")

        # Create alerts directory if it doesn't exist
        os.makedirs(self.base_dir, exist_ok=True)

        # Clear old files at the start
        self._initialize_file(self.normal_alerts_file, "ALL ALERTS\n" + "="*50 + "\n")
        self._initialize_file(self.critical_alerts_file, "CRITICAL ALERTS\n" + "="*50 + "\n")

    def _initialize_file(self, file_path, header_text):
        with open(file_path, 'w') as f:
            f.write(header_text)

    def save_alert(self, alert_data):
        alert_json = json.dumps(alert_data, indent=4)

        # Always save in the normal alerts file
        with open(self.normal_alerts_file, 'a') as f:
            f.write(f"[{self._current_time()}] {alert_json}\n\n")

        # If the alert is critical, also save in critical alerts file
        if alert_data.get('confidence', 0) > 0.8:
            with open(self.critical_alerts_file, 'a') as f:
                f.write(f"[{self._current_time()}] {alert_json}\n\n")

    def _current_time(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
