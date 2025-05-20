import time
from alert_system import AlertSystem

# Create AlertSystem instance once here
alert_system = AlertSystem()

def save_alert_generic(alert_type, detection_info, confidence=1.0, additional_info=None):
    alert_data = {
        'timestamp': time.time(),
        'alert_type': alert_type,
        'confidence': confidence,
        'details': detection_info
    }

    if additional_info:
        alert_data['additional_info'] = additional_info

    alert_system.save_alert(alert_data)
