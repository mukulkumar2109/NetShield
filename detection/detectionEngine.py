import re
from scapy.all import Raw, IP
from alert_helper import save_alert_generic
import joblib
import sklearn
import pandas as pd
from datetime import datetime

class detectionEngine:
    def __init__(self):
        self.rules = [
            {
                'id': 1,
                'description': 'Suspicious HTTP keyword',
                'pattern': re.compile(br"(malware|attack|exploit|virus|trojan|phishing)", re.IGNORECASE)
            },
            {
                'id': 2,
                'description': 'Potential credential leak',
                'pattern': re.compile(br"(username=.*&?password=.*)", re.IGNORECASE)
            },
            {
                'id': 3,
                'description': 'SQL Injection attempt',
                'pattern': re.compile(br"(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bUPDATE\b).*(--|\bOR\b|\bAND\b)", re.IGNORECASE)
            },
            {
                'id': 4,
                'description': 'XSS Attack attempt',
                'pattern': re.compile(br"(<script>|javascript:|onerror=|onload=)", re.IGNORECASE)
            },
            {
                'id': 5,
                'description': 'Shellcode or suspicious binary payload',
                'pattern': re.compile(br"(\x90{10,}|/bin/sh|\xCC\xCC\xCC)", re.IGNORECASE)  # NOP sled or /bin/sh
            },
            {
                'id': 6,
                'description': 'Remote command execution keywords',
                'pattern': re.compile(br"(wget|curl|nc\s+\-e|bash\s+\-i)", re.IGNORECASE)
            }
        ]
        self.loaded = joblib.load('top20features.pkl')
        self.model = self.loaded['model']
        self.top_features = [
            'Max Packet Length', 'Avg Bwd Segment Size', 'Packet Length Std', 'Packet Length Variance',
            'Average Packet Size', 'Destination Port', 'Bwd Packet Length Max', 'Bwd Packet Length Std',
            'Subflow Fwd Bytes', 'Total Length of Bwd Packets', 'Bwd Packet Length Mean',
            'Packet Length Mean', 'Init_Win_bytes_forward', 'Subflow Bwd Bytes',
            'Total Length of Fwd Packets', 'Avg Fwd Segment Size', 'Bwd Header Length',
            'Fwd Packet Length Max', 'Fwd Header Length.1', 'Fwd Header Length'
        ]
        self.feature_mapping = {
            'Max Packet Length': 'max_packet_length',
            'Avg Bwd Segment Size': 'avg_bwd_segment_size',
            'Packet Length Std': 'packet_length_std',
            'Packet Length Variance': 'packet_length_variance',
            'Average Packet Size': 'average_packet_size',
            'Destination Port': 'destination_port',
            'Bwd Packet Length Max': 'bwd_packet_length_max',
            'Bwd Packet Length Std': 'bwd_packet_length_std',
            'Subflow Fwd Bytes': 'subflow_fwd_bytes',
            'Total Length of Bwd Packets': 'total_bwd_bytes',
            'Bwd Packet Length Mean': 'bwd_packet_length_mean',
            'Packet Length Mean': 'packet_length_mean',
            'Init_Win_bytes_forward': 'window_size',  
            'Subflow Bwd Bytes': 'subflow_bwd_bytes',
            'Total Length of Fwd Packets': 'total_fwd_bytes',  
            'Avg Fwd Segment Size': 'avg_fwd_segment_size',
            'Bwd Header Length': 'bwd_header_length_mean',
            'Fwd Packet Length Max': 'fwd_packet_length_max',   
            'Fwd Header Length.1': 'fwd_header_length_mean',    #2
            'Fwd Header Length': 'fwd_header_length'  # Adjust if needed
        }

    def inspect_packet(self, packet):
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            for rule in self.rules:
                if rule['pattern'].search(payload):
                    print(f"[ALERT] Rule {rule['id']} matched: {rule['description']}")
                    save_alert_generic(
                        alert_type='payload',
                        detection_info={
                            'pattern_detected': rule['description'],
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                        },
                        confidence=0.95
                    )
                    return True
        return False
    
    def anomaly_detection(self, packet, features):
        # input_data = [features.get(self.feature_mapping.get(f, ''), 0) for f in self.top_features]
        self.loaded = joblib.load('top20.pkl')
        self.model = self.loaded['model']
        X = pd.DataFrame([features], columns=self.top_features)
        prediction = self.model.predict(X)

        print(f"Flow: {packet[IP].src, packet[IP].dst} => Prediction: {prediction}")

    def test(self, X, y):
        pred = self.model.predict(X)
        if(pred==1):
            print("[ALERT] attack detected")
            save_alert_generic(
                        alert_type='anomaly',
                        detection_info={
                            'current_time': datetime.now().strftime("%H:%M:%S"),
                        },
                        confidence=0.9
                    )
        else:
            print("Normal Activity")
        # print(f'{pred}')

