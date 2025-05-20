from scapy.all import IP, TCP, UDP, Raw, sniff
from collections import defaultdict
from detection.detectionEngine import detectionEngine
import time, datetime
from alert_helper import save_alert_generic

class PacketAnalyzer:
    def __init__(self, work_hours=(9,17)):
        self.k = 0
        self.window = None
        self.work_start, self.work_end = work_hours
        self.tcp_ip = None
        self.udp_ip = None
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'fwd_packet_lengths': [],
            'bwd_packet_lengths': [],
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'fwd_header_lengths': [],
            'bwd_header_lengths': []
        })
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.detection_engine = detectionEngine()

        self.flow_rules = [
            {
                'id': 101,
                'description': 'Potential SYN Flood Attack',
                'condition': self.syn_flood_rule
            },
            {
                'id': 102,
                'description': 'Potential Port Scanning',
                'condition': self.port_scan_rule
            }
        ]

    def check_time_based_alert(self,packet):
        packet_time = datetime.datetime.fromtimestamp(packet.time).time()
        if not (self.work_start <= packet_time.hour < self.work_end):
            print(f"[TIME ALERT] Packet captured outside work hours: {packet_time}")
            save_alert_generic(
                alert_type='time',
                detection_info={
                    'activity_time': f"{packet_time.hour}:{packet_time.minute}",
                    'expected_work_hours': '09:00-17:00'
                },
                confidence=1.0
            )

    def check_anomaly(self, features, flow_key):
        thresholds = {
            'packet_rate': (0,50),
            'byte_rate': (0,1e6)
        }
        anomalies = []

        for feature, (min_val, max_val) in thresholds.items():
            if feature in features:
                if not (min_val <= features[feature] < max_val):
                    anomalies.append(f"{feature} out of range: {features[feature]}")
                    save_alert_generic(
                        alert_type='anomaly',
                        detection_info={
                            'packet_rate': features['packet_rate'],
                            'byte_rate': features['byte_rate'],
                            'problem': f"{feature} out of range: {features[feature]}",
                        },
                        confidence=0.9
                    )

        if anomalies:
            print(f"\n[ANOMALY ALERT] detected anomalies for flow {flow_key}:")
            for anomaly in anomalies:
                print(f"  ->{anomaly}")
                


    def analyze_packet(self, packet):
        try:
            self.detection_engine.inspect_packet(packet)
        except Exception as e:
            print(f"Error: payload inspection failed: {e}")
        self.check_time_based_alert(packet)
        # Ensure it's IP + TCP or UDP
        if IP in packet and (TCP in packet or UDP in packet):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = 'TCP' if TCP in packet else 'UDP'
            port_src = packet[TCP].sport if TCP in packet else packet[UDP].sport
            port_dst = packet[TCP].dport if TCP in packet else packet[UDP].dport
            if(self.k==0):
                self.starting_ip=ip_src
                self.p = 0 if proto == 'TCP' else 1
            self.k += 1
            if(self.k!=1 and proto=='TCP' and self.p == 1):
                self.p = 0
                self.starting_ip = ip_src
            elif(self.k!=1 and proto=='UDP' and self.p == 0):
                self.p = 1
                self.starting_ip = ip_src

            flow_key = (ip_src, ip_dst, port_src, port_dst, proto)

            if flow_key not in self.flow_stats:
                self.flow_stats[flow_key] = {
                    'packet_count': 0,
                    'byte_count': 0,
                    'start_time': None,
                    'last_time': None,
                    'fwd_packet_lengths': [],
                    'bwd_packet_lengths': [],
                    'fwd_bytes': 0,
                    'bwd_bytes': 0,
                    'fwd_header_lengths': [],
                    'bwd_header_lengths': []
                }

            # Update flow stats
            stats = self.flow_stats[flow_key]
            stats.setdefault('packet_lengths', [])
            stats.setdefault('fwd_packet_lengths', [])
            stats.setdefault('bwd_packet_lengths', [])

            packet_length = len(packet)
            stats['packet_lengths'].append(packet_length)


            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if stats['start_time'] is None:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            if ip_src == self.starting_ip:  # Forward flow
                stats['fwd_packet_lengths'].append(packet_length)
                stats['fwd_bytes'] += len(packet)
                self.fwd_packet_lengths.append(packet_length)
                if TCP in packet:
                    fwd_header_length = packet[IP].len - (packet[TCP].dataofs * 4)
                    stats['fwd_header_lengths'].append(fwd_header_length)
            else:  # Backward flow
                stats['bwd_packet_lengths'].append(packet_length)
                stats['bwd_bytes'] += len(packet)
                self.bwd_packet_lengths.append(packet_length)
                if TCP in packet:
                    bwd_header_length = packet[IP].len - (packet[TCP].dataofs * 4)
                    stats['bwd_header_lengths'].append(bwd_header_length)


            features = self.extract_features(packet, stats, proto)
            self.check_flow_rules(features, flow_key)
            self.check_anomaly(features, flow_key)
            self.detection_engine.anomaly_detection(packet, features)
            self.pretty_print(flow_key, features)


    def extract_features(self, packet, stats, proto):
        print(self.fwd_packet_lengths)
        print(self.bwd_packet_lengths)
        duration = int(stats['last_time'] - stats['start_time']) if int(stats['last_time'] - stats['start_time']) else 1
        total_packets = len(stats['packet_lengths'])
        total_bytes = sum(stats['packet_lengths'])
        features = {'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'max_packet_length': max(stats['packet_lengths'], default=0),
            'average_packet_size': total_bytes / total_packets if total_packets else 0,
            'packet_length_mean': total_bytes / total_packets if total_packets else 0,
            'packet_length_std': (sum((x - (total_bytes / total_packets)) ** 2 for x in stats['packet_lengths']) / total_packets) ** 0.5 if total_packets else 0,
            'packet_length_variance': (sum((x - (total_bytes / total_packets)) ** 2 for x in stats['packet_lengths']) / total_packets) if total_packets else 0,
            'destination_port': packet[TCP].dport if proto == 'TCP' else packet[UDP].dport,
            'subflow_fwd_bytes': sum(self.fwd_packet_lengths),
            'subflow_bwd_bytes': sum(self.bwd_packet_lengths),
            'avg_fwd_segment_size': sum(self.fwd_packet_lengths) / len(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0,
            'avg_bwd_segment_size': sum(self.bwd_packet_lengths) / len(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0,
            'fwd_header_length': int(sum(self.fwd_packet_lengths) / len(self.fwd_packet_lengths)) if self.fwd_packet_lengths else 0,
            'fwd_header_length_mean': int(sum(self.fwd_packet_lengths) / len(self.fwd_packet_lengths)) if self.fwd_packet_lengths else 0,
            # 'fwd_header_length.1': sum(stats.get('fwd_packet_lengths', [])) / len(stats['fwd_packet_lengths']) if stats['fwd_packet_lengths'] else 0,  # if required separately
            'bwd_packet_length_max': max(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0,
            'bwd_packet_length_mean': sum(self.bwd_packet_lengths)/len(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0,
            'bwd_packet_length_std': (sum((x-sum(self.bwd_packet_lengths)/len(self.bwd_packet_lengths)) ** 2 for x in self.bwd_packet_lengths)/len(self.bwd_packet_lengths)) ** 0.5 if self.bwd_packet_lengths else 0,
            'total_bwd_bytes': sum(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0,
            'bwd_header_length_mean': sum(self.bwd_packet_lengths) / len(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0,
            'total_fwd_bytes': sum(self.fwd_packet_lengths),
            'fwd_packet_length_max': max(self.fwd_packet_lengths),

        }

        if stats['fwd_packet_lengths']:
            print("fwd")
            # print(stats['fwd_packet_lengths'])
            # print(stats['bwd_packet_lengths'])
            features.update({
                'fwd_packet_length_max': max(stats['fwd_packet_lengths']),
                'fwd_packet_length_mean': sum(stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths']),
                'fwd_packet_length_std': (sum((x - (sum(stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths']))) ** 2 for x in stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths'])) ** 0.5,
                'fwd_packet_length_variance': (sum((x - (sum(stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths']))) ** 2 for x in stats['fwd_packet_lengths']) / len(stats['fwd_packet_lengths'])),
                'total_fwd_bytes': stats['fwd_bytes'],
                'fwd_header_length_mean': sum(stats['fwd_header_lengths']) / len(stats['fwd_header_lengths']) if stats['fwd_header_lengths'] else 0
            })

        if stats['bwd_packet_lengths']:
            print("bwd")
            # print(stats['fwd_packet_lengths'])
            # print(stats['bwd_packet_lengths'])
            features.update({
                'bwd_packet_length_max': max(stats['bwd_packet_lengths']),
                'bwd_packet_length_mean': sum(stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths']),
                'bwd_packet_length_std': (sum((x - (sum(stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths']))) ** 2 for x in stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths'])) ** 0.5,
                'bwd_packet_length_variance': (sum((x - (sum(stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths']))) ** 2 for x in stats['bwd_packet_lengths']) / len(stats['bwd_packet_lengths'])),
                'total_bwd_bytes': stats['bwd_bytes'],
                'bwd_header_length_mean': sum(stats['bwd_header_lengths']) / len(stats['bwd_header_lengths']) if stats['bwd_header_lengths'] else 0
            })
        print(self.k)
        if proto == 'TCP' and self.k==1:
            self.window = packet[TCP].window
        if proto == 'TCP':
            features.update({
                'tcp_flags': int(packet[TCP].flags),
                'window_size': self.window
            })

        
        if proto == 'UDP':
            features.update({
                'udp_flags': 0,
                'window_size': self.window if self.window else 0
            })

        return features

    def check_flow_rules(self, features, flow_key):
        for rule in self.flow_rules:
            if rule['condition'](features):
                print(f"\n[FLOW ALERT] Rule {rule['id']} matched: {rule['description']} for Flow {flow_key}")
                save_alert_generic(
                    alert_type='flow',
                    detection_info={
                        'flow': flow_key,
                        'abnormal_behavior': rule['description']
                    },
                    confidence=0.8
                )

    def syn_flood_rule(self, features):
        return features.get('tcp_flags') == 0x02 and features.get('packet_rate', 0) > 100

    def port_scan_rule(self, features):
        return features.get('packet_size', 0) < 100 and features.get('packet_rate', 0) > 50


    def pretty_print(self, flow_key, features):
        print(f"\n[+] Flow: {flow_key}")
        for key, value in features.items():
            print(f"    {key}: {value}")



