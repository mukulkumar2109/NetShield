from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import threading
import queue
from analyzer.PacketAnalyzer import PacketAnalyzer

class PacketCapture:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.analyzer = PacketAnalyzer()

    def packet_callback(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            self.packet_queue.put(packet)
            self.analyzer.analyze_packet(packet)  

    def start_capture(self):
        def capture_thread():
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_capture.is_set()
            )

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import threading
import queue
from analyzer.PacketAnalyzer import PacketAnalyzer

class PacketCapture:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.analyzer = PacketAnalyzer()

    def packet_callback(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            self.packet_queue.put(packet)
            self.analyzer.analyze_packet(packet)  

    def start_capture(self):
        def capture_thread():
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda _: self.stop_capture.is_set()
            )

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()
