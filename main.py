from capture.PacketCapture import PacketCapture
import pandas as pd
import time


if __name__ == "__main__":
    sniffer = PacketCapture(interface="eth0")  #add your own interface here
    sniffer.start_capture()
