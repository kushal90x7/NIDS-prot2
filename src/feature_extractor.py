import numpy as np
from scapy.layers.inet import IP, TCP, UDP  # Add specific imports
from scapy.all import *
import time
import logging

class PacketFeatureExtractor:
    def __init__(self):
        self.last_packet_time = None
        self.feature_names = [
            'packet_size',
            'protocol_type',
            'port',
            'flags',
            'time_interval'
        ]
        logging.info("PacketFeatureExtractor initialized")

    def extract_features(self, packet):
        """Extract features from network packets for ML analysis"""
        try:
            current_time = time.time()
            features = {}

            # Extract packet size (numeric)
            features['packet_size'] = float(len(packet))

            # Convert protocol type to numeric
            if IP in packet:
                features['protocol_type'] = float(packet[IP].proto)
            else:
                features['protocol_type'] = 0.0

            # Convert port and flags to numeric
            if TCP in packet:
                features['port'] = float(packet[TCP].dport)
                # Convert TCP flags to integer before float conversion
                features['flags'] = float(int(packet[TCP].flags))
            elif UDP in packet:
                features['port'] = float(packet[UDP].dport)
                features['flags'] = 0.0
            else:
                features['port'] = 0.0
                features['flags'] = 0.0

            # Time interval (already numeric)
            if self.last_packet_time:
                features['time_interval'] = float(current_time - self.last_packet_time)
            else:
                features['time_interval'] = 0.0
            
            self.last_packet_time = current_time

            return np.array([features[name] for name in self.feature_names]).reshape(1, -1)

        except Exception as e:
            logging.error(f"Error extracting features: {e}")
            return np.zeros((1, len(self.feature_names)))