from scapy.all import *
import pandas as pd
import numpy as np
from feature_extractor import PacketFeatureExtractor
import time
import os
from scapy.layers.inet import IP, TCP, UDP

def generate_attack_traffic(n_samples=1000):
    """Generate synthetic attack traffic patterns"""
    rng = np.random.default_rng(42)
    attack_data = []
    feature_names = ['packet_size', 'protocol_type', 'port', 'flags', 'time_interval']
    
    # Different attack patterns
    attack_patterns = [
        # DoS attack pattern
        {
            'packet_size': (1000, 2000),  # Large packets
            'protocol_type': [6],         # TCP
            'port': [80, 443, 8080],      # Common web ports
            'flags': [2, 4],              # SYN, RST
            'time_interval': (0.001, 0.01) # Very short intervals
        },
        # Port scan pattern
        {
            'packet_size': (60, 100),     # Small packets
            'protocol_type': [6],         # TCP
            'port': range(1, 1024),       # Common ports
            'flags': [2],                 # SYN
            'time_interval': (0.1, 0.5)   # Regular intervals
        }
    ]
    
    for _ in range(n_samples):
        pattern = rng.choice(attack_patterns)
        sample = [
            rng.uniform(*pattern['packet_size']),
            float(rng.choice(pattern['protocol_type'])),
            float(rng.choice(pattern['port'])),
            float(rng.choice(pattern['flags'])),
            rng.uniform(*pattern['time_interval'])
        ]
        attack_data.append(sample)
    
    return pd.DataFrame(attack_data, columns=feature_names)

def collect_training_data(duration=60, output_file="data/raw/network_traffic.csv", include_attacks=True):
    """Collect network traffic data for training"""
    feature_extractor = PacketFeatureExtractor()
    packets_data = []
    start_time = time.time()
    
    def packet_callback(packet):
        if IP in packet:
            features = feature_extractor.extract_features(packet)
            # Add label (0 for normal traffic)
            row = list(features[0]) + [0]
            packets_data.append(row)
    
    print(f"Collecting network traffic for {duration} seconds...")
    sniff(prn=packet_callback, timeout=duration)
    
    # Create DataFrame with normal traffic
    columns = feature_extractor.feature_names + ['is_attack']
    df_normal = pd.DataFrame(packets_data, columns=columns)
    
    # Add synthetic attack data if requested
    if include_attacks:
        n_normal = len(df_normal)
        n_attacks = n_normal // 4  # 25% attacks, 75% normal
        df_attacks = generate_attack_traffic(n_attacks)
        df_attacks['is_attack'] = 1
        
        # Combine normal and attack traffic
        df = pd.concat([df_normal, df_attacks], ignore_index=True)
        print(f"Generated {n_attacks} synthetic attack samples")
    else:
        df = df_normal
    
    # Save to CSV
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"Data collected and saved to {output_file}")
    print(f"Dataset composition: {len(df)} total samples")
    print(f"Normal: {len(df[df['is_attack'] == 0])} samples")
    print(f"Attack: {len(df[df['is_attack'] == 1])} samples")

if __name__ == "__main__":
    collect_training_data()