"""
Feature Extraction Module
Converts raw packet logs into feature vectors for ML
"""

import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime

class FeatureExtractor:
    def __init__(self, window_size_seconds=10):
        self.window_size = window_size_seconds
        self.reset()
    
    def reset(self):
        """Reset all accumulators"""
        self.packets_in_window = []
        self.window_start_time = None
        self.all_features = []
        self.labels = []
    
    def extract_features_from_packet_log(self, packet_log):
        """
        Convert packet log into feature vectors
        Returns: (features_array, labels_array)
        """
        if not packet_log:
            return np.array([]), np.array([])
        
        # Convert to DataFrame for easier processing
        df = pd.DataFrame(packet_log)
        df['timestamp'] = pd.to_numeric(df['timestamp'])
        
        # Sort by timestamp
        df = df.sort_values('timestamp')
        
        min_time = df['timestamp'].min()
        max_time = df['timestamp'].max()
        
        # Create sliding windows
        current_time = min_time
        
        while current_time <= max_time:
            window_end = current_time + self.window_size
            
            # Get packets in this window
            window_packets = df[(df['timestamp'] >= current_time) & 
                                (df['timestamp'] < window_end)]
            
            if len(window_packets) > 0:
                features = self._compute_window_features(window_packets)
                
                # Determine label (attack type in this window)
                attack_types = window_packets['attack_type'].unique()
                if 'normal' in attack_types and len(attack_types) > 1:
                    label = 'attack'  # Mixed window
                elif 'normal' in attack_types:
                    label = 'normal'
                else:
                    label = attack_types[0] if len(attack_types) > 0 else 'normal'
                
                self.all_features.append(features)
                self.labels.append(label)
            
            current_time = window_end
        
        return np.array(self.all_features), np.array(self.labels)
    
    def _compute_window_features(self, window_df):
        """Compute features for a window of packets"""
        features = {}
        
        # Basic statistics
        features['packet_count'] = len(window_df)
        features['total_bytes'] = window_df['size'].sum() if 'size' in window_df.columns else 0
        features['avg_packet_size'] = window_df['size'].mean() if 'size' in window_df.columns else 0
        features['std_packet_size'] = window_df['size'].std() if 'size' in window_df.columns and len(window_df) > 1 else 0
        
        # Temporal features
        if len(window_df) > 1:
            time_diffs = window_df['timestamp'].diff().dropna()
            features['avg_interarrival'] = time_diffs.mean()
            features['std_interarrival'] = time_diffs.std()
            features['packet_rate'] = len(window_df) / self.window_size
            features['byte_rate'] = features['total_bytes'] / self.window_size
        else:
            features['avg_interarrival'] = 0
            features['std_interarrival'] = 0
            features['packet_rate'] = features['packet_count'] / self.window_size
            features['byte_rate'] = features['total_bytes'] / self.window_size
        
        # Protocol distribution
        if 'protocol' in window_df.columns:
            tcp_count = (window_df['protocol'] == 'TCP').sum()
            udp_count = (window_df['protocol'] == 'UDP').sum()
            features['tcp_ratio'] = tcp_count / len(window_df) if len(window_df) > 0 else 0
            features['udp_ratio'] = udp_count / len(window_df) if len(window_df) > 0 else 0
        else:
            features['tcp_ratio'] = 0
            features['udp_ratio'] = 0
        
        # TCP flag analysis (for attack detection)
        if 'tcp_flags' in window_df.columns:
            syn_count = window_df['tcp_flags'].str.contains('SYN', na=False).sum()
            ack_count = window_df['tcp_flags'].str.contains('ACK', na=False).sum()
            rst_count = window_df['tcp_flags'].str.contains('RST', na=False).sum()
            
            features['syn_ratio'] = syn_count / len(window_df) if len(window_df) > 0 else 0
            features['ack_ratio'] = ack_count / len(window_df) if len(window_df) > 0 else 0
            features['rst_ratio'] = rst_count / len(window_df) if len(window_df) > 0 else 0
        else:
            features['syn_ratio'] = 0
            features['ack_ratio'] = 0
            features['rst_ratio'] = 0
        
        # Destination diversity (entropy approximation)
        if 'dst' in window_df.columns:
            dst_counts = window_df['dst'].value_counts()
            probabilities = dst_counts / len(window_df)
            features['dst_entropy'] = -sum(p * np.log(p) for p in probabilities if p > 0)
        else:
            features['dst_entropy'] = 0
        
        # Source diversity
        if 'src' in window_df.columns:
            src_counts = window_df['src'].value_counts()
            probabilities = src_counts / len(window_df)
            features['src_entropy'] = -sum(p * np.log(p) for p in probabilities if p > 0)
        else:
            features['src_entropy'] = 0
        
        # Burstiness (variance-to-mean ratio of packet counts)
        if len(window_df) > 10:
            # Divide window into sub-windows
            sub_window_size = max(1, len(window_df) // 5)
            sub_counts = []
            for i in range(0, len(window_df), sub_window_size):
                sub_counts.append(len(window_df.iloc[i:i+sub_window_size]))
            features['burstiness'] = np.var(sub_counts) / (np.mean(sub_counts) + 0.001)
        else:
            features['burstiness'] = 0
        
        # Additional features for attack detection
        features['unique_dst_ratio'] = len(window_df['dst'].unique()) / len(window_df) if len(window_df) > 0 else 0
        features['unique_src_ratio'] = len(window_df['src'].unique()) / len(window_df) if len(window_df) > 0 else 0
        
        # Convert to list in fixed order
        feature_order = [
            'packet_count', 'total_bytes', 'avg_packet_size', 'std_packet_size',
            'avg_interarrival', 'std_interarrival', 'packet_rate', 'byte_rate',
            'tcp_ratio', 'udp_ratio', 'syn_ratio', 'ack_ratio', 'rst_ratio',
            'dst_entropy', 'src_entropy', 'burstiness', 'unique_dst_ratio', 'unique_src_ratio'
        ]
        
        return [features.get(f, 0) for f in feature_order]
    
    def get_feature_names(self):
        """Return names of all features"""
        return [
            'packet_count', 'total_bytes', 'avg_packet_size', 'std_packet_size',
            'avg_interarrival', 'std_interarrival', 'packet_rate', 'byte_rate',
            'tcp_ratio', 'udp_ratio', 'syn_ratio', 'ack_ratio', 'rst_ratio',
            'dst_entropy', 'src_entropy', 'burstiness', 'unique_dst_ratio', 'unique_src_ratio'
        ]


# Test the extractor
if __name__ == "__main__":
    from traffic_generator import IoTTrafficGenerator
    
    print("=" * 60)
    print("Feature Extractor - Test")
    print("=" * 60)
    
    # Generate some traffic
    gen = IoTTrafficGenerator()
    
    print("\nGenerating traffic samples...")
    gen.start_normal_traffic(10)
    gen.start_attack("recon", 5)
    gen.start_normal_traffic(10)
    gen.start_attack("ddos", 5)
    
    # Extract features
    extractor = FeatureExtractor(window_size_seconds=5)
    features, labels = extractor.extract_features_from_packet_log(gen.get_packet_log())
    
    print(f"\nFeatures extracted: {features.shape}")
    print(f"Labels: {labels}")
    
    # Show sample features
    print("\nSample Feature Vector (first window):")
    feature_names = extractor.get_feature_names()
    for i, (name, value) in enumerate(zip(feature_names, features[0])):
        print(f"  {name}: {value:.4f}")