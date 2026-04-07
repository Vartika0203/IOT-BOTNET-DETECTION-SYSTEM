"""
IoT Botnet Traffic Generator
Simulates normal IoT devices and botnet attack traffic
"""

import random
import time
import threading
from datetime import datetime
from scapy.all import IP, TCP, UDP, send, Raw

class IoTTrafficGenerator:
    def __init__(self):
        # Simulated devices in the network
        self.devices = [
            {"name": "Living_Room_Sensor", "ip": "192.168.1.101", "type": "sensor"},
            {"name": "Bedroom_Sensor", "ip": "192.168.1.102", "type": "sensor"},
            {"name": "Smart_Plug_1", "ip": "192.168.1.103", "type": "actuator"},
            {"name": "Smart_Plug_2", "ip": "192.168.1.104", "type": "actuator"},
            {"name": "Security_Camera", "ip": "192.168.1.105", "type": "camera"},
            {"name": "Smart_Thermostat", "ip": "192.168.1.106", "type": "sensor"},
            {"name": "Door_Lock", "ip": "192.168.1.107", "type": "actuator"},
            {"name": "Light_Controller", "ip": "192.168.1.108", "type": "actuator"},
        ]
        
        # External destinations (cloud servers, internet)
        self.external_ips = ["8.8.8.8", "34.120.45.2", "52.45.123.1", "3.12.87.4"]
        
        # C2 Server (for botnet simulation)
        self.c2_server = "185.130.5.253"
        
        # Attack victim (target of DDoS)
        self.victim = "192.168.1.200"
        
        # Control flags
        self.attack_active = False
        self.attack_type = None
        
        # Logging
        self.packet_log = []
        
    def generate_normal_sensor_packet(self, device):
        """Generate normal sensor reading (temperature, humidity, etc.)"""
        src_ip = device["ip"]
        dst_ip = random.choice(self.external_ips)
        
        # Simulate sensor data
        payload = f"SENSOR_DATA:{device['name']}:{random.uniform(20, 30):.1f}:{datetime.now().timestamp()}"
        
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=443) / Raw(load=payload)
        return packet
    
    def generate_normal_actuator_packet(self, device):
        """Generate normal actuator command/response"""
        src_ip = device["ip"]
        dst_ip = random.choice(self.external_ips)
        
        payload = f"STATUS:{device['name']}:{random.choice(['ON', 'OFF'])}:{datetime.now().timestamp()}"
        
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=443) / Raw(load=payload)
        return packet
    
    def generate_camera_packet(self, device):
        """Generate camera streaming packets (higher rate)"""
        src_ip = device["ip"]
        dst_ip = random.choice(self.external_ips)
        
        # Camera sends larger packets more frequently
        payload_size = random.randint(500, 1500)
        payload = "VIDEO_DATA:" + "X" * payload_size
        
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1024, 65535), dport=554) / Raw(load=payload[:100])  # Truncated for demo
        return packet
    
    def generate_recon_packet(self, device):
        """Generate reconnaissance attack packet (port scanning)"""
        src_ip = device["ip"]
        # Scanning multiple destination IPs
        dst_ip = f"192.168.1.{random.randint(1, 254)}"
        
        # SYN packet to common IoT ports
        target_ports = [22, 23, 80, 443, 8080, 8443]
        dst_port = random.choice(target_ports)
        
        # SYN flag set (TCP flag 0x02)
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S")
        return packet
    
    def generate_cc_packet(self, device):
        """Generate C&C communication packet"""
        src_ip = device["ip"]
        dst_ip = self.c2_server
        
        # Beacon message to C2 server
        payload = f"BOT_ID:{device['name']}:{datetime.now().timestamp()}:STATUS_READY"
        
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=random.randint(1024, 65535), dport=6667) / Raw(load=payload)  # IRC port
        return packet
    
    def generate_ddos_packet(self, device):
        """Generate DDoS attack packet (UDP flood)"""
        src_ip = device["ip"]
        dst_ip = self.victim
        
        # Random payload size for UDP flood
        payload_size = random.randint(100, 500)
        payload = "A" * payload_size
        
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=random.randint(1, 65535), dport=random.randint(1, 10000)) / Raw(load=payload)
        return packet
    
    def send_packet(self, packet):
        """Send a single packet and log it"""
        try:
            # For demonstration, we'll just log instead of actually sending
            # (Sending real packets requires admin privileges)
            packet_info = {
                "timestamp": datetime.now().timestamp(),
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "protocol": "TCP" if packet.haslayer(TCP) else "UDP",
                "size": len(packet),
                "attack_type": self.attack_type if self.attack_active else "normal"
            }
            
            # Add TCP flags if TCP packet
            if packet.haslayer(TCP):
                flags = []
                if packet[TCP].flags.S:
                    flags.append("SYN")
                if packet[TCP].flags.A:
                    flags.append("ACK")
                if packet[TCP].flags.R:
                    flags.append("RST")
                packet_info["tcp_flags"] = ",".join(flags) if flags else "None"
            else:
                packet_info["tcp_flags"] = "None"
                
            self.packet_log.append(packet_info)
            return packet_info
        except:
            return None
    
    def start_normal_traffic(self, duration_seconds=60):
        """Generate normal traffic for specified duration"""
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration_seconds and not self.attack_active:
            for device in self.devices:
                # Different behavior based on device type
                if device["type"] == "sensor":
                    # Sensors send every 5-10 seconds
                    if random.random() < 0.15:  # ~15% chance per loop iteration
                        packet = self.generate_normal_sensor_packet(device)
                        info = self.send_packet(packet)
                        if info:
                            packet_count += 1
                            
                elif device["type"] == "actuator":
                    # Actuators send less frequently (status updates)
                    if random.random() < 0.05:
                        packet = self.generate_normal_actuator_packet(device)
                        info = self.send_packet(packet)
                        if info:
                            packet_count += 1
                            
                elif device["type"] == "camera":
                    # Cameras send frequently (streaming)
                    if random.random() < 0.3:
                        packet = self.generate_camera_packet(device)
                        info = self.send_packet(packet)
                        if info:
                            packet_count += 1
            
            # Small delay to control packet rate
            time.sleep(0.1)
        
        return packet_count
    
    def start_attack(self, attack_type, duration_seconds=30):
        """Start a specific attack"""
        self.attack_active = True
        self.attack_type = attack_type
        start_time = time.time()
        packet_count = 0
        
        print(f"[ATTACK STARTED] {attack_type.upper()} attack - Duration: {duration_seconds}s")
        
        while time.time() - start_time < duration_seconds:
            # All compromised devices participate
            for device in self.devices[:5]:  # First 5 devices are "compromised"
                
                if attack_type == "recon":
                    packet = self.generate_recon_packet(device)
                elif attack_type == "cc":
                    packet = self.generate_cc_packet(device)
                elif attack_type == "ddos":
                    packet = self.generate_ddos_packet(device)
                else:
                    packet = None
                
                if packet:
                    info = self.send_packet(packet)
                    if info:
                        packet_count += 1
                        
                # Attack packets are sent rapidly
                time.sleep(0.01)  # 10ms between packets (high rate)
        
        self.attack_active = False
        self.attack_type = None
        print(f"[ATTACK ENDED] {packet_count} packets sent")
        
        return packet_count
    
    def get_packet_log(self):
        """Return all captured packets for analysis"""
        return self.packet_log
    
    def clear_log(self):
        """Clear the packet log"""
        self.packet_log = []


# Test the generator
if __name__ == "__main__":
    print("=" * 60)
    print("IoT Botnet Traffic Generator - Test")
    print("=" * 60)
    
    generator = IoTTrafficGenerator()
    
    print("\n[1] Generating Normal Traffic (15 seconds)...")
    normal_count = generator.start_normal_traffic(15)
    print(f"    Generated {normal_count} normal packets")
    
    print("\n[2] Generating Reconnaissance Attack (10 seconds)...")
    recon_count = generator.start_attack("recon", 10)
    
    print("\n[3] Generating Normal Traffic (15 seconds)...")
    normal_count2 = generator.start_normal_traffic(15)
    print(f"    Generated {normal_count2} normal packets")
    
    print("\n[4] Generating C&C Attack (10 seconds)...")
    cc_count = generator.start_attack("cc", 10)
    
    print("\n[5] Generating DDoS Attack (10 seconds)...")
    ddos_count = generator.start_attack("ddos", 10)
    
    # Summary
    print("\n" + "=" * 60)
    print("TRAFFIC SUMMARY")
    print("=" * 60)
    print(f"Total packets captured: {len(generator.get_packet_log())}")
    
    # Show sample packets
    print("\nSample Packets:")
    for i, pkt in enumerate(generator.get_packet_log()[:10]):
        print(f"  {i+1}. {pkt}")