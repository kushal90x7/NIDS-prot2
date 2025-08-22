from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *
from ml_model import NIDSModel
from feature_extractor import PacketFeatureExtractor
import threading
import queue
import logging
import time
from datetime import datetime
import os
import argparse

class NetworkIDS:
    def __init__(self, interface=None, cli_mode=False):
        self.interface = interface
        self.packet_buffer = queue.Queue(maxsize=1000)
        self.alert_queue = queue.Queue()
        self.stop_threads = False
        self.model = NIDSModel()
        self.feature_extractor = PacketFeatureExtractor()
        self.packets_analyzed = 0
        self.start_time = None
        self.cli_mode = cli_mode
        
        # Setup logging
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            filename='logs/intrusion_detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Only initialize UI if not in CLI mode
        if not cli_mode:
            from nids_ui import NIDSUI
            self.ui = NIDSUI()
            self.ui.set_emergency_stop_callback(self.emergency_stop)

    def log_message(self, message, level="info"):
        """Log message to both file and console"""
        if level == "info":
            logging.info(message)
        elif level == "warning":
            logging.warning(message)
        elif level == "error":
            logging.error(message)
        
        # Print to console in CLI mode
        if self.cli_mode:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
        else:
            self.ui.add_log(message, level)

    def start_capture(self):
        """Start packet capture and analysis"""
        try:
            # Load ML model
            self.model.load()
            self.log_message("Model loaded successfully")
            
            self.start_time = datetime.now()
            self.log_message(f"Starting capture at {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Start threads
            capture_thread = threading.Thread(target=self._capture_packets)
            analysis_thread = threading.Thread(target=self._analyze_packets)
            alert_thread = threading.Thread(target=self._process_alerts)
            
            capture_thread.start()
            analysis_thread.start()
            alert_thread.start()
            
            self.log_message("NIDS started successfully", "info")
            
            return capture_thread, analysis_thread, alert_thread
            
        except Exception as e:
            error_msg = f"Error starting NIDS: {e}"
            self.log_message(error_msg, "error")
            raise

    def _capture_packets(self):
        """Capture network packets"""
        try:
            def packet_handler(packet):
                if not self.stop_threads and IP in packet:
                    self.packet_buffer.put(packet, block=True)
                    self.packets_analyzed += 1
                    
                    if self.cli_mode:
                        if self.packets_analyzed % 100 == 0:  # Only show every 100th packet in CLI
                            self.log_message(f"Packets analyzed: {self.packets_analyzed}")
                    else:
                        self.ui.update_packets_count(self.packets_analyzed)
                    
                    # Log basic packet info
                    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
                    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"
                    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Unknown"
                    
                    # Update UI or log packet info
                    if not self.cli_mode:
                        self.ui.update_port_activity(dst_port, protocol)
                    
                    log_msg = f"{protocol}: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}"
                    self.log_message(log_msg, "info")
            
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=0
            )
        except Exception as e:
            error_msg = f"Packet capture error: {e}"
            self.log_message(error_msg, "error")

    def _analyze_packets(self):
        """Analyze captured packets"""
        while not self.stop_threads:
            try:
                packet = self.packet_buffer.get(timeout=1)
                features = self.feature_extractor.extract_features(packet)
                
                # ML-based detection
                if self.model.predict(features):
                    confidence = self.model.predict_proba(features)[0][1]
                    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
                    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"
                    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Unknown"
                    
                    alert = {
                        'timestamp': datetime.now(),
                        'src_ip': packet[IP].src,
                        'src_port': src_port,
                        'dst_ip': packet[IP].dst,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'type': 'ML_DETECTION',
                        'confidence': confidence
                    }
                    self.alert_queue.put(alert)
                    
            except queue.Empty:
                continue
            except Exception as e:
                error_msg = f"Packet analysis error: {e}"
                self.log_message(error_msg, "error")

    def _process_alert(self, alert):
        """Helper function to process and log alerts"""
        try:
            alert_msg = (
                f"ALERT: {alert['type']}\n"
                f"Source: {alert['src_ip']}:{alert['src_port']} -> "
                f"Destination: {alert['dst_ip']}:{alert['dst_port']}\n"
                f"Protocol: {alert['protocol']}\n"
                f"Confidence: {alert['confidence']:.2f}"
            )
            self.log_message(alert_msg, "alert")
        except Exception as e:
            error_msg = f"Error formatting alert message: {e}"
            self.log_message(error_msg, "error")

    def _process_alerts(self):
        """Process and log alerts"""
        while not self.stop_threads:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._process_alert(alert)
            except queue.Empty:
                continue
            except Exception as e:
                error_msg = f"Alert processing error: {e}"
                self.log_message(error_msg, "error")

    def stop(self):
        """Stop all NIDS processes"""
        self.stop_threads = True
        logging.info("NIDS stopped")
        
        if self.start_time:
            duration = datetime.now() - self.start_time
            self.log_message(f"Monitoring stopped. Duration: {duration}", "info")
        
        if not self.cli_mode:
            self.ui.update_status("Stopped")
            self.ui.update_capture_status("Stopped")
            self.ui.root.after(100, self.ui.root.quit)

    def run(self):
        """Run the NIDS"""
        try:
            threads = self.start_capture()
            if not self.cli_mode:
                self.ui.start()  # Start UI main loop
            else:
                # In CLI mode, wait for Ctrl+C
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.log_message("Stopping NIDS (Ctrl+C detected)...")
                    self.stop()
                
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.log_message(f"Runtime error: {e}", "error")
            self.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode without GUI')
    parser.add_argument('--interface', help='Network interface to monitor')
    args = parser.parse_args()
    
    nids = NetworkIDS(interface=args.interface, cli_mode=args.cli)
    nids.run()
