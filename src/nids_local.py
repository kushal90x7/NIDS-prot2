from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *
from ml_model import NIDSModel
from feature_extractor import PacketFeatureExtractor
from nids_ui import NIDSUI
import threading
import queue
import logging
import time
from datetime import datetime
import os
import argparse

class NetworkIDS:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_buffer = queue.Queue(maxsize=1000)
        self.alert_queue = queue.Queue()
        self.stop_threads = False
        self.model = NIDSModel()
        self.feature_extractor = PacketFeatureExtractor()
        self.packets_analyzed = 0
        self.start_time = None
        
        # Initialize UI
        self.ui = NIDSUI()
        self.ui.set_emergency_stop_callback(self.emergency_stop)
        
        # Setup logging with UI integration
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            filename='logs/intrusion_detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def start_capture(self):
        """Start packet capture and analysis"""
        try:
            # Load ML model
            self.model.load()
            self.ui.update_model_status("Loaded")
            self.ui.update_status("Loading model...")
            
            self.start_time = datetime.now()
            self.ui.add_log(f"Starting capture at {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}", "info")
            
            # Start threads
            capture_thread = threading.Thread(target=self._capture_packets)
            analysis_thread = threading.Thread(target=self._analyze_packets)
            alert_thread = threading.Thread(target=self._process_alerts)
            
            capture_thread.start()
            analysis_thread.start()
            alert_thread.start()
            
            self.ui.update_capture_status("Running")
            self.ui.update_status("Monitoring network traffic")
            self.ui.add_log("NIDS started successfully", "success")
            
            return capture_thread, analysis_thread, alert_thread
            
        except Exception as e:
            error_msg = f"Error starting NIDS: {e}"
            logging.error(error_msg)
            self.ui.add_error(error_msg)
            self.ui.update_status("Error")
            self.ui.update_capture_status("Error")
            raise

    def _capture_packets(self):
        """Capture network packets"""
        try:
            def packet_handler(packet):
                if not self.stop_threads and IP in packet:
                    self.packet_buffer.put(packet, block=True)
                    self.packets_analyzed += 1
                    self.ui.update_packets_count(self.packets_analyzed)
                    
                    # Log basic packet info
                    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
                    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"
                    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Unknown"
                    
                    # Update port activity in UI
                    self.ui.update_port_activity(dst_port, protocol)
                    
                    # Add to live traffic log
                    log_msg = f"{protocol}: {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}"
                    self.ui.add_log(log_msg, "info")
            
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=0
            )
        except Exception as e:
            error_msg = f"Packet capture error: {e}"
            logging.error(error_msg)
            self.ui.add_error(error_msg)
            self.ui.update_capture_status("Error")

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
                logging.error(error_msg)
                self.ui.add_error(error_msg)

    def _process_alerts(self):
        """Process and log alerts"""
        while not self.stop_threads:
            try:
                alert = self.alert_queue.get(timeout=1)
                alert_msg = (
                    f"Alert: {alert['type']}\n"
                    f"Source: {alert['src_ip']}:{alert['src_port']} -> "
                    f"Destination: {alert['dst_ip']}:{alert['dst_port']}\n"
                    f"Protocol: {alert['protocol']}\n"
                    f"Confidence: {alert['confidence']:.2f}"
                )
                
                logging.warning(alert_msg)
                self.ui.add_alert(alert_msg)
                self.ui.add_log(f"ALERT: Potential intrusion from {alert['src_ip']}:{alert['src_port']}", "alert")
                
            except queue.Empty:
                continue
            except Exception as e:
                error_msg = f"Alert processing error: {e}"
                logging.error(error_msg)
                self.ui.add_error(error_msg)

    def emergency_stop(self):
        """Handle emergency stop button"""
        try:
            # Set stop flag for all threads
            self.stop_threads = True
            
            # Log the stop
            stop_msg = "Emergency stop triggered! Stopping all monitoring..."
            logging.warning(stop_msg)
            self.ui.add_log(stop_msg, "alert")
            
            # Update UI status
            self.ui.update_status("Shutting Down")
            self.ui.update_capture_status("Stopped")
            self.ui.update_model_status("Unloaded")
            
            if self.start_time:
                duration = datetime.now() - self.start_time
                self.ui.add_log(f"Monitoring duration: {duration}", "info")
            
            # Close UI after a short delay to show final status
            self.ui.root.after(1500, self.ui.root.destroy)
            
        except Exception as e:
            error_msg = f"Error during emergency stop: {e}"
            logging.error(error_msg)
            self.ui.add_error(error_msg)
            # Force quit if error during emergency stop
            self.ui.root.destroy()

    def stop(self):
        """Stop all NIDS processes"""
        self.stop_threads = True
        logging.info("NIDS stopped")
        
        if self.start_time:
            duration = datetime.now() - self.start_time
            self.ui.add_log(f"Monitoring duration: {duration}", "info")
        
        self.ui.update_status("Stopped")
        self.ui.update_capture_status("Stopped")
        self.ui.add_log("NIDS stopped", "info")
        
        # Use after() to schedule UI shutdown from main thread
        self.ui.root.after(100, self.ui.root.quit)

    def run(self):
        """Run the NIDS with UI"""
        try:
            threads = self.start_capture()
            self.ui.start()  # Start UI main loop
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.ui.add_error(f"Runtime error: {e}")
            self.ui.update_status("Error")
            self.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System (Local UI Version)')
    parser.add_argument('--interface', help='Network interface to monitor')
    args = parser.parse_args()
    
    nids = NetworkIDS(interface=args.interface)
    nids.run()