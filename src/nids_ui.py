import tkinter as tk
from tkinter import ttk, scrolledtext
import queue
import threading
import time
from datetime import datetime

class NIDSUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Intrusion Detection System")
        self.root.geometry("800x600")
        
        # Message queues
        self.log_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.error_queue = queue.Queue()
        
        # Emergency stop callback
        self.emergency_stop_callback = None
        
        self._init_ui()
        self._start_update_thread()
    
    def _init_ui(self):
        """Initialize the UI components"""
        # Set window icon and style
        style = ttk.Style()
        style.configure("Alert.TLabel", foreground="red")
        style.configure("Success.TLabel", foreground="green")
        
        # Create main container with tabs
        self.tabControl = ttk.Notebook(self.root)
        
        # Main monitoring tab
        self.monitor_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.monitor_tab, text='📊 Monitor')
        
        # Alerts tab with counter
        self.alerts_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.alerts_tab, text='🚨 Alerts (0)')
        
        # Errors tab with counter
        self.errors_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.errors_tab, text='⚠️ Errors (0)')
        
        # Port Activity tab
        self.ports_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.ports_tab, text='🔌 Port Activity')
        
        self.tabControl.pack(expand=1, fill="both")
        
        # Setup all tabs
        self._setup_monitor_tab(self.monitor_tab)
        self._setup_alerts_tab(self.alerts_tab)
        self._setup_errors_tab(self.errors_tab)
        self._setup_ports_tab(self.ports_tab)
        
        # Emergency Stop Button Frame (above status bar)
        self._setup_emergency_stop()
        
        # Bottom status bar with multiple sections
        self._setup_status_bar()

    def _setup_monitor_tab(self, parent):
        """Setup the monitoring tab with enhanced statistics"""
        # Main stats panel
        stats_frame = ttk.LabelFrame(parent, text="System Statistics", padding="5")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Statistics grid
        self.packets_count = tk.StringVar(value="0")
        self.alerts_count = tk.StringVar(value="0")
        self.errors_count = tk.StringVar(value="0")
        
        # Stats layout
        ttk.Label(stats_frame, text="Packets Analyzed:").grid(row=0, column=0, padx=5, pady=2)
        ttk.Label(stats_frame, textvariable=self.packets_count).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(stats_frame, text="Alerts Detected:").grid(row=0, column=2, padx=5, pady=2)
        ttk.Label(stats_frame, textvariable=self.alerts_count, style="Alert.TLabel").grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Label(stats_frame, text="Errors:").grid(row=0, column=4, padx=5, pady=2)
        ttk.Label(stats_frame, textvariable=self.errors_count).grid(row=0, column=5, padx=5, pady=2)
        
        # Console output
        console_frame = ttk.LabelFrame(parent, text="Live Network Traffic", padding="5")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add text tags for formatting
        self.log_text.tag_configure("timestamp", foreground="#666666")
        self.log_text.tag_configure("info", foreground="#000000")
        self.log_text.tag_configure("alert", foreground="#FF0000")
        self.log_text.tag_configure("success", foreground="#008000")

    def _setup_alerts_tab(self, parent):
        """Setup the alerts tab"""
        self.alerts_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD)
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add custom tags for formatting
        self.alerts_text.tag_configure("alert", foreground="red")
        self.alerts_text.tag_configure("timestamp", foreground="blue")
    
    def _setup_errors_tab(self, parent):
        """Setup the errors tab"""
        self.errors_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD)
        self.errors_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add custom tags for formatting
        self.errors_text.tag_configure("error", foreground="red")
        self.errors_text.tag_configure("timestamp", foreground="blue")

    def _setup_ports_tab(self, parent):
        """Setup the ports monitoring tab"""
        # Port activity frame
        frame = ttk.LabelFrame(parent, text="Active Ports Monitor", padding="5")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Port list with columns
        columns = ('port', 'protocol', 'connections', 'last_activity')
        self.ports_tree = ttk.Treeview(frame, columns=columns, show='headings')
        
        # Define column headings
        self.ports_tree.heading('port', text='Port Number')
        self.ports_tree.heading('protocol', text='Protocol')
        self.ports_tree.heading('connections', text='Connections')
        self.ports_tree.heading('last_activity', text='Last Activity')
        
        # Column widths
        self.ports_tree.column('port', width=100)
        self.ports_tree.column('protocol', width=100)
        self.ports_tree.column('connections', width=100)
        self.ports_tree.column('last_activity', width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Store port activity data
        self.port_activity = {}

    def _setup_emergency_stop(self):
        """Setup stop button"""
        stop_frame = ttk.Frame(self.root)
        stop_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
        
        # Create a styled stop button with grey color
        style = ttk.Style()
        style.configure("Stop.TButton",
                      font=('Helvetica', 10, 'bold'),
                      padding=10)
        
        self.stop_button = ttk.Button(
            stop_frame,
            text="⏹ STOP",
            style="Stop.TButton",
            command=self._handle_emergency_stop
        )
        self.stop_button.pack(side=tk.RIGHT, padx=10)
        
        # Add keyboard shortcut (Ctrl+Q) for stop
        self.root.bind('<Control-q>', lambda e: self._handle_emergency_stop())
    
    def _handle_emergency_stop(self):
        """Handle emergency stop button click"""
        if self.emergency_stop_callback:
            # Add visual feedback
            self.stop_button.state(['disabled'])
            self.add_log("Emergency stop triggered!", "alert")
            self.update_status("Emergency Stopping...")
            
            # Call the emergency stop callback
            self.emergency_stop_callback()
    
    def set_emergency_stop_callback(self, callback):
        """Set the callback function for emergency stop"""
        self.emergency_stop_callback = callback

    def _setup_status_bar(self):
        """Setup enhanced status bar"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status indicators
        self.status_var = tk.StringVar(value="Status: Ready")
        self.capture_status = tk.StringVar(value="Capture: Stopped")
        self.model_status = tk.StringVar(value="Model: Not Loaded")
        
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        ttk.Separator(status_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=2)
        ttk.Label(status_frame, textvariable=self.capture_status).pack(side=tk.LEFT, padx=5)
        ttk.Separator(status_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=2)
        ttk.Label(status_frame, textvariable=self.model_status).pack(side=tk.LEFT, padx=5)

    def _start_update_thread(self):
        """Start the UI update thread"""
        def update_ui():
            while True:
                try:
                    # Update log messages
                    while not self.log_queue.empty():
                        timestamp, msg, level = self.log_queue.get_nowait()
                        self.log_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
                        self.log_text.insert(tk.END, f"{msg}\n", level)
                        self.log_text.see(tk.END)
                    
                    # Update alerts
                    while not self.alert_queue.empty():
                        alert = self.alert_queue.get_nowait()
                        self._add_alert(alert)
                    
                    # Update errors
                    while not self.error_queue.empty():
                        error = self.error_queue.get_nowait()
                        self._add_error(error)
                    
                    time.sleep(0.1)
                except Exception as e:
                    print(f"UI Update Error: {e}")
        
        update_thread = threading.Thread(target=update_ui, daemon=True)
        update_thread.start()

    def _add_alert(self, alert):
        """Add an alert to the alerts tab"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.alerts_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.alerts_text.insert(tk.END, "ALERT: ", "alert")
        self.alerts_text.insert(tk.END, f"{alert}\n")
        self.alerts_text.see(tk.END)
        
        # Update alerts count
        current_count = int(self.alerts_count.get())
        new_count = current_count + 1
        self.alerts_count.set(str(new_count))
        self.tabControl.tab(1, text=f'🚨 Alerts ({new_count})')

    def _add_error(self, error):
        """Add an error to the errors tab"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.errors_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self.errors_text.insert(tk.END, "ERROR: ", "error")
        self.errors_text.insert(tk.END, f"{error}\n")
        self.errors_text.see(tk.END)
        
        # Update error count
        current_count = int(self.errors_count.get())
        new_count = current_count + 1
        self.errors_count.set(str(new_count))
        self.tabControl.tab(2, text=f'⚠️ Errors ({new_count})')

    def update_port_activity(self, port, protocol, src_ip=None, dst_ip=None):
        """Update port activity information"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        port_key = f"{port}-{protocol}"
        
        if port_key not in self.port_activity:
            self.port_activity[port_key] = {
                'connections': 1,
                'last_activity': current_time
            }
            # Add new row to treeview
            self.ports_tree.insert('', tk.END, values=(port, protocol, 1, current_time))
        else:
            # Update existing row
            self.port_activity[port_key]['connections'] += 1
            self.port_activity[port_key]['last_activity'] = current_time
            
            # Find and update the tree item
            for item in self.ports_tree.get_children():
                if self.ports_tree.item(item)['values'][0] == port:
                    self.ports_tree.item(item, values=(
                        port,
                        protocol,
                        self.port_activity[port_key]['connections'],
                        current_time
                    ))
                    break

    def add_log(self, message, level="info"):
        """Add a formatted message to the log queue"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put((timestamp, message, level))

    def add_alert(self, alert_data):
        """Add an alert to the alert queue"""
        self.alert_queue.put(alert_data)
    
    def add_error(self, error_message):
        """Add an error to the error queue"""
        self.error_queue.put(error_message)
    
    def update_status(self, status):
        """Update the status bar"""
        self.status_var.set(f"Status: {status}")
    
    def update_packets_count(self, count):
        """Update the packets analyzed count"""
        self.packets_count.set(f"Packets Analyzed: {count}")
    
    def update_capture_status(self, status):
        """Update capture status in status bar"""
        self.capture_status.set(f"Capture: {status}")

    def update_model_status(self, status):
        """Update model status in status bar"""
        self.model_status.set(f"Model: {status}")

    def start(self):
        """Start the UI main loop"""
        self.root.mainloop()
    
    def stop(self):
        """Stop the UI"""
        self.root.quit()