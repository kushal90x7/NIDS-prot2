# Network Intrusion Detection System (NIDS) with Machine Learning

A real-time network intrusion detection system that uses machine learning to detect potential network attacks and anomalies.

## Features

- Real-time network packet capture and analysis
- Machine Learning-based attack detection using Random Forest
- Support for multiple attack detection (DoS, Port Scanning)
- Feature extraction from network packets
- Live traffic monitoring and alerting
- Detailed logging and reporting
- Model training with balanced dataset (normal + synthetic attack data)
- Containerized deployment for easy demonstration

## Project Structure

```
nids_project/
├── data/
│   ├── raw/           # Raw captured network traffic
│   └── processed/     # Processed features and datasets
├── models/            # Trained ML models
├── logs/             # System and detection logs
├── src/              # Source code
│   ├── __init__.py
│   ├── nids.py       # Main NIDS implementation
│   ├── ml_model.py   # Machine learning components
│   ├── feature_extractor.py # Network feature extraction
│   ├── collect_data.py     # Data collection script
│   ├── train_model.py      # Model training script
│   └── simulate_attacks.py # Attack traffic simulator
├── Dockerfile        # Main NIDS container
├── Dockerfile.generator    # Traffic/Attack generator container
├── docker-compose.yml     # Multi-container orchestration
├── run.sh           # Linux/MacOS startup script
└── run.bat          # Windows startup script
```

## Requirements

- Docker Engine
- Docker Compose
- X11 server for GUI:
  - **Windows**: VcXsrv
    1. Download and install [VcXsrv](https://sourceforge.net/projects/vcxsrv/)
    2. Launch XLaunch from Start Menu
    3. Choose "Multiple windows" and Display number 0
    4. Select "Start no client"
    5. In Extra settings, check "Disable access control"
    6. Save configuration and finish
  
  - **MacOS**: XQuartz
    1. Install XQuartz: `brew install --cask xquartz` or download from [XQuartz.org](https://www.xquartz.org/)
    2. Log out and log back in to complete installation
    3. Open XQuartz from Applications/Utilities
    4. In XQuartz Preferences -> Security, enable "Allow connections from network clients"
    5. Restart XQuartz
  
  - **Linux**: Built-in X11
    - Ubuntu/Debian: `sudo apt-get install x11-xserver-utils`
    - Fedora: `sudo dnf install xorg-x11-server-utils`

## Quick Start (Docker)

1. Install Docker and Docker Compose
2. Set up X11 server using the instructions above for your OS
3. Run the NIDS:

```bash
# On Windows
run.bat

# On Linux/MacOS
chmod +x run.sh  # Make script executable
./run.sh
```

The system will start three containers:
- NIDS Monitor: Main detection system with GUI
- Traffic Generator: Generates normal network traffic
- Attack Simulator: Simulates attack patterns

## Manual Installation (Without Docker)

1. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate     # Windows
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Collect training data:
```bash
python src/collect_data.py
```

2. Train the model:
```bash
python src/train_model.py
```

3. Start the NIDS:
```bash
python src/nids.py
```

4. (Optional) Simulate attacks:
```bash
python src/simulate_attacks.py --attack-type all
```

## Docker Container Details

### NIDS Monitor Container
- Runs the main NIDS application with GUI
- Monitors network traffic in real-time
- Displays alerts and statistics

### Traffic Generator Container
- Generates normal network traffic
- Helps build baseline behavior
- Runs for 5 minutes by default

### Attack Simulator Container
- Simulates various attack patterns
- Supports DoS and port scanning attacks
- Configurable attack duration and intensity

## Attack Detection Capabilities

1. DoS (Denial of Service) Attacks:
   - High-volume traffic patterns
   - Rapid connection attempts
   - SYN flood detection

2. Port Scanning:
   - Sequential port scanning
   - SYN scanning
   - Rapid port enumeration

## Logging and Alerts

The system logs all detected intrusion attempts in `logs/intrusion_detection.log` with:
- Timestamp
- Source IP and Port
- Destination IP and Port
- Protocol
- Attack type
- Confidence score



