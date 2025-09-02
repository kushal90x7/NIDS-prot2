import argparse
import subprocess
import sys

def check_requirements():
    """Check if required packages are installed"""
    try:
        import tkinter
        import scapy
        return True
    except ImportError as e:
        print(f"Missing required package: {e.name}")
        print("Please run: pip install -r requirements.txt")
        return False

def main():
    parser = argparse.ArgumentParser(description='NIDS Runner')
    parser.add_argument('--mode', choices=['local', 'docker'], default='local',
                      help='Run mode: local (with UI) or docker (CLI mode)')
    parser.add_argument('--interface', help='Network interface to monitor')
    args = parser.parse_args()

    if args.mode == 'local':
        # Check requirements for local mode
        if not check_requirements():
            sys.exit(1)
            
        print("Starting NIDS in local mode with UI...")
        from nids_local import NetworkIDS
        nids = NetworkIDS(interface=args.interface)
        nids.run()
    
    else:  # docker mode
        print("Starting NIDS in Docker mode...")
        try:
            subprocess.run(['docker-compose', 'up', '--build'], check=True)
        except subprocess.CalledProcessError:
            print("Error running Docker containers. Make sure Docker is running and you have permissions.")
            sys.exit(1)
        except FileNotFoundError:
            print("Docker not found. Please install Docker and Docker Compose first.")
            sys.exit(1)

if __name__ == "__main__":
    main()