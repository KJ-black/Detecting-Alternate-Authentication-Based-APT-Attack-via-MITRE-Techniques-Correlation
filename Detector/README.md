# APT Detector
The aim of this program is to discover C&C and lateral movement behaviors by analyzing connection and system logs collected by an ELK server.

## Usage
1. Configure your ELK server's info in `Credentials/config.py`
2. Configure some basic info in `APT_detector.py` such as `hosts`, `ip2host`, ...
3. `python APT_detector.py`