# NetworkScanner
A simple Python script for scanning IP ranges and checking open ports using the "scapy" library. It helps identify active devices in a network and scans specific devices for open ports.


## Requirements

- Python 3.x
- scapy library

You can install the necessary dependencies by running:

```bash
pip install scapy
```

# Usage Instructions

Download or Clone the Project:

Using Git:
```bash
git clone https://github.com/Dreaxy96/NetworkScanner.git
cd NetworkScanner
```
Or, alternatively, download the ZIP file from GitHub and extract it.

Run the Script:

Open your terminal or command prompt, navigate to the directory where the NetworkScanner.py file is located, and run the following command:
```bash
python NetworkScanner.py
```
Input the IP Range:

You will be prompted to enter the IP range you wish to scan. For example:
```bash
Enter the IP range to scan (e.g., 192.168.1.1/24): 
```
Select the Device for Port Scanning:

After scanning the IP range, the script will list active devices. You will be prompted to enter the IP address of the device you want to scan for open ports:
```bash
Enter the IP address to scan for open ports:
```
The script will then attempt to detect open ports on that device.

View Results:

The script will display a list of open ports for the selected device, or indicate that no open ports were found.

Example output:
```bash
Active Devices:
IP: 192.168.1.101 | MAC: 00:11:22:33:44:55
IP: 192.168.1.102 | MAC: 00:11:22:33:44:56

Enter the IP address to scan for open ports: 192.168.1.101

Open Ports: [22, 80, 443]
```
License
This project is licensed under the MIT License - see the LICENSE file for details.
