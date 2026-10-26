# Network-Traffic-Monitor

A Python script that monitors network traffic and automatically blocks source IP addresses when their packet rate exceeds a user-defined threshold.

## Features

- Monitors live IP packets using Scapy.
- Counts packets received from each source IP.
- Calculates packet rates over time.
- Allows users to set a packet-rate threshold.
- Automatically blocks IP addresses using Linux `iptables`.
- Checks for root privileges before starting.

## Important : After execute the file, if some sites may be slow then reboot your device.

## Requirements

- Python 3
- Kali Linux or another Linux distribution  

## Usage

Run the script with root privileges:

```bash
sudo python3 [file_name].py
```

Enter the packet-rate threshold when prompted. The script will monitor network traffic and attempt to block source IP addresses whose calculated packet rate exceeds the threshold.

## How It Works

1. Captures IP packets using Scapy.
2. Extracts source IP addresses.
3. Counts packets from each IP address.
4. Calculates the packet rate.
5. Compares the rate with the configured threshold.
6. Adds an `iptables` rule to drop matching incoming traffic when the threshold is exceeded.

## Disclaimer

This project is intended for educational purposes and authorized network testing only. Test in a controlled environment, as legitimate devices may also be blocked. The script provides basic threshold-based monitoring and is not a complete DDoS protection solution.
