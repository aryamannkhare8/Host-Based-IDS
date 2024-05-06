# Host-Based Intrusion Detection System (IDS)

This repository hosts a simple yet powerful Host-Based Intrusion Detection System (IDS) designed to monitor network traffic, identify suspicious activity based on predefined rules, and send email alerts if suspicious packets are detected. It employs Scapy for packet capture and analysis, and uses Python's email capabilities for notifications.

## Features

- **Packet Capture**: Utilizes Scapy to intercept and analyze network traffic in real-time.
- **Suspicious Activity Detection**: Filters and identifies potential threats based on hard-coded rules related to port numbers and unusually large packet sizes.
- **Email Alerts**: Automatically sends detailed alerts to the system administrator upon detection of suspicious activities.

## Components

The system consists of two main scripts:
1. **Packet Capture and Analysis Script** (`packet_capture.py`):
   - Captures network packets in real-time.
   - Analyzes packets for suspicious properties such as known malicious port numbers or unusually large packet sizes.
2. **Email Notification Script** (`email_alert.py`):
   - Constructs and sends an email alert with detailed information about any detected suspicious activities.

## Dependencies

To run this IDS, you will need:
- Python 3.x
- Scapy
- smtplib for sending emails
- email.mime.text for creating email messages
- datetime for timestamp handling


