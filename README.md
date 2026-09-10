# Enterprise AI Traffic Proxy & Security Monitor

A custom `mitmproxy` script to monitor enterprise AI prompt traffic, enforce forbidden keyword policies, block unapproved AI services, and stream alert logs to a socket receiver.

## Prerequisites

- Python 3.10 or higher

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/auriete/AI-security-proxy
   cd AI-security-proxy
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. **Replace the address in admin_sim.py with the IP of the LAN device running listener.py.**

1. **Start the Security Proxy:**
   ```
   mitmdump -s .\listener.py -p 9091 -q
   ```

2. **Start the Admin Log Viewer (Works on both local device and other device on the same network):**
   ```
   python admin_sim.py
   ```

