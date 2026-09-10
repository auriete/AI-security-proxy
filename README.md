# Enterprise AI Traffic Proxy & Security Monitor

A custom `mitmproxy` script to monitor enterprise AI prompt traffic, enforce forbidden keyword policies, block unapproved AI services, and stream alert logs to a socket receiver.

## Prerequisites

- Python 3.10 or higher

## Installation

1. Clone the repository:
   ```
   git clone [https://github.com/](https://github.com/)<your-username>/mitmproxy-security-proxy.git
   cd mitmproxy-security-proxy
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

2. **Start the Security Proxy:**
   ```
   mitmdump -s .\listener.py -p 9091 -q
   ```

1. **Start the Admin Log Viewer:**
   ```
   python admin_sim.py
   ```
