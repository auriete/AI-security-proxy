# Enterprise AI Traffic Proxy & Security Monitor

A custom `mitmproxy` script to monitor enterprise AI prompt traffic, enforce forbidden keyword policies, block unapproved AI services, and stream alert logs to a socket receiver.

## Prerequisites

- Python 3.10 or higher

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/auriete/AI-security-proxy
   cd mitmproxy-security-proxy
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Start the Admin Log Viewer:**
   ```bash
   python admin_sim.py
   ```

2. **Start the Security Proxy:**
   ```bash
   mitmdump -s listener.py
   ```