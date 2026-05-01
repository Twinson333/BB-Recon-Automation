# BB-Recon - Bug Bounty Recon Orchestrator

An advanced **bug bounty reconnaissance automation tool** designed to
streamline asset discovery, probing, and vulnerability scanning at
scale.

This tool orchestrates multiple recon utilities into a single workflow
with **resume capability, streaming execution, and modular scanning
options**.

------------------------------------------------------------------------

## Features

-   Streaming Command Execution\
-   Resume Support (.done markers)\
-   HTTP Probing (httpx integration)\
-   Port Scanning (naabu integration)\
-   Nuclei Scanning (Optional)\
-   Crawling Support (hakrawler)\
-   Screenshot Capture (Optional)\
-   Multi-threaded Execution\
-   Graceful Cleanup on Interrupt\
-   Structured Logging

------------------------------------------------------------------------

## Project Structure

``` text
bb-recon/
│── bb-recon.py
│── bb_recon_interface.py
│── install.sh
```

------------------------------------------------------------------------

## Installation

### Clone the repository

``` bash
git clone https://github.com/Twinson333/BB-Recon-Automation.git
cd BB-Recon-Automation
```

### Run installer

``` bash
chmod +x install.sh
./install.sh
```

------------------------------------------------------------------------

## Usage

### Basic Scan

``` bash
python3 bb-recon.py -d example.com
```

### Full Recon

``` bash
python3 bb-recon.py -d example.com --ports --nuclei --screenshots
```

### GUI
``` bash
python3 bb_recon_interface.py
```
------------------------------------------------------------------------

## Output

``` text
output/
├── subdomains.txt
├── live_hosts.json
├── ports.txt
├── nuclei_results.txt
├── endpoints.txt
└── screenshots/
```

------------------------------------------------------------------------

## ⚠️ Disclaimer

This tool is intended for authorized security testing only.

------------------------------------------------------------------------

## 👤 Author

**Antony Esthak Twinson (Cyber Tamarin)**\
Bug Bounty Hunter \| Penetration Tester
