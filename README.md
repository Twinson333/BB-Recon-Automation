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

### GUI (recommended)
``` bash
python3 bb_recon_interface.py
```
------------------------------------------------------------------------

## Output

``` text
output/
├── logs
├── nuclei_results.txt
├── out
│   ├── admin_urls.txt
│   ├── api_endpoints.txt
│   ├── auth_urls.txt
│   ├── graphql_endpoints.txt
│   ├── interesting_files.txt
│   ├── javascript_files.txt
│   ├── json_urls.txt
│   ├── live_metadata.txt
│   ├── live_urls.txt
│   ├── nuclei_high_signal_targets.txt
│   ├── nuclei_targets.txt
│   ├── parameterized_urls_clean.txt
│   ├── params_urls.txt
│   ├── redirect_candidates.txt
│   ├── unique_parameters.txt
│   └── upload_urls.txt
├── raw
│   ├── all_urls.txt
│   ├── archive_urls.txt
│   ├── arjun_output.txt
│   ├── crawl_urls.txt
│   ├── open_ports.txt
│   ├── resolved_subdomains.txt
│   └── subdomains.txt
├── summary.json
├── summary.md
└── tmp
```

------------------------------------------------------------------------

## ⚠️ Disclaimer

This tool is intended for authorized security testing only.

------------------------------------------------------------------------

## 👤 Author

**Antony Esthak Twinson (Cyber Tamarin)**\
Bug Bounty Hunter \| Penetration Tester
