# Netscan


Netscan is a Python-based tool for automating network scans using Nmap and classifying vulnerabilities based on CVSS scores. This tool helps security professionals and network administrators identify potential vulnerabilities in their networks and prioritize remediation efforts.

## Features
* **Automated Network Scanning**: Uses Nmap to perform network scans and identify open ports, services, and operating systems.
* **CVSS Scoring**: Classifies vulnerabilities based on CVSS scores, providing a standardized way to assess vulnerability severity.
* **Customizable**: Allows users to customize scan options, targets, and CVSS score thresholds.

## Requirements
* **Python 3.x**: Nmap-Auto is written in Python 3.x and requires a compatible version to run.
* **python-nmap**: The tool uses the `python-nmap` library to interact with Nmap.
* **Nmap**: Nmap must be installed on the system and accessible from the command line.

## Installation
1. **Clone the Repository**: `git clone https:                                         
2. **Install Dependencies**: `pip install -r requirements.txt`
3. **Run the Script**: `python src/nmap_scanner.py`

        
1. **Configure Targets**: Edit `config/targets.txt` to specify the targets for scanning.
2. **Customize Scan Options**: Edit `config/settings.py` to customize scan options and CVSS score thresholds.
3. **Run the Scan**: Execute `python src/nmap_scanner.py` to perform the scan and generate reports.

## Output
The tool generates two output files:

* **scan_results.json**: A JSON file containing the raw scan results.
* **vulnerability_report.txt**: A human-readable report summarizing the vulnerabilities and their classifications.

## Contributing
Contributions are welcome! If you'd like to contribute to Nmap-Auto, please fork the repository and submit a pull request.

## License
Nmap-Auto is licensed under the [MIT License](LICENSE).
