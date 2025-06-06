import nmap
import json

class NetScan:
    def __init__(self, targets, scan_options):
        self.targets = targets
        self.scan_options = scan_options
        self.nm = nmap.PortScanner()

    def scan(self):
        scan_results = {}
        for target in self.targets:
            try:
                self.nm.scan(target, arguments=self.scan_options)
                scan_results[target] = self.nm.get_nmap_last_output()
            except Exception as e:
                print(f"Error scanning {target}: {e}")
        return scan_results

    def save_results(self, scan_results, output_file):
        with open(output_file, 'w') as f:
            json.dump(scan_results, f, indent=4)

    def classify_vulnerabilities(self, scan_results):
        # Simulate vulnerability classification based on CVSS scores
        vulnerabilities = {}
        for target, result in scan_results.items():
            vulnerabilities[target] = []
            # Parse the Nmap output to extract service information
            for line in result.splitlines():
                if "open" in line:
                    service = line.split()[2]
                    # Simulate CVSS score retrieval (replace with actual logic)
                    cvss_score = 5.0
                    vulnerabilities[target].append({
                        "service": service,
                        "cvss_score": cvss_score,
                        "classification": self.classify_cvss(cvss_score)
                    })
        return vulnerabilities

    def classify_cvss(self, score):
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"

    def save_vulnerability_report(self, vulnerabilities, output_file):
        with open(output_file, 'w') as f:
            for target, vulns in vulnerabilities.items():
                f.write(f"Target: {target}\n")
                for vuln in vulns:
                    f.write(f"  Service: {vuln['service']}, CVSS Score: {vuln['cvss_score']}, Classification: {vuln['classification']}\n")

def main():
    targets = ["192.168.1.100"]
    scan_options = "-sV"
    output_file = "scan_results.json"
    vulnerability_report_file = "vulnerability_report.txt"

    netscan = NetScan(targets, scan_options)
    scan_results = netscan.scan()
    netscan.save_results(scan_results, output_file)
    vulnerabilities = netscan.classify_vulnerabilities(scan_results)
    netscan.save_vulnerability_report(vulnerabilities, vulnerability_report_file)

if __name__ == "__main__":
    main()
