import unittest
from netscan import NetScan
import json
import os

class TestNetScan(unittest.TestCase):
    def setUp(self):
        self.targets = ["192.168.1.100"]
        self.scan_options = "-sV"
        self.netscan = NetScan(self.targets, self.scan_options)

    def test_scan(self):
        scan_results = self.netscan.scan()
        self.assertIsNotNone(scan_results)
        self.assertIsInstance(scan_results, dict)

    def test_save_results(self):
        scan_results = self.netscan.scan()
        output_file = "test_scan_results.json"
        self.netscan.save_results(scan_results, output_file)
        self.assertTrue(os.path.exists(output_file))
        os.remove(output_file)

    def test_classify_vulnerabilities(self):
        scan_results = self.netscan.scan()
        vulnerabilities = self.netscan.classify_vulnerabilities(scan_results)
        self.assertIsNotNone(vulnerabilities)
        self.assertIsInstance(vulnerabilities, dict)

    def test_classify_cvss(self):
        self.assertEqual(self.netscan.classify_cvss(9.5), "Critical")
        self.assertEqual(self.netscan.classify_cvss(7.5), "High")
        self.assertEqual(self.netscan.classify_cvss(4.5), "Medium")
        self.assertEqual(self.netscan.classify_cvss(2.5), "Low")

    def test_save_vulnerability_report(self):
        scan_results = self.netscan.scan()
        vulnerabilities = self.netscan.classify_vulnerabilities(scan_results)
        output_file = "test_vulnerability_report.txt"
        self.netscan.save_vulnerability_report(vulnerabilities, output_file)
        self.assertTrue(os.path.exists(output_file))
        os.remove(output_file)

if __name__ == "__main__":
    unittest.main()
