# Burp Suite Extension for CVE and Log4j Checking
By @CadGoose

## Overview
This Burp Suite extension is designed to check for specific CVEs and Log4j-related vulnerabilities in HTTP, HTTPS, and WebSocket responses during passive and active scans. The current implementation focuses on detecting CVE-2021-44228 (Log4Shell) and other Log4j-related vulnerabilities.

## Features
- **Passive Scan**: Automatically scans HTTP, HTTPS, and WebSocket responses for specific CVEs and Log4j patterns.
- **Active Scan**: Injects payloads into HTTP requests and analyzes responses to detect vulnerability exploitation.
- **Custom Alerts**: Provides detailed issue reports when potential vulnerabilities are detected.

## Prerequisites
- **Burp Suite**: Professional or Community Edition
- **Jython**: A Python interpreter written in Java, which can be downloaded from [Jython.org](http://www.jython.org/downloads.html).

## Installation
1. **Download and Install Jython**:
   - Download Jython from [Jython.org](http://www.jython.org/downloads.html).
   - Follow the instructions to install Jython.

2. **Add the Extension to Burp Suite**:
   - Open Burp Suite.
   - Go to the Extender tab.
   - Click on the Extensions tab within the Extender tab.
   - Click on Add, select the extension type as "Python", and choose the `burp_extension.py` file.

## Usage
1. **Run Burp Suite**:
   - The extension will start scanning for the specified CVEs and Log4j patterns when passive scanning HTTP, HTTPS, and WebSocket responses.
   - For active scanning, the extension will inject payloads and analyze responses to detect exploit attempts.

2. **Review Scan Results**:
   - Detected issues will be listed in the Scanner tab under Issues.

## Disclaimer
This tool is intended for educational purposes and should be used responsibly. Ensure you have appropriate permissions before scanning any network or application.

## Author
Created by @CadGoose

This project was developed to enhance the capabilities of Burp Suite in identifying specific CVEs and Log4j vulnerabilities and to contribute to the cybersecurity community.

Feel free to contribute or reach out for any suggestions!
