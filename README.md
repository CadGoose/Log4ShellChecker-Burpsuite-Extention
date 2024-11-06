# Enhanced CVE and Log4j Checker
By @CadGoose

## Overview
The **Enhanced CVE and Log4j Checker** is a Burp Suite extension designed to identify specific CVEs and Log4j-related vulnerabilities in HTTP, HTTPS, and WebSocket responses. This extension performs both passive and active scans, provides detailed issue reports, and allows users to export vulnerability data for further analysis.

## Features
- **Passive Scan**: Automatically scans HTTP, HTTPS, and WebSocket responses for specific CVEs and Log4j patterns.
- **Active Scan**: Injects payloads into HTTP requests and analyzes responses to detect exploit attempts.
- **Custom Alerts**: Provides detailed issue reports when potential vulnerabilities are detected.
- **Logging**: Maintains a log of detected vulnerabilities with timestamps.
- **Exportable Reports**: Users can export detected issues to a JSON file for easy sharing and integration with other tools.
- **User Interface**: Includes a custom UI panel in Burp Suite for managing the extension and exporting reports.

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

2. **View and Export Scan Results**:
   - Detected issues will be listed in the Scanner tab under Issues.
   - To export the report, go to the "CVE Checker" tab and click the "Export Report" button to save the report as a JSON file.

## Detection Details
### Passive Scanning
- **Log4Shell Patterns**:
  - `${jndi:ldap://`
  - `${jndi:rmi://`
  - `${jndi:ldaps://`
  - `${jndi:dns://`
  - `${jndi:iiop://`
  - `${jndi:corba://`
  - `${jndi:nds://`
  - `${jndi:nis://`
  - `${jndi:rfc://`

- **Other Log4j-Related Patterns**:
  - `${sys:os.name}`
  - `${env:}`
  - `${sys:}`
  - `${env:AWS_SECRET_ACCESS_KEY}`
  - `${java:version}`
  - `${java:os}`
  - `${env:AWS_SESSION_TOKEN}`
  - `${env:AWS_ACCESS_KEY_ID}`
  - `${main:ARGS}`

### Active Scanning
- **Payloads Injected**:
  - `${jndi:ldap://example.com/a}`
  - `${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://example.com/a}`
  - `${sys:os.name}`
  - `${env:AWS_SECRET_ACCESS_KEY}`
  - `${java:version}`

## Disclaimer
This tool is intended for educational purposes and should be used responsibly. Ensure you have appropriate permissions before scanning any network or application.

## Author
Created by @CadGoose

This project was developed to enhance the capabilities of Burp Suite in identifying specific CVEs and Log4j vulnerabilities and to contribute to the cybersecurity community.

Feel free to contribute or reach out for any suggestions!
