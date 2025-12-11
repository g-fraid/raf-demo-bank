# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab, IHttpListener
from java.awt import BorderLayout, Dimension
from java.awt import GridBagLayout, GridBagConstraints, Insets
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JScrollPane, JButton, JCheckBox, JTabbedPane, BorderFactory
from javax.swing import BoxLayout
from java.awt.event import ActionListener
from java.lang import String
import json
import hmac
import hashlib
from collections import OrderedDict


class BurpExtender(IBurpExtender, ITab, IHttpListener):

    #
    # IBurpExtender implementation
    #
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request-Signer-Extension")

        # UI state
        self._init_ui()

        # Register as tab and HTTP listener
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

        self.log("Request-Signer-Extension loaded.")
        self.log("Configure HMAC secret, URL filter, parameter order and tool scope, then resend requests.")

    #
    # ITab implementation
    #
    def getTabCaption(self):
        return "Request-Signer-Extension"

    def getUiComponent(self):
        return self.mainPanel

    #
    # IHttpListener implementation
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if not messageIsRequest:
                return

            if not self._is_tool_in_scope(toolFlag):
                return

            if not self._is_url_in_scope(messageInfo):
                return

            self._resign_request(messageInfo, toolFlag)
        except Exception as e:
            # Do not break Burp flow on errors, just log them
            try:
                self.log("ERROR in processHttpMessage: %s" % e)
            except:
                pass

    #
    # UI creation
    #
    def _init_ui(self):
        self.mainPanel = JPanel(BorderLayout())

        # Top configuration panel
        configPanel = JPanel()
        configPanel.setLayout(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 4, 4, 4)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0

        row = 0

        # HMAC secret
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 0.0
        configPanel.add(JLabel("HMAC secret:"), gbc)

        self.txtSecret = JTextField()
        gbc.gridx = 1
        gbc.gridy = row
        gbc.weightx = 1.0
        configPanel.add(self.txtSecret, gbc)
        row += 1

        # URL filter
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 0.0
        configPanel.add(JLabel("Target URL contains (comma separated):"), gbc)

        self.txtUrlFilter = JTextField()
        gbc.gridx = 1
        gbc.gridy = row
        gbc.weightx = 1.0
        configPanel.add(self.txtUrlFilter, gbc)
        row += 1

        # Parameter order
        gbc.gridx = 0
        gbc.gridy = row
        gbc.weightx = 0.0
        configPanel.add(JLabel("Parameter order (comma separated):"), gbc)

        self.txtParamOrder = JTextField("senderIban,receiverIban,amount")
        gbc.gridx = 1
        gbc.gridy = row
        gbc.weightx = 1.0
        configPanel.add(self.txtParamOrder, gbc)
        row += 1

        # Tool scope
        scopePanel = JPanel()
        scopePanel.setLayout(BoxLayout(scopePanel, BoxLayout.X_AXIS))
        scopePanel.setBorder(BorderFactory.createTitledBorder("Tool scope"))

        self.chkProxy = JCheckBox("Proxy", True)
        self.chkRepeater = JCheckBox("Repeater", True)
        self.chkIntruder = JCheckBox("Intruder", True)
        self.chkScanner = JCheckBox("Scanner", False)

        scopePanel.add(self.chkProxy)
        scopePanel.add(self.chkRepeater)
        scopePanel.add(self.chkIntruder)
        scopePanel.add(self.chkScanner)

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        configPanel.add(scopePanel, gbc)
        row += 1

        configPanel.setBorder(BorderFactory.createTitledBorder("Request signing configuration"))

        # Middle: test panel
        testPanel = JPanel()
        testPanel.setLayout(GridBagLayout())
        gbc2 = GridBagConstraints()
        gbc2.insets = Insets(4, 4, 4, 4)
        gbc2.fill = GridBagConstraints.BOTH
        gbc2.weightx = 1.0

        r = 0
        gbc2.gridx = 0
        gbc2.gridy = r
        gbc2.weightx = 0.0
        gbc2.fill = GridBagConstraints.HORIZONTAL
        testPanel.add(JLabel("Sample JSON body for test:"), gbc2)
        r += 1

        self.txtTestBody = JTextArea(6, 60)
        self.txtTestBody.setLineWrap(True)
        self.txtTestBody.setWrapStyleWord(True)
        scrollTest = JScrollPane(self.txtTestBody)
        gbc2.gridx = 0
        gbc2.gridy = r
        gbc2.weightx = 1.0
        gbc2.weighty = 1.0
        gbc2.fill = GridBagConstraints.BOTH
        testPanel.add(scrollTest, gbc2)
        r += 1

        btnPanel = JPanel()
        self.btnTestSign = JButton("Compute test signature", actionPerformed=self._on_test_signature)
        btnPanel.add(self.btnTestSign)

        gbc2.gridx = 0
        gbc2.gridy = r
        gbc2.weightx = 0.0
        gbc2.weighty = 0.0
        gbc2.fill = GridBagConstraints.NONE
        testPanel.add(btnPanel, gbc2)
        r += 1

        gbc2.gridx = 0
        gbc2.gridy = r
        gbc2.fill = GridBagConstraints.HORIZONTAL
        testPanel.add(JLabel("Result HMAC (hex):"), gbc2)
        r += 1

        self.txtTestResult = JTextField()
        self.txtTestResult.setEditable(False)
        gbc2.gridx = 0
        gbc2.gridy = r
        gbc2.fill = GridBagConstraints.HORIZONTAL
        testPanel.add(self.txtTestResult, gbc2)
        r += 1

        testPanel.setBorder(BorderFactory.createTitledBorder("Signature test"))

        # Bottom: debug log
        logPanel = JPanel(BorderLayout())
        logPanel.setBorder(BorderFactory.createTitledBorder("Debug log"))

        self.txtLog = JTextArea()
        self.txtLog.setEditable(False)
        self.txtLog.setLineWrap(True)
        self.txtLog.setWrapStyleWord(True)
        scrollLog = JScrollPane(self.txtLog)
        scrollLog.setPreferredSize(Dimension(800, 200))

        btnClearLog = JButton("Clear log", actionPerformed=self._on_clear_log)

        logPanel.add(scrollLog, BorderLayout.CENTER)
        logPanel.add(btnClearLog, BorderLayout.SOUTH)

        # Compose main panel
        centerPanel = JPanel()
        centerPanel.setLayout(BorderLayout())
        centerPanel.add(configPanel, BorderLayout.NORTH)
        centerPanel.add(testPanel, BorderLayout.CENTER)

        self.mainPanel.add(centerPanel, BorderLayout.CENTER)
        self.mainPanel.add(logPanel, BorderLayout.SOUTH)

    #
    # UI callbacks
    #
    def _on_clear_log(self, event):
        self.txtLog.setText("")

    def _on_test_signature(self, event):
        try:
            secret = self._get_hmac_secret()
            if not secret:
                self.log("Test: HMAC secret is empty.")
                self.txtTestResult.setText("")
                return

            body_text = self.txtTestBody.getText()
            if not body_text:
                self.log("Test: sample body is empty.")
                self.txtTestResult.setText("")
                return

            try:
                data = json.loads(body_text)
            except Exception as e:
                self.log("Test: failed to parse sample JSON body: %s" % e)
                self.txtTestResult.setText("")
                return

            param_names = self._get_param_order()
            if not param_names:
                self.log("Test: parameter order is empty.")
                self.txtTestResult.setText("")
                return

            payload = OrderedDict()
            for name in param_names:
                if name not in data:
                    self.log("Test: parameter '%s' not present in JSON body." % name)
                    self.txtTestResult.setText("")
                    return
                payload[name] = data[name]

            payload_json = json.dumps(payload, separators=(",", ":"))
            mac = hmac.new(secret.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256).hexdigest()
            self.txtTestResult.setText(mac)
            self.log("Test: computed HMAC for payload JSON: %s" % payload_json)
        except Exception as e:
            self.log("ERROR in test signature: %s" % e)
            self.txtTestResult.setText("")

    #
    # Helpers: configuration
    #
    def _get_hmac_secret(self):
        s = self.txtSecret.getText()
        if s is None:
            return ""
        return s.strip()

    def _get_url_filters(self):
        raw = self.txtUrlFilter.getText()
        if raw is None:
            return []
        parts = [p.strip() for p in raw.split(",")]
        return [p for p in parts if p]

    def _get_param_order(self):
        raw = self.txtParamOrder.getText()
        if raw is None:
            return []
        parts = [p.strip() for p in raw.split(",")]
        return [p for p in parts if p]

    def _is_tool_in_scope(self, toolFlag):
        cb = self.callbacks

        if self.chkProxy.isSelected() and toolFlag == cb.TOOL_PROXY:
            return True
        if self.chkRepeater.isSelected() and toolFlag == cb.TOOL_REPEATER:
            return True
        if self.chkIntruder.isSelected() and toolFlag == cb.TOOL_INTRUDER:
            return True
        if self.chkScanner.isSelected() and toolFlag == cb.TOOL_SCANNER:
            return True

        return False

    def _is_url_in_scope(self, messageInfo):
        try:
            filters = self._get_url_filters()
            if not filters:
                # If no filters are set, treat as out-of-scope to be explicit.
                return False

            req = messageInfo.getRequest()
            if req is None:
                return False

            analyzed = self.helpers.analyzeRequest(messageInfo)
            url = analyzed.getUrl()
            if url is None:
                return False

            # java.net.URL -> string
            url_str = url.toString()
            url_lc = url_str.lower()

            for f in filters:
                if f.lower() in url_lc:
                    return True

            return False
        except Exception as e:
            self.log("ERROR in _is_url_in_scope: %s" % e)
            return False

    #
    # Core resign logic
    #
    def _resign_request(self, messageInfo, toolFlag):
        secret = self._get_hmac_secret()
        if not secret:
            # Secret is mandatory for signing
            return

        req_bytes = messageInfo.getRequest()
        if req_bytes is None:
            return

        req_str = self.helpers.bytesToString(req_bytes)
        analyzed = self.helpers.analyzeRequest(messageInfo)
        body_offset = analyzed.getBodyOffset()
        headers = list(analyzed.getHeaders())

        body = req_str[body_offset:]
        body_stripped = body.strip()

        if not body_stripped:
            # Nothing to sign
            return

        # This extension targets JSON bodies
        if not body_stripped.startswith("{"):
            return

        try:
            data = json.loads(body_stripped)
        except Exception as e:
            self.log("Failed to parse JSON body for signing: %s" % e)
            return

        param_names = self._get_param_order()
        if not param_names:
            # Parameter order is mandatory to build canonical payload
            return

        # Build canonical payload object in given order
        payload = OrderedDict()
        for name in param_names:
            if name not in data:
                self.log("Parameter '%s' not present in JSON body, skipping request." % name)
                return
            payload[name] = data[name]

        payload_json = json.dumps(payload, separators=(",", ":"))
        mac = hmac.new(secret.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256).hexdigest()

        # Set/overwrite signature field in JSON body
        data["signature"] = mac

        # Re-serialize full body (actual request body)
        new_body = json.dumps(data, separators=(",", ":"))

        # Remove Content-Length header (if present); it will be recalculated
        new_headers = []
        for h in headers:
            h_lc = h.lower()
            if h_lc.startswith("content-length:"):
                continue
            new_headers.append(h)

        new_req = self.helpers.buildHttpMessage(new_headers, new_body.encode("utf-8"))
        messageInfo.setRequest(new_req)

        try:
            url = analyzed.getUrl()
            if url is not None:
                url_str = url.toString()
            else:
                url_str = "<unknown>"

            self.log("Signed request for URL: %s (toolFlag=%s)" % (url_str, toolFlag))
            self.log("Payload JSON: %s" % payload_json)
            self.log("Signature: %s" % mac)
        except Exception as e:
            self.log("ERROR while logging signed request: %s" % e)

    #
    # Logging helper
    #
    def log(self, text):
        try:
            if text is None:
                return
            self.txtLog.append(str(text) + "\n")
            self.txtLog.setCaretPosition(self.txtLog.getDocument().getLength())
        except:
            pass
