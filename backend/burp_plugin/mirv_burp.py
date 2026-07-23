# -*- coding: utf-8 -*-
"""
MIRV Burp Plugin — sends selected requests to the MIRV bridge.

INSTALL
-------
1. Burp Suite → Extender → Extensions → Add
2. Extension type: Python
3. Select this file (mirv_burp.py)
4. Make sure Jython is installed (Burp → Extender → Options → Python Environment)

CONFIGURE
---------
Set the MIRV bridge URL and (optional) auth token via either:
  * environment variables: MIRV_BRIDGE_URL and MIRV_BURP_TOKEN
    (Burp picks these up from the OS at launch), OR
  * edit the two constants below directly.

USAGE
-----
Right-click any request in Burp (Proxy history, Repeater, Intruder,
Target site map...) → "Send to MIRV". The request + response are
POSTed to ``<MIRV_BRIDGE_URL>/api/burp/ingest`` with the
``X-MIRV-Token`` header when a token is configured.

NOTES
-----
* Pure Jython 2.7 — no extra deps, only the stdlib modules Burp ships.
* Uses urllib2 (Jython 2.7 stdlib) so it works on stock Burp installs.
* Sending happens on the Swing event-dispatch thread for simplicity;
  for high-volume scenarios, run on a worker thread (left as an
  exercise — Burp's IExtensionHelpers is fast enough for ad-hoc use).
"""

# ── Configuration ─────────────────────────────────────────────────
import os as _os
MIRV_BRIDGE_URL = (_os.environ.get("MIRV_BRIDGE_URL") or "http://127.0.0.1:8000").rstrip("/")
MIRV_TOKEN = _os.environ.get("MIRV_BURP_TOKEN") or ""
# You can also hard-set the constants above if env vars are awkward.

# ── Jython / Burp imports ─────────────────────────────────────────
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane
from java.awt.event import ActionListener
from java.util import LinkedList
import json
import urllib2


class BurpExtender(IBurpExtender, IContextMenuFactory):
    """Burp extender that adds a 'Send to MIRV' right-click action."""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("MIRV Bridge")
        callbacks.registerContextMenuFactory(self)
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        self._log("MIRV Bridge loaded → %s" % MIRV_BRIDGE_URL)
        self._log("Right-click a request → 'Send to MIRV'")
        if MIRV_TOKEN:
            self._log("Auth token configured (len=%d)" % len(MIRV_TOKEN))
        else:
            self._log("No auth token — bridge must be in open mode")

    # ── Context menu ─────────────────────────────────────────────
    def createMenuItems(self, invocation):
        menu = LinkedList()
        item = JMenuItem("Send to MIRV", actionPerformed=self._make_handler(invocation))
        menu.add(item)
        return menu

    def _make_handler(self, invocation):
        """Return an ActionListener-style callable bound to this invocation."""
        def handler(event):
            self._send(invocation)
        return handler

    # ── Sending logic ────────────────────────────────────────────
    def _send(self, invocation):
        try:
            sel = invocation.getSelectedMessages()
            if not sel or len(sel) == 0:
                self._log("No message selected")
                return
            count = 0
            for msg in sel:
                try:
                    self._send_one(msg)
                    count += 1
                except Exception as e:
                    self._err("send_one failed: %s" % _safe_str(e))
            self._log("Sent %d request(s) to MIRV" % count)
        except Exception as e:
            self._err("_send failed: %s" % _safe_str(e))

    def _send_one(self, msg):
        """Build the JSON payload from one IHttpRequestResponse and POST it."""
        req_info = self._helpers.analyzeRequest(msg)
        method = req_info.getMethod()
        url = _safe_str(req_info.getUrl())
        headers = [_safe_str(h) for h in req_info.getHeaders()]

        body = ""
        req_bytes = msg.getRequest()
        if req_bytes:
            body_off = req_info.getBodyOffset()
            # req_bytes is a byte[] — slice from body offset
            body = _bytes_to_str(req_bytes[body_off:])

        resp_status = None
        resp_headers = []
        resp_body = ""
        resp_bytes = msg.getResponse()
        if resp_bytes:
            resp_info = self._helpers.analyzeResponse(resp_bytes)
            resp_status = resp_info.getStatusCode()
            resp_headers = [_safe_str(h) for h in resp_info.getHeaders()]
            rbody_off = resp_info.getBodyOffset()
            resp_body = _bytes_to_str(resp_bytes[rbody_off:])

        payload = json.dumps({
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "response_status": resp_status,
            "response_headers": resp_headers,
            "response_body": resp_body,
            "source": "burp",
        })

        req = urllib2.Request(
            MIRV_BRIDGE_URL + "/api/burp/ingest",
            payload,
            {
                "Content-Type": "application/json",
                "X-MIRV-Token": MIRV_TOKEN,
            },
        )
        try:
            resp = urllib2.urlopen(req, timeout=5)
            # drain the response so the socket is released
            _ = resp.read()
        except urllib2.HTTPError as he:
            self._err("HTTP %d from bridge for %s %s" % (he.code, method, url))
        except urllib2.URLError as ue:
            self._err("bridge unreachable (%s) — is MIRV running at %s?" % (
                _safe_str(ue.reason), MIRV_BRIDGE_URL))
        self._log("Sent %s %s" % (method, url))

    # ── Logging helpers (writes to Burp's Extender output tab) ───
    def _log(self, msg):
        try:
            self._stdout.write("[MIRV] " + _safe_str(msg) + "\n")
        except Exception:
            print("[MIRV] " + _safe_str(msg))

    def _err(self, msg):
        try:
            self._stderr.write("[MIRV ERROR] " + _safe_str(msg) + "\n")
        except Exception:
            print("[MIRV ERROR] " + _safe_str(msg))


# ── Jython byte[] helpers ─────────────────────────────────────────
def _bytes_to_str(b):
    """Decode a Jython byte[] (or Java array of byte) into a Python str."""
    if b is None:
        return ""
    # `b` may be a Jython array of signed bytes (-128..127); normalize.
    try:
        # Jython exposes byte arrays like Python bytes in many versions
        return "".join(chr(x & 0xFF) for x in b)
    except TypeError:
        # Already a Java String or Python str
        return _safe_str(b)


def _safe_str(v):
    """Coerce any Java/Jython value into a Python str without raising."""
    try:
        return str(v)
    except Exception:
        try:
            return v.toString()
        except Exception:
            return repr(v)