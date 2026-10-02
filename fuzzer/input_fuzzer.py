"""
Improper input validation fuzzing (OWASP API8/API10 territory).

This module never runs a real exploit -- it only sends well-known *detection*
payloads (the same generic strings shipped with Burp Intruder, wfuzz, ffuf,
etc.) and checks whether the target reflects them unescaped or leaks an
internal error, which is the standard non-destructive way to flag a
potential injection point for manual follow-up.
"""
import json
import time
from typing import Any, Dict, List, Optional

import requests

from .config import FuzzConfig
from .analyzer import ResponseAnalyzer, Finding


class InputValidationFuzzer:
    def __init__(self, config: FuzzConfig, analyzer: Optional[ResponseAnalyzer] = None,
                 session: Optional[requests.Session] = None):
        self.config = config
        self.analyzer = analyzer or ResponseAnalyzer()
        self.session = session or requests.Session()
        with open(config.payloads_path, "r") as f:
            self.payloads = json.load(f)

    def _flat_payload_list(self) -> List[Any]:
        flat = []
        for key, val in self.payloads.items():
            if key == "oversized":
                flat.append(val * 500)  # build an actually-oversized string
                continue
            if isinstance(val, list):
                flat.extend(val)
        return flat

    def fuzz_query_params(self, endpoint: str, param_names: List[str], role: Optional[str] = None,
                           method: str = "GET") -> None:
        auth = self.config.auth_kwargs(role)
        base_url = f"{self.config.base_url.rstrip('/')}/{endpoint}"
        for param in param_names:
            for payload in self._flat_payload_list():
                params = {param: payload}
                try:
                    resp = self.session.request(method, base_url, params=params,
                                                  timeout=self.config.timeout,
                                                  verify=self.config.verify_tls, **auth)
                except requests.RequestException as e:
                    print(f"[!] {base_url}?{param}={payload!r} -> connection error: {e}")
                    continue

                self._analyze(endpoint, method, payload, resp)
                if self.config.delay:
                    time.sleep(self.config.delay)

    def fuzz_json_body(self, endpoint: str, base_body: Dict[str, Any], field_names: List[str],
                        role: Optional[str] = None, method: str = "POST") -> None:
        auth = self.config.auth_kwargs(role)
        url = f"{self.config.base_url.rstrip('/')}/{endpoint}"
        for field in field_names:
            for payload in self._flat_payload_list():
                body = dict(base_body)
                body[field] = payload
                try:
                    resp = self.session.request(method, url, json=body,
                                                  timeout=self.config.timeout,
                                                  verify=self.config.verify_tls, **auth)
                except requests.RequestException as e:
                    print(f"[!] {url} field={field} payload={payload!r} -> connection error: {e}")
                    continue

                self._analyze(endpoint, method, payload, resp)
                if self.config.delay:
                    time.sleep(self.config.delay)

    def _analyze(self, endpoint: str, method: str, payload: Any, resp: requests.Response) -> None:
        body_text = resp.text or ""
        self.analyzer.detect_error_leak(endpoint, method, body_text)

        # Reflection check: payload came back byte-for-byte unescaped -> potential
        # XSS/injection point worth manual confirmation.
        if isinstance(payload, str) and payload and payload in body_text:
            self.analyzer.findings.append(Finding(
                category="Input Validation",
                severity="medium",
                endpoint=endpoint,
                method=method,
                detail="Payload was reflected unescaped in the response body (possible XSS/injection point).",
                evidence=payload[:80],
            ))
            print(f"[~] {endpoint}: payload reflected unescaped -> {payload[:40]!r}")

        try:
            json_body = resp.json()
            self.analyzer.detect_sensitive_exposure(endpoint, method, json_body)
        except ValueError:
            pass
