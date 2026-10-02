"""
Authorization / authentication testing.

Covers two OWASP API Top 10 categories:
  API1 - Broken Object Level Authorization (BOLA / IDOR)
  API2 - Broken Authentication
"""
import time
from typing import Dict, Iterable, List, Optional

import requests

from .config import FuzzConfig
from .analyzer import ResponseAnalyzer


class AuthTester:
    def __init__(self, config: FuzzConfig, analyzer: Optional[ResponseAnalyzer] = None,
                 session: Optional[requests.Session] = None):
        self.config = config
        self.analyzer = analyzer or ResponseAnalyzer()
        self.session = session or requests.Session()

    def _request(self, method: str, url: str, role: Optional[str] = None, **kwargs):
        auth = self.config.auth_kwargs(role)
        merged_headers = {**auth["headers"], **kwargs.pop("headers", {})}
        merged_cookies = {**auth["cookies"], **kwargs.pop("cookies", {})}
        return self.session.request(method, url, headers=merged_headers, cookies=merged_cookies,
                                     timeout=self.config.timeout, verify=self.config.verify_tls, **kwargs)

    # ---------- Broken Authentication (API2) ----------

    def test_no_auth(self, endpoint: str, method: str = "GET") -> None:
        """Does the endpoint enforce auth at all?"""
        url = f"{self.config.base_url.rstrip('/')}/{endpoint}"
        try:
            unauth = self._request(method, url, role=None)
        except requests.RequestException as e:
            print(f"[!] {url} -> connection error: {e}")
            return

        # Compare against the first available token, if any, as a rough baseline.
        if self.config.tokens:
            first_role = next(iter(self.config.tokens))
            try:
                authed = self._request(method, url, role=first_role)
            except requests.RequestException:
                return
            self.analyzer.detect_unauthorized_access(
                endpoint, method,
                unauth.status_code, unauth.text,
                authed.status_code, authed.text,
            )
        self.analyzer.detect_error_leak(endpoint, method, unauth.text)

    def test_invalid_token(self, endpoint: str, method: str = "GET") -> None:
        """Tampered / malformed token -- should be rejected, not silently accepted."""
        url = f"{self.config.base_url.rstrip('/')}/{endpoint}"
        garbage_jwt = "eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxfQ."  # classic alg:none tampering test
        try:
            resp = self._request(method, url, role=None,
                                  headers={self.config.auth_header_name: f"Bearer {garbage_jwt}"})
        except requests.RequestException as e:
            print(f"[!] {url} -> connection error: {e}")
            return
        if resp.status_code < 400:
            print(f"[~] {endpoint}: forged/invalid token was accepted -> {resp.status_code}")
            self.analyzer.detect_unauthorized_access(endpoint, method, resp.status_code, resp.text,
                                                       resp.status_code, resp.text)

    # ---------- BOLA / IDOR (API1) ----------

    def test_cross_user_access(self, endpoint_template: str, object_ids_by_owner: Dict[str, Iterable[str]],
                                method: str = "GET") -> None:
        """
        endpoint_template: e.g. "api/users/{id}" or "api/orders/{id}"
        object_ids_by_owner: {"user_a": ["101"], "user_b": ["202"]}
        For every (requester token, someone else's object id) pair, check whether
        access succeeds. Any success is a BOLA finding.
        """
        roles = list(object_ids_by_owner.keys())
        for requester_role in roles:
            if requester_role not in self.config.tokens:
                print(f"[!] No token configured for role '{requester_role}', skipping.")
                continue
            for owner_role, ids in object_ids_by_owner.items():
                if owner_role == requester_role:
                    continue
                for object_id in ids:
                    path = endpoint_template.format(id=object_id)
                    url = f"{self.config.base_url.rstrip('/')}/{path}"
                    try:
                        resp = self._request(method, url, role=requester_role)
                    except requests.RequestException as e:
                        print(f"[!] {url} -> connection error: {e}")
                        continue
                    self.analyzer.detect_bola(endpoint_template, method, object_id,
                                               owner_role, requester_role,
                                               resp.status_code, resp.text)
                    if self.config.delay:
                        time.sleep(self.config.delay)
