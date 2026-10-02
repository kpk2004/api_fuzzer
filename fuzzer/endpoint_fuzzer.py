"""
Endpoint discovery + HTTP method fuzzing.

This is the "automate endpoint testing" half of the project: walk a wordlist
against the target, keep anything that isn't a hard 404, then probe each
discovered path with multiple HTTP verbs to catch verb-tampering issues
(e.g. an endpoint that blocks POST but forgets to block PUT/PATCH/DELETE).
"""
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from .config import FuzzConfig
from .analyzer import ResponseAnalyzer

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


@dataclass
class DiscoveredEndpoint:
    path: str
    status: int
    length: int
    allowed_methods: Dict[str, int] = field(default_factory=dict)  # method -> status


class EndpointFuzzer:
    def __init__(self, config: FuzzConfig, analyzer: Optional[ResponseAnalyzer] = None,
                 session: Optional[requests.Session] = None):
        self.config = config
        self.analyzer = analyzer or ResponseAnalyzer()
        self.session = session or requests.Session()

    def _load_wordlist(self) -> List[str]:
        with open(self.config.wordlist_path, "r") as f:
            return [line.strip().lstrip("/") for line in f if line.strip() and not line.startswith("#")]

    def discover(self, role: Optional[str] = None) -> List[DiscoveredEndpoint]:
        """GET every candidate path, keep anything that doesn't 404."""
        found: List[DiscoveredEndpoint] = []
        auth = self.config.auth_kwargs(role)
        for word in self._load_wordlist():
            url = f"{self.config.base_url.rstrip('/')}/{word}"
            try:
                resp = self.session.get(url, timeout=self.config.timeout,
                                         verify=self.config.verify_tls, **auth)
            except requests.RequestException as e:
                print(f"[!] {url} -> connection error: {e}")
                continue

            self.analyzer.detect_error_leak(word, "GET", resp.text)

            if resp.status_code != 404:
                print(f"[+] {resp.status_code}\t{word}\t({len(resp.content)} bytes)")
                found.append(DiscoveredEndpoint(path=word, status=resp.status_code, length=len(resp.content)))

            if self.config.delay:
                time.sleep(self.config.delay)
        return found

    def fuzz_methods(self, endpoints: List[DiscoveredEndpoint], role: Optional[str] = None) -> None:
        """For each discovered endpoint, try every verb and record what's allowed."""
        auth = self.config.auth_kwargs(role)
        for ep in endpoints:
            url = f"{self.config.base_url.rstrip('/')}/{ep.path}"
            for method in METHODS:
                try:
                    resp = self.session.request(method, url, timeout=self.config.timeout,
                                                 verify=self.config.verify_tls, **auth)
                except requests.RequestException as e:
                    print(f"[!] {method} {url} -> connection error: {e}")
                    continue

                ep.allowed_methods[method] = resp.status_code
                self.analyzer.detect_error_leak(ep.path, method, resp.text)

                # A verb that "shouldn't" work (e.g. DELETE) returning 2xx on an
                # endpoint that only advertises GET is worth a human's attention.
                if method in ("PUT", "PATCH", "DELETE") and resp.status_code < 300:
                    print(f"    [~] {ep.path}: unexpected {method} -> {resp.status_code} (verb tampering?)")

                if self.config.delay:
                    time.sleep(self.config.delay)
