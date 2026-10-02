"""
Shared configuration object passed between fuzzer modules.
"""
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class FuzzConfig:
    base_url: str                                  # e.g. "https://api.target.com"
    wordlist_path: str = "wordlists/common_endpoints.txt"
    payloads_path: str = "payloads/injection_payloads.json"
    timeout: float = 8.0
    delay: float = 0.0                              # seconds between requests (be a good citizen)
    verify_tls: bool = True
    default_headers: Dict[str, str] = field(default_factory=lambda: {
        "User-Agent": "api-fuzzer/1.0 (authorized-security-testing)"
    })
    # Map of role name -> auth token/cookie value, e.g. {"user_a": "<jwt>", "user_b": "<jwt>"}
    tokens: Dict[str, str] = field(default_factory=dict)
    # How the token should be attached: "cookie", "bearer", or "header"
    auth_mode: str = "bearer"
    auth_cookie_name: str = "token"
    auth_header_name: str = "Authorization"
    output_dir: str = "reports"

    def auth_kwargs(self, role: Optional[str]):
        """Build the requests kwargs (headers/cookies) for a given role's token."""
        headers = dict(self.default_headers)
        cookies = {}
        if role is None or role not in self.tokens:
            return {"headers": headers, "cookies": cookies}

        token = self.tokens[role]
        if self.auth_mode == "bearer":
            headers[self.auth_header_name] = f"Bearer {token}"
        elif self.auth_mode == "header":
            headers[self.auth_header_name] = token
        elif self.auth_mode == "cookie":
            cookies[self.auth_cookie_name] = token
        return {"headers": headers, "cookies": cookies}
