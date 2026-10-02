"""
Response analysis logic: anomaly detection, error-based leak detection,
sensitive-data exposure detection, and unauthorized-access pattern detection.

This module never exploits anything -- it only looks at responses that the
other modules already received and flags patterns worth a human's attention.
"""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Signatures that commonly indicate a server is leaking internal error detail
# (stack traces, DB errors, framework debug pages). This is the same class of
# generic detection string list used by tools like Burp/ZAP/wfuzz.
ERROR_SIGNATURES = [
    r"sql syntax.*mysql", r"warning.*\Wmysqli?_", r"unclosed quotation mark",
    r"ORA-\d{5}", r"PostgreSQL.*ERROR", r"SQLite3?::", r"pg_query\(\)",
    r"Traceback \(most recent call last\)", r"Whitelabel Error Page",
    r"System\.NullReferenceException", r"at java\.", r"Fatal error:",
    r"Warning: .*on line \d+", r"stacktrace", r"django\.core\.exceptions",
    r"Internal Server Error", r"debug\s*=\s*true",
]

# Field names that should rarely (if ever) appear in an API response body.
# Used to flag "excessive data exposure" (OWASP API3).
SENSITIVE_KEYS = [
    "password", "passwd", "pwd", "ssn", "social_security", "secret",
    "api_key", "apikey", "private_key", "credit_card", "card_number", "cvv",
    "token", "session_id", "auth_token", "refresh_token", "hash",
    "salt", "internal_id", "is_admin", "role",
]

ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.IGNORECASE)


@dataclass
class Finding:
    category: str          # e.g. "BOLA", "Broken Auth", "Excessive Data Exposure", "Input Validation"
    severity: str           # "info" | "low" | "medium" | "high"
    endpoint: str
    method: str
    detail: str
    evidence: Optional[str] = None


@dataclass
class ResponseAnalyzer:
    findings: List[Finding] = field(default_factory=list)

    # ---------- helpers ----------

    @staticmethod
    def _flatten_keys(obj: Any) -> List[str]:
        """Recursively collect all dict keys in a JSON-like structure."""
        keys = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.append(str(k))
                keys.extend(ResponseAnalyzer._flatten_keys(v))
        elif isinstance(obj, list):
            for item in obj:
                keys.extend(ResponseAnalyzer._flatten_keys(item))
        return keys

    # ---------- detectors ----------

    def detect_error_leak(self, endpoint: str, method: str, body_text: str) -> Optional[Finding]:
        match = ERROR_RE.search(body_text or "")
        if match:
            f = Finding(
                category="Error-Based Leak",
                severity="medium",
                endpoint=endpoint,
                method=method,
                detail="Response contains a stack trace / DB error / debug signature.",
                evidence=match.group(0)[:120],
            )
            self.findings.append(f)
            return f
        return None

    def detect_sensitive_exposure(self, endpoint: str, method: str, json_body: Any) -> Optional[Finding]:
        if json_body is None:
            return None
        keys_found = sorted(set(k.lower() for k in self._flatten_keys(json_body)) & set(SENSITIVE_KEYS))
        if keys_found:
            f = Finding(
                category="Excessive Data Exposure",
                severity="high" if any(k in ("password", "secret", "credit_card", "private_key") for k in keys_found) else "medium",
                endpoint=endpoint,
                method=method,
                detail=f"Response body includes sensitive-looking field(s): {', '.join(keys_found)}",
            )
            self.findings.append(f)
            return f
        return None

    def detect_anomaly(self, endpoint: str, method: str, baseline_status: int, baseline_len: int,
                        status: int, length: int, len_delta_pct: float = 0.25) -> Optional[Finding]:
        """Flag a response that deviates meaningfully from an expected baseline."""
        if status != baseline_status:
            f = Finding(
                category="Anomaly",
                severity="low",
                endpoint=endpoint,
                method=method,
                detail=f"Status code {status} differs from baseline {baseline_status}.",
            )
            self.findings.append(f)
            return f
        if baseline_len > 0 and abs(length - baseline_len) / baseline_len > len_delta_pct:
            f = Finding(
                category="Anomaly",
                severity="low",
                endpoint=endpoint,
                method=method,
                detail=f"Response length {length} deviates >{int(len_delta_pct*100)}% from baseline {baseline_len}.",
            )
            self.findings.append(f)
            return f
        return None

    def detect_unauthorized_access(self, endpoint: str, method: str,
                                    unauth_status: int, unauth_body: str,
                                    auth_status: int, auth_body: str) -> Optional[Finding]:
        """
        Broken Authentication (OWASP API2): flag when a request with NO/invalid
        credentials gets a response that looks materially the same as an
        authenticated one (same success status + non-trivial matching body).
        """
        if unauth_status == 200 and unauth_status == auth_status:
            similarity = self._similarity(unauth_body, auth_body)
            if similarity > 0.85:
                f = Finding(
                    category="Broken Authentication",
                    severity="high",
                    endpoint=endpoint,
                    method=method,
                    detail=f"Unauthenticated request returned 200 with a response "
                            f"{similarity:.0%} similar to the authenticated one.",
                )
                self.findings.append(f)
                return f
        return None

    def detect_bola(self, endpoint_template: str, method: str, object_id: str,
                     owner_role: str, requester_role: str,
                     status: int, body: str) -> Optional[Finding]:
        """
        BOLA / IDOR (OWASP API1): flag when a token belonging to one user
        successfully retrieves/modifies an object that belongs to a different user.
        """
        if status in (200, 201, 204):
            f = Finding(
                category="BOLA",
                severity="high",
                endpoint=endpoint_template.format(id=object_id),
                method=method,
                detail=(f"Token for '{requester_role}' accessed object '{object_id}' "
                        f"owned by '{owner_role}' and received status {status}."),
                evidence=body[:120] if body else None,
            )
            self.findings.append(f)
            return f
        return None

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        """Cheap length/character-overlap similarity, good enough for triage."""
        a, b = a or "", b or ""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        shorter, longer = sorted([a, b], key=len)
        if len(longer) == 0:
            return 1.0
        matches = sum(1 for c in shorter if c in longer)
        return matches / len(longer)
