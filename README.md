# API Fuzzer

A Python fuzzer built on `requests` that automates endpoint/parameter/method
testing against REST APIs and flags patterns aligned with the OWASP API
Security Top 10:

- **API1 - Broken Object Level Authorization (BOLA/IDOR)** — cross-user object
  access checks (`fuzzer/auth_tester.py`)
- **API2 - Broken Authentication** — no-token / forged-token checks compared
  against an authenticated baseline (`fuzzer/auth_tester.py`)
- **API3 - Excessive Data Exposure** — recursive scan of JSON responses for
  sensitive field names (`fuzzer/analyzer.py`)
- **API7/API8 - Improper Input Validation / Injection** — SQLi/XSS/SSTI/path-
  traversal/type-confusion payload fuzzing with reflection + error-leak
  detection (`fuzzer/input_fuzzer.py`)
- Verb-tampering / method fuzzing across discovered endpoints
  (`fuzzer/endpoint_fuzzer.py`)

## ⚠️ Authorized use only

Only point this at targets you own or are explicitly authorized to test —
your own lab/staging environment, an in-scope bug bounty program, or a
training platform such as PortSwigger's Web Security Academy or OWASP Juice
Shop. Running this against systems without permission is illegal in most
jurisdictions.

## Project layout

```
api_fuzzer/
├── main.py                     # CLI entrypoint
├── fuzzer/
│   ├── config.py                # FuzzConfig: url, tokens, auth mode, etc.
│   ├── analyzer.py               # anomaly / error-leak / exposure / BOLA detection
│   ├── endpoint_fuzzer.py        # wordlist-based endpoint + method discovery
│   ├── auth_tester.py            # BOLA + broken-auth testing
│   ├── input_fuzzer.py           # injection/type-confusion payload fuzzing
│   └── report.py                 # JSON + HTML report generation
├── wordlists/common_endpoints.txt
├── payloads/injection_payloads.json
├── tokens.example.json           # copy to tokens.json and fill in real tokens
└── reports/                      # generated reports land here
```

## Install

```bash
pip install -r requirements.txt
```

## Usage

Endpoint discovery + method fuzzing only:

```bash
python main.py --url https://demo.local/api --endpoints
```

Everything, with two user tokens for BOLA testing:

```bash
cp tokens.example.json tokens.json   # then fill in real tokens
python main.py --url https://demo.local/api \
  --tokens tokens.json --auth-mode bearer \
  --bola-endpoint-template "api/orders/{id}" \
  --bola-object-ids '{"user_a": ["101"], "user_b": ["202"]}' \
  --fuzz-endpoint "api/search" --fuzz-params "q,category" \
  --all
```

If your app authenticates via a session cookie (like the original snippet
this project grew from) instead of a bearer header:

```bash
python main.py --url https://demo.local --tokens tokens.json \
  --auth-mode cookie --auth-cookie-name token --all
```

Reports land in `reports/report.json` and `reports/report.html`.

## Notes on the original script this was built from

The starting snippet had two bugs worth calling out (fixed here):

1. `return end_dict` was indented inside the `for` loop, so the function
   returned after checking only the very first wordlist entry.
2. `methods_fuzz(url, wordlist='wordlist.txt', auth, token)` put a
   non-default argument (`auth`) after a default argument — that's a
   `SyntaxError` in Python; a function signature can't go back to required
   args after a default one.

Everything else — hitting a wordlist of paths, then POSTing to a discovered
endpoint with a captured session token — was the right instinct; it's now
generalized into reusable modules with actual detection logic instead of a
single hardcoded example request.
