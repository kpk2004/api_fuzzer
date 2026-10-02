#!/usr/bin/env python3
"""
API Fuzzer - CLI entrypoint.

Automates endpoint/method/parameter fuzzing against a target API and flags
common OWASP API Top 10 issues: BOLA, broken authentication, excessive data
exposure, and improper input validation.

FOR USE ONLY AGAINST SYSTEMS YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST
(e.g. your own lab, an in-scope bug bounty target, PortSwigger Academy,
OWASP Juice Shop, etc.). See README.md.

Example:
    python main.py --url https://demo.local/api \\
        --wordlist wordlists/common_endpoints.txt \\
        --tokens tokens.example.json \\
        --auth-mode bearer \\
        --all
"""
import argparse
import json
import sys

from fuzzer import (
    FuzzConfig, ResponseAnalyzer, EndpointFuzzer, AuthTester,
    InputValidationFuzzer, report,
)


def parse_args():
    p = argparse.ArgumentParser(description="OWASP-API-Top-10-aligned API fuzzer.")
    p.add_argument("--url", required=True, help="Base target URL, e.g. https://api.target.com")
    p.add_argument("--wordlist", default="wordlists/common_endpoints.txt")
    p.add_argument("--payloads", default="payloads/injection_payloads.json")
    p.add_argument("--tokens", help="Path to JSON file mapping role -> token")
    p.add_argument("--auth-mode", choices=["bearer", "header", "cookie"], default="bearer")
    p.add_argument("--auth-cookie-name", default="token")
    p.add_argument("--delay", type=float, default=0.0, help="Seconds between requests")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--no-verify-tls", action="store_true")
    p.add_argument("--output-dir", default="reports")

    p.add_argument("--endpoints", action="store_true", help="Run endpoint + method discovery")
    p.add_argument("--auth", action="store_true", help="Run BOLA + broken-auth checks")
    p.add_argument("--input", action="store_true", help="Run input-validation fuzzing")
    p.add_argument("--all", action="store_true", help="Run every module")

    p.add_argument("--bola-endpoint-template", default=None,
                    help="e.g. 'api/orders/{id}' -- required for --auth's BOLA test")
    p.add_argument("--bola-object-ids", default=None,
                    help='JSON, e.g. \'{"user_a": ["101"], "user_b": ["202"]}\'')

    p.add_argument("--fuzz-endpoint", default=None, help="Endpoint to target for --input, e.g. 'api/login'")
    p.add_argument("--fuzz-params", default=None, help="Comma-separated query param names for --input")

    return p.parse_args()


def main():
    args = parse_args()
    tokens = {}
    if args.tokens:
        with open(args.tokens, "r") as f:
            tokens = json.load(f)

    config = FuzzConfig(
        base_url=args.url,
        wordlist_path=args.wordlist,
        payloads_path=args.payloads,
        timeout=args.timeout,
        delay=args.delay,
        verify_tls=not args.no_verify_tls,
        tokens=tokens,
        auth_mode=args.auth_mode,
        auth_cookie_name=args.auth_cookie_name,
        output_dir=args.output_dir,
    )
    analyzer = ResponseAnalyzer()

    run_endpoints = args.endpoints or args.all
    run_auth = args.auth or args.all
    run_input = args.input or args.all

    if not any([run_endpoints, run_auth, run_input]):
        print("Nothing to do -- pass --endpoints, --auth, --input, or --all.")
        sys.exit(1)

    discovered = []
    role = next(iter(tokens), None)

    if run_endpoints:
        print("\n=== [1] Endpoint discovery ===")
        ef = EndpointFuzzer(config, analyzer)
        discovered = ef.discover(role=role)
        print(f"\n=== [2] HTTP method fuzzing on {len(discovered)} discovered endpoint(s) ===")
        ef.fuzz_methods(discovered, role=role)

    if run_auth:
        print("\n=== [3] Broken authentication checks ===")
        at = AuthTester(config, analyzer)
        targets = [e.path for e in discovered] or ["api/users/1"]
        for t in targets:
            at.test_no_auth(t)
            at.test_invalid_token(t)

        if args.bola_endpoint_template and args.bola_object_ids:
            print("\n=== [4] BOLA / IDOR cross-user access checks ===")
            ids_by_owner = json.loads(args.bola_object_ids)
            at.test_cross_user_access(args.bola_endpoint_template, ids_by_owner)
        else:
            print("\n[i] Skipping BOLA cross-user test -- pass --bola-endpoint-template and --bola-object-ids to enable it.")

    if run_input:
        print("\n=== [5] Input validation fuzzing ===")
        if args.fuzz_endpoint and args.fuzz_params:
            ivf = InputValidationFuzzer(config, analyzer)
            params = [p.strip() for p in args.fuzz_params.split(",")]
            ivf.fuzz_query_params(args.fuzz_endpoint, params, role=role)
        else:
            print("[i] Skipping -- pass --fuzz-endpoint and --fuzz-params to enable it.")

    print(f"\n=== Done: {len(analyzer.findings)} finding(s) ===")
    json_path = report.write_json_report(analyzer.findings, config.output_dir)
    html_path = report.write_html_report(analyzer.findings, config.output_dir)
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")


if __name__ == "__main__":
    main()
