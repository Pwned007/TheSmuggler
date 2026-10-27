#!/usr/bin/env python3
"""
HRS — HTTP Request Smuggling Scanner

Usage:
  python main.py scan https://target.com
  python main.py scan https://target.com -t cl-te,te-cl -v
  python main.py scan https://target.com -o report.json --delay 0.5
  python main.py scan -f targets.txt --no-h2 --timeout 20 --concurrency 5
  python main.py scan https://target.com --proxy 127.0.0.1:8080
  python main.py confirm https://cytomate.net --technique cl-0
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from hrs.core.reporter import Reporter
from hrs.core.scanner import Scanner
from hrs.utils.helpers import parse_target


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hrs",
        description="HTTP Request Smuggling Scanner -- CL.TE | TE.CL | TE.TE | H2.CL | H2.TE | CL.0 | H2-Tunnel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Techniques:
  cl-te      Front-end uses Content-Length, back-end uses Transfer-Encoding
  te-cl      Front-end uses Transfer-Encoding, back-end uses Content-Length
  te-te      Both use TE but one is confused by obfuscated headers (12+ variants)
  cl-0       Content-Length: 0 desync (back-end ignores CL)
  h2-cl      HTTP/2 content-length injection via H2->H1 downgrade
  h2-te      HTTP/2 transfer-encoding injection via H2->H1 downgrade
  h2-tunnel  HTTP/2 request tunneling (complete H1 request in H2 body)

Examples:
  python main.py scan https://target.com
  python main.py scan https://target.com -t cl-te,te-cl -v -o report.json
  python main.py scan https://target.com -p /api/v1/ --header "Cookie: session=x" --no-h2
  python main.py scan -f targets.txt --timeout 20 --delay-threshold 5 --concurrency 5
  python main.py scan https://target.com --proxy 127.0.0.1:8080
  python main.py scan https://target.com --delay 0.5
  python main.py confirm https://cytomate.net --technique cl-0
  python main.py confirm https://cytomate.net --technique cl-0 -o confirm.json
  python main.py bypass https://cytomate.net --technique cl-0
  python main.py bypass https://cytomate.net --technique cl-0 --paths /admin,/api/internal --poc
  python main.py poc https://cytomate.net --technique cl-0 --bypass-path /admin
        """,
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ------------------------------------------------------------------ scan
    scan_p = sub.add_parser("scan", help="Scan for HTTP request smuggling")

    tg = scan_p.add_mutually_exclusive_group(required=True)
    tg.add_argument("target", nargs="?", help="Target URL")
    tg.add_argument("-f", "--file", metavar="FILE",
                    help="File with one target URL per line")

    scan_p.add_argument(
        "-t", "--techniques", default="all", metavar="LIST",
        help="Comma-separated techniques (default: all = cl-te,te-cl,te-te,cl-0,h2-cl,h2-te,h2-tunnel)",
    )
    scan_p.add_argument("-p", "--path", default="/", help="HTTP path to test (default: /)")
    scan_p.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    scan_p.add_argument(
        "--timeout", type=float, default=15.0,
        help="Probe socket timeout in seconds (default: 15)",
    )
    scan_p.add_argument(
        "--baseline-timeout", type=float, default=5.0,
        help="Baseline request timeout in seconds (default: 5)",
    )
    scan_p.add_argument(
        "--retries", type=int, default=3,
        help="Probe retries per technique (default: 3)",
    )
    scan_p.add_argument(
        "--delay", type=float, default=0.0, metavar="SECONDS",
        help="Sleep between techniques to avoid rate-limiting (default: 0)",
    )
    scan_p.add_argument(
        "--delay-threshold", type=float, default=3.0,
        help="Seconds above baseline to flag as a timing hit (default: 3)",
    )
    scan_p.add_argument(
        "--concurrency", type=int, default=1, metavar="N",
        help="Parallel targets when using -f (default: 1 = sequential)",
    )
    scan_p.add_argument(
        "--proxy", metavar="HOST:PORT",
        help="Route all probes through this HTTP CONNECT proxy (e.g. 127.0.0.1:8080 for Burp)",
    )
    scan_p.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write JSON report to this file",
    )
    scan_p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show raw probe payloads and PoC requests in output",
    )
    scan_p.add_argument(
        "--no-h2", action="store_true",
        help="Skip HTTP/2 probes (H2.CL, H2.TE, H2-Tunnel)",
    )
    scan_p.add_argument(
        "--force", action="store_true",
        help="Run even if no front-end proxy is detected",
    )
    scan_p.add_argument(
        "--header", action="append", dest="headers", metavar="NAME:VALUE",
        help="Add a custom header to all requests (repeatable)",
    )

    # --------------------------------------------------------------- confirm
    confirm_p = sub.add_parser(
        "confirm",
        help="Prove impact via differential response (no live victim needed)",
    )
    confirm_p.add_argument("target", help="Target URL")
    confirm_p.add_argument(
        "--technique", default="cl-0",
        choices=["cl-0"],
        help="Technique to confirm (default: cl-0)",
    )
    confirm_p.add_argument("-p", "--path", default="/", help="Path to test (default: /)")
    confirm_p.add_argument(
        "--timeout", type=float, default=10.0,
        help="Socket timeout in seconds (default: 10)",
    )
    confirm_p.add_argument(
        "--retries", type=int, default=3,
        help="Confirmation attempts (default: 3)",
    )
    confirm_p.add_argument(
        "--proxy", metavar="HOST:PORT",
        help="Route through HTTP CONNECT proxy (e.g. 127.0.0.1:8080 for Burp)",
    )
    confirm_p.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write JSON report to this file",
    )
    confirm_p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show raw follow-up response",
    )

    # ---------------------------------------------------------------- bypass
    bypass_p = sub.add_parser(
        "bypass",
        help="Test WAF bypass via request smuggling — smuggle requests to WAF-blocked paths",
    )
    bypass_p.add_argument("target", help="Target URL")
    bypass_p.add_argument(
        "--technique", default="cl-0",
        choices=["cl-0", "cl-te", "te-cl"],
        help="Confirmed smuggling technique to use (default: cl-0)",
    )
    bypass_p.add_argument(
        "-p", "--path", default="/",
        help="Outer request path (base path allowed by WAF, default: /)",
    )
    bypass_p.add_argument(
        "--paths", metavar="LIST",
        help="Comma-separated list of WAF-blocked paths to test (default: built-in list of 40+ paths)",
    )
    bypass_p.add_argument(
        "--timeout", type=float, default=10.0,
        help="Socket timeout in seconds (default: 10)",
    )
    bypass_p.add_argument(
        "--retries", type=int, default=2,
        help="Attempts per path (default: 2)",
    )
    bypass_p.add_argument(
        "--delay", type=float, default=0.2, metavar="SECONDS",
        help="Delay between paths (default: 0.2)",
    )
    bypass_p.add_argument(
        "--proxy", metavar="HOST:PORT",
        help="Route through HTTP CONNECT proxy",
    )
    bypass_p.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write JSON results to this file",
    )
    bypass_p.add_argument(
        "--poc", action="store_true",
        help="Generate PoC files for every confirmed bypass",
    )

    # ------------------------------------------------------------------- poc
    poc_p = sub.add_parser(
        "poc",
        help="Generate standalone PoC script, Burp request, and markdown report for a finding",
    )
    poc_p.add_argument("target", help="Target URL")
    poc_p.add_argument(
        "--technique", default="cl-0",
        choices=["cl-0", "cl-te", "te-cl", "te-te", "h2-cl", "h2-te", "h2-tunnel"],
        help="Technique to generate PoC for (default: cl-0)",
    )
    poc_p.add_argument(
        "--confidence", default="HIGH",
        choices=["HIGH", "MEDIUM", "LOW"],
        help="Confidence level for the report (default: HIGH)",
    )
    poc_p.add_argument("-p", "--path", default="/", help="Target path (default: /)")
    poc_p.add_argument(
        "--bypass-path", metavar="PATH",
        help="Include a WAF bypass demo for this path in the PoC (e.g. /admin)",
    )
    poc_p.add_argument(
        "-o", "--out-prefix", metavar="PREFIX", default=None,
        help="Output file prefix (default: <host>_<technique>)",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        _run_scan(args)
    elif args.command == "confirm":
        _run_confirm(args)
    elif args.command == "bypass":
        _run_bypass(args)
    elif args.command == "poc":
        _run_poc(args)


# =========================================================================
# scan
# =========================================================================

def _run_scan(args) -> None:
    reporter = Reporter(verbose=args.verbose)
    reporter.banner()

    if args.techniques == "all":
        techniques = ["cl-te", "te-cl", "te-te", "cl-0", "h2-cl", "h2-te", "h2-tunnel"]
    else:
        techniques = [t.strip().lower() for t in args.techniques.split(",")]

    if args.no_h2:
        techniques = [t for t in techniques if not t.startswith("h2")]

    custom_headers: dict = {}
    for h in args.headers or []:
        if ":" not in h:
            reporter.console.print(f"[red]Bad header format: '{h}' -- use NAME:VALUE[/red]")
            sys.exit(1)
        name, _, value = h.partition(":")
        custom_headers[name.strip()] = value.strip()

    if args.file:
        try:
            with open(args.file) as f:
                targets = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            reporter.console.print(f"[red]File not found: {args.file}[/red]")
            sys.exit(1)
    else:
        targets = [args.target]

    all_results = []

    def _scan_one(url: str):
        try:
            t = parse_target(url)
        except Exception as exc:
            reporter.console.print(f"[red]Cannot parse URL '{url}': {exc}[/red]")
            return []
        scanner = Scanner(
            host=t["host"],
            port=t["port"],
            use_ssl=t["ssl"],
            path=args.path or t["path"],
            method=args.method,
            timeout=args.timeout,
            baseline_timeout=args.baseline_timeout,
            retries=args.retries,
            delay=args.delay,
            delay_threshold=args.delay_threshold,
            techniques=techniques,
            custom_headers=custom_headers,
            reporter=reporter,
            force=args.force,
            proxy=args.proxy,
        )
        return scanner.run()

    concurrency = max(1, args.concurrency)
    if concurrency == 1 or len(targets) == 1:
        for url in targets:
            all_results.extend(_scan_one(url))
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(_scan_one, url): url for url in targets}
            for future in as_completed(futures):
                try:
                    all_results.extend(future.result())
                except Exception as exc:
                    reporter.console.print(f"[red]Worker error: {exc}[/red]")

    reporter.print_summary(all_results)

    if args.verbose:
        _print_poc(all_results, reporter)

    if args.output:
        report = reporter.to_json(all_results)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        reporter.console.print(f"\n[green]JSON report written to: {args.output}[/green]")

    found = any(getattr(r, "vulnerable", False) for r in all_results)
    sys.exit(1 if found else 0)


def _print_poc(results, reporter) -> None:
    """Print Burp-ready PoC raw bytes for every confirmed finding."""
    from rich.panel import Panel
    from hrs.utils.helpers import abbreviate_payload

    findings = [r for r in results if getattr(r, "vulnerable", False)]
    if not findings:
        return

    reporter.console.print("\n[bold cyan]-- PoC Requests (paste into Burp Repeater) --[/bold cyan]")
    for r in findings:
        payload = getattr(r, "probe_payload", b"")
        if not payload:
            continue
        reporter.console.print(Panel(
            abbreviate_payload(payload, max_bytes=2000),
            title=f"[bold]{r.technique} PoC — {r.confidence} confidence[/bold]",
            border_style="red" if r.confidence == "HIGH" else "yellow",
            expand=False,
        ))


# =========================================================================
# confirm
# =========================================================================

def _run_confirm(args) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    from hrs.techniques.cl_zero_confirm import confirm
    from hrs.utils.helpers import abbreviate_payload

    console = Console()

    try:
        t = parse_target(args.target)
    except Exception as exc:
        console.print(f"[red]Cannot parse URL '{args.target}': {exc}[/red]")
        sys.exit(2)

    proxy_note = f"  |  Proxy: {args.proxy}" if getattr(args, "proxy", None) else ""
    console.print(Panel(
        f"[bold cyan]HRS[/bold cyan] -- CL.0 Differential Response Confirmation\n"
        f"[dim]Target: {args.target}  |  Path: {args.path}{proxy_note}[/dim]",
        border_style="cyan", expand=False,
    ))

    console.print(
        f"\n[dim]Running Strategy A (same-connection pipeline) then Strategy B "
        f"(two-connection pool) -- {args.retries} attempts each...[/dim]"
    )

    result = confirm(
        host=t["host"],
        port=t["port"],
        use_ssl=t["ssl"],
        path=args.path,
        timeout=args.timeout,
        retries=args.retries,
        proxy=getattr(args, "proxy", None),
    )

    tbl = Table(box=box.ROUNDED, show_lines=True, title="Differential Response Results")
    tbl.add_column("Request", style="bold")
    tbl.add_column("Path")
    tbl.add_column("Response", justify="center")
    tbl.add_column("Meaning")

    tbl.add_row(
        "Baseline GET", args.path, str(result.baseline_status), "Normal response (expected)",
    )
    tbl.add_row(
        "Direct GET canary", result.canary_path, str(result.canary_direct_status),
        "Known status for non-existent canary path",
    )
    tbl.add_row(
        "Smuggle POST", args.path,
        str(result.smuggle_status) if result.smuggle_status else "-",
        "CL:0 probe with injected canary GET",
    )
    followup_status_cell = (
        f"[bold red]{result.followup_status}[/bold red]"
        if result.vulnerable
        else str(result.followup_status) if result.followup_status else "-"
    )
    followup_meaning_cell = (
        f"[bold red]Received canary response -- {result.strategy}[/bold red]"
        if result.vulnerable
        else f"Normal / unclear (parsed {result.parsed_count} response(s) from stream)"
    )
    tbl.add_row(
        "[bold]Follow-up GET[/bold]", args.path,
        followup_status_cell, followup_meaning_cell,
    )
    console.print()
    console.print(tbl)

    console.print()
    if result.vulnerable:
        console.print(Panel(
            f"[bold red][!] CONFIRMED -- {result.confidence} confidence[/bold red]\n\n"
            + result.explanation,
            border_style="red",
            title="Impact Confirmed",
        ))
    else:
        console.print(Panel(
            f"[yellow]Inconclusive -- {result.explanation}[/yellow]",
            border_style="yellow",
            title="Result",
        ))

    if args.verbose:
        if result.raw_all_bytes:
            console.print(Panel(
                abbreviate_payload(result.raw_all_bytes, max_bytes=1200),
                title=f"[dim]Raw bytes from same-connection attempt "
                      f"({len(result.raw_all_bytes)} bytes, "
                      f"{result.parsed_count} response(s) parsed)[/dim]",
                border_style="dim",
            ))
        if result.raw_followup and result.raw_followup != result.raw_all_bytes:
            console.print(Panel(
                abbreviate_payload(result.raw_followup, max_bytes=800),
                title="[dim]Raw follow-up response (Strategy B)[/dim]",
                border_style="dim",
            ))

    if args.output:
        report = {
            "tool": "HRS -- HTTP Request Smuggling Scanner",
            "command": "confirm",
            "technique": args.technique,
            "target": args.target,
            "path": args.path,
            "vulnerable": result.vulnerable,
            "confidence": result.confidence,
            "canary_path": result.canary_path,
            "baseline_status": result.baseline_status,
            "canary_direct_status": result.canary_direct_status,
            "smuggle_status": result.smuggle_status,
            "followup_status": result.followup_status,
            "explanation": result.explanation,
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n[green]JSON report written to: {args.output}[/green]")

    sys.exit(1 if result.vulnerable else 0)


# =========================================================================
# bypass
# =========================================================================

def _run_bypass(args) -> None:
    import json as _json
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    from hrs.techniques.waf_bypass import run_bypass, DEFAULT_PATHS
    from hrs.utils.helpers import parse_target

    console = Console()

    try:
        t = parse_target(args.target)
    except Exception as exc:
        console.print(f"[red]Cannot parse URL '{args.target}': {exc}[/red]")
        sys.exit(2)

    paths = (
        [p.strip() for p in args.paths.split(",") if p.strip()]
        if args.paths else None
    )

    console.print(Panel(
        f"[bold cyan]HRS[/bold cyan] -- WAF Bypass via {args.technique.upper()}\n"
        f"[dim]Target: {args.target}  |  Outer path: {args.path}  |  "
        f"Paths to test: {len(paths) if paths else len(DEFAULT_PATHS)}[/dim]",
        border_style="cyan", expand=False,
    ))
    console.print()

    result = run_bypass(
        host=t["host"],
        port=t["port"],
        use_ssl=t["ssl"],
        technique=args.technique,
        base_path=args.path,
        paths=paths,
        timeout=args.timeout,
        retries=args.retries,
        proxy=getattr(args, "proxy", None),
        delay=args.delay,
    )

    # Results table
    tbl = Table(box=box.ROUNDED, show_lines=True,
                title="WAF Bypass Results")
    tbl.add_column("Path", style="bold")
    tbl.add_column("Direct (WAF)", justify="center")
    tbl.add_column("Smuggled", justify="center")
    tbl.add_column("Result")

    for f in result.findings:
        if f.confirmed:
            row_style = "bold red"
            verdict = "[bold red]BYPASSED[/bold red]"
        elif f.smuggled_status == 0:
            row_style = "dim"
            verdict = "[dim]no response[/dim]"
        else:
            row_style = ""
            verdict = "[dim green]blocked[/dim green]"

        tbl.add_row(
            f.path,
            str(f.direct_status),
            str(f.smuggled_status) if f.smuggled_status else "-",
            verdict,
        )

    console.print(tbl)
    console.print()

    bypassed = result.confirmed_bypasses
    if bypassed:
        console.print(Panel(
            f"[bold red]{len(bypassed)} WAF bypass(es) confirmed[/bold red]\n\n"
            + "\n".join(
                f"  {f.path}  —  WAF returned {f.direct_status}, "
                f"smuggled returned {f.smuggled_status}"
                for f in bypassed
            ),
            border_style="red",
            title="Confirmed Bypasses",
        ))

        if args.poc:
            from hrs.poc.generator import generate_all
            from hrs.techniques.waf_bypass import build_bypass_payload
            console.print()
            for f in bypassed:
                smuggle, _ = build_bypass_payload(
                    t["host"], args.path, f.path, args.technique
                )
                safe_host = t["host"].replace(".", "_")
                safe_path = f.path.strip("/").replace("/", "_") or "root"
                prefix = f"{safe_host}_{args.technique}_{safe_path}"
                files = generate_all(
                    host=t["host"], port=t["port"], use_ssl=t["ssl"],
                    path=args.path, technique=args.technique,
                    confidence="HIGH",
                    description=f"WAF bypass confirmed for path {f.path}.",
                    evidence=(
                        f"Direct access to {f.path} returned HTTP {f.direct_status} (blocked). "
                        f"Smuggling a GET {f.path} inside a POST {args.path} bypassed "
                        f"WAF inspection and the back-end returned HTTP {f.smuggled_status}."
                    ),
                    probe_payload=smuggle,
                    out_prefix=prefix,
                    bypass_path=f.path,
                )
                console.print(
                    f"  [green]PoC files for {f.path}:[/green]\n"
                    f"    {files['py_file']}\n"
                    f"    {files['txt_file']}\n"
                    f"    {files['md_file']}"
                )
    else:
        console.print(Panel(
            "[yellow]No WAF bypasses confirmed on this run.\n\n"
            "Tips:\n"
            "  - Ensure the technique matches a confirmed finding (run scan first)\n"
            "  - Try --paths with specific paths known to be protected\n"
            "  - Increase --retries if the server is inconsistent\n"
            "  - Try a different --path for the outer request (e.g. /api/)[/yellow]",
            border_style="yellow",
            title="No Bypasses Found",
        ))

    if args.output:
        report = {
            "tool": "HRS -- HTTP Request Smuggling Scanner",
            "command": "bypass",
            "technique": result.technique,
            "target": args.target,
            "base_path": result.base_path,
            "baseline_status": result.baseline_status,
            "paths_tested": result.paths_tested,
            "bypasses_confirmed": len(bypassed),
            "findings": [
                {
                    "path": f.path,
                    "direct_status": f.direct_status,
                    "smuggled_status": f.smuggled_status,
                    "confirmed": f.confirmed,
                    "note": f.note,
                }
                for f in result.findings
            ],
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            _json.dump(report, fh, indent=2)
        console.print(f"\n[green]JSON report written to: {args.output}[/green]")

    sys.exit(1 if bypassed else 0)


# =========================================================================
# poc
# =========================================================================

def _run_poc(args) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from hrs.poc.generator import generate_all
    from hrs.techniques.probes import (
        build_cl_te_smuggle, build_te_cl_smuggle,
        build_cl_zero_smuggle, build_followup_get,
    )
    from hrs.utils.helpers import parse_target

    console = Console()

    try:
        t = parse_target(args.target)
    except Exception as exc:
        console.print(f"[red]Cannot parse URL '{args.target}': {exc}[/red]")
        sys.exit(2)

    host     = t["host"]
    port     = t["port"]
    use_ssl  = t["ssl"]
    path     = args.path
    tech     = args.technique
    conf     = args.confidence

    # Build the canonical probe payload for the chosen technique
    technique_map = {
        "cl-0":  lambda: build_cl_zero_smuggle(host, path),
        "cl-te": lambda: build_cl_te_smuggle(host, path),
        "te-cl": lambda: build_te_cl_smuggle(host, path),
        "te-te": lambda: build_cl_te_smuggle(host, path),   # best approximation
        "h2-cl": lambda: (                                   # synthesise H1 equivalent
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Content-Length: 100\r\nConnection: keep-alive\r\n\r\n"
        ).encode(),
        "h2-te": lambda: (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"
            "Connection: keep-alive\r\n\r\n1\r\nZ"
        ).encode(),
        "h2-tunnel": lambda: (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: 64\r\nConnection: keep-alive\r\n\r\n"
            f"GET /hrs-tunnel-canary HTTP/1.1\r\nHost: {host}\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode(),
    }

    probe_payload = technique_map.get(tech, technique_map["cl-0"])()

    _DESCRIPTIONS = {
        "cl-0":  "CL.0 desync: the back-end ignores Content-Length and reads trailing bytes as a new request.",
        "cl-te": "CL.TE desync: the front-end uses Content-Length while the back-end uses Transfer-Encoding.",
        "te-cl": "TE.CL desync: the front-end uses Transfer-Encoding while the back-end uses Content-Length.",
        "te-te": "TE.TE desync: both servers support TE but one is confused by an obfuscated header variant.",
        "h2-cl": "H2.CL desync: injected content-length header survives the HTTP/2 -> HTTP/1.1 downgrade.",
        "h2-te": "H2.TE desync: forbidden transfer-encoding header is forwarded through the H2->H1 gateway.",
        "h2-tunnel": "H2 Request Tunneling: complete H1 request embedded in the H2 DATA body.",
    }
    _EVIDENCE = {
        "cl-0":  "Front-end forwards the body bytes to the back-end; back-end treats them as a new pipelined request.",
        "cl-te": "Front-end forwards exactly Content-Length bytes; back-end reads chunked body and leaves a dangling prefix.",
        "te-cl": "Front-end de-chunks and forwards; back-end reads only Content-Length bytes, leaving the remainder as a new request.",
        "te-te": "The obfuscated TE header confuses one server into falling back to Content-Length, creating a CL.TE or TE.CL split.",
        "h2-cl": "The H2->H1 gateway blindly forwards the injected content-length: 100 header; the H1 back-end stalls waiting for 100 bytes.",
        "h2-te": "The gateway forwards the forbidden TE header; the H1 back-end and gateway disagree on body framing.",
        "h2-tunnel": "The gateway reuses a persistent H1 connection; our H1 request body is queued as a new back-end request.",
    }

    out_prefix = args.out_prefix or f"{host.replace('.', '_')}_{tech}"

    console.print(Panel(
        f"[bold cyan]HRS[/bold cyan] -- PoC Generator\n"
        f"[dim]Target: {args.target}  |  Technique: {tech.upper()}  |  "
        f"Confidence: {conf}[/dim]",
        border_style="cyan", expand=False,
    ))
    console.print()

    files = generate_all(
        host=host, port=port, use_ssl=use_ssl,
        path=path, technique=tech, confidence=conf,
        description=_DESCRIPTIONS.get(tech, ""),
        evidence=_EVIDENCE.get(tech, ""),
        probe_payload=probe_payload,
        out_prefix=out_prefix,
        bypass_path=getattr(args, "bypass_path", None),
    )

    console.print(Panel(
        f"[bold green]PoC files generated:[/bold green]\n\n"
        f"  [cyan]Python script[/cyan]  : {files['py_file']}\n"
        f"  [cyan]Burp request[/cyan]   : {files['txt_file']}\n"
        f"  [cyan]Markdown report[/cyan]: {files['md_file']}",
        border_style="green",
        title="Output",
        expand=False,
    ))
    console.print()
    console.print(
        f"[dim]Run the PoC:[/dim]  python {files['py_file']}\n"
        f"[dim]Import into Burp:[/dim]  open {files['txt_file']} and paste into Repeater\n"
        f"[dim]Report section:[/dim]  paste {files['md_file']} into your pentest report"
    )


if __name__ == "__main__":
    main()
