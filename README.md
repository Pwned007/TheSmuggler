# The Smuggler (HRS)

**By Syed Sadam Hussain Shah** — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)

An HTTP Request Smuggling scanner, exploit-confirmation tool, and PoC generator —
**CL.TE · TE.CL · TE.TE · CL.0 · H2.CL · H2.TE · H2-Tunnel**, plus a WAF-bypass tester
and a one-command PoC/evidence generator.

## What it is

Most request-smuggling tooling stops at a timing anomaly, which is exactly what produces
false positives from a slow endpoint, network jitter, or a busy load balancer. The Smuggler
is built around **differential-response confirmation** instead: it measures a plain baseline,
sends a smuggle probe immediately followed by a follow-up request on the *same* connection,
and checks whether the follow-up's response has changed — then re-runs a matched **control**
(a well-formed request with no dangling bytes) and requires the control to stay clean. Timing
alone never produces a finding; a differential hit does.

## Techniques

| Technique | What's being exploited |
|---|---|
| `cl-te` | Front-end uses Content-Length, back-end uses Transfer-Encoding |
| `te-cl` | Front-end uses Transfer-Encoding, back-end uses Content-Length |
| `te-te` | Both support TE, but one is confused by an obfuscated TE header (12+ obfuscation variants tried) |
| `cl-0`  | Back-end ignores Content-Length (treats it as 0) while the front-end honours it |
| `h2-cl` | HTTP/2 → HTTP/1.1 downgrade: injected content-length mismatches actual body length |
| `h2-te` | HTTP/2 → HTTP/1.1 downgrade: injected `transfer-encoding: chunked` (forbidden in H2 by RFC 7540) |
| `h2-tunnel` | A complete, well-formed HTTP/1.1 request is tunneled inside an H2 DATA body ([Kettle, "HTTP/2: The Sequel is Always Worse", 2021](https://portswigger.net/research/http2)) |

H2.CL/H2.TE use two-phase detection (timing probe → differential canary confirmation on a
second connection) so a timing hit alone never becomes a finding — it's only reported once the
differential canary confirms it, upgrading confidence to HIGH.

## Installation

```bash
git clone https://github.com/Pwned007/thesmuggler.git
cd thesmuggler
pip install -r requirements.txt
```

Requires Python 3.8+. Dependencies: [`h2`](https://pypi.org/project/h2/) (HTTP/2 framing) and
[`rich`](https://pypi.org/project/rich/) (console output).

## Usage

### Scan — detect smuggling

```bash
python main.py scan https://target.com
python main.py scan https://target.com -t cl-te,te-cl,te-te,cl-0,h2-cl,h2-te,h2-tunnel
python main.py scan https://target.com -t cl-0 -v -o report.json
python main.py scan https://target.com --proxy 127.0.0.1:8080        # through Burp
python main.py scan https://target.com --delay 0.5                   # rate-limit friendly
python main.py scan https://target.com --no-h2                       # skip HTTP/2 probes
python main.py scan https://target.com --force                       # no front-end detected, scan anyway
python main.py scan https://target.com -p /admin --method POST
python main.py scan https://target.com --header "Cookie: session=abc" --header "X-Custom: value"
python main.py scan -f targets.txt --concurrency 5 --no-h2 -o report.json
```

Scan auto-detects whether a front-end proxy/CDN is present before running (these techniques
need a front-end/back-end parser mismatch — a single origin has nothing to desync against).
Use `--force` to scan anyway.

### Confirm — prove impact without a live victim

```bash
python main.py confirm https://target.com
python main.py confirm https://target.com --technique cl-0
python main.py confirm https://target.com -p /admin --retries 5
python main.py confirm https://target.com --proxy 127.0.0.1:8080
```

Tries two strategies: (A) smuggle + injected canary + follow-up all on one connection, parsing
all three responses; (B) smuggle + canary on connection 1, then an unrelated request on
connection 2 — if connection 2 receives the canary's response, the back-end connection pool is
shared and the impact is proven cross-connection.

### Bypass — smuggle past a WAF

```bash
python main.py bypass https://target.com --technique cl-0
python main.py bypass https://target.com --technique cl-0 --paths /admin,/api/internal,/.env
python main.py bypass https://target.com --technique cl-0 --poc -o bypass.json
python main.py bypass https://target.com --technique cl-0 --proxy 127.0.0.1:8080 --poc
```

The WAF inspects and allows the **outer** request (e.g. `POST /`); the **inner** smuggled
request (e.g. `GET /admin`) reaches the back-end directly, bypassing inspection entirely.
Tests 40+ built-in paths (admin panels, cloud metadata/actuators, `.env`, git config, internal
APIs, Elasticsearch, etc.) or a custom `--paths` list, and prints direct-vs-smuggled status
side by side for each.

### PoC — generate the write-up

```bash
python main.py poc https://target.com --technique cl-0
python main.py poc https://target.com --technique cl-0 --bypass-path /admin
python main.py poc https://target.com --technique cl-0 -o finding_prefix
```

Produces three files from one command:

| File | Purpose |
|---|---|
| `*_poc.py` | Standalone Python script — stdlib only (`socket`/`ssl`), zero dependencies, paste and run |
| `*_request.txt` | Raw HTTP bytes formatted for Burp Repeater (paste or import) |
| `*_evidence.md` | Report-ready section: technique explanation, request/response, severity, CVSS note, remediation |

## Flags reference

| Flag | Applies to | Meaning |
|---|---|---|
| `-t / --techniques` | scan | comma-separated techniques, or `all` (default) |
| `-p / --path` | all | HTTP path to test (default `/`) |
| `--method` | scan | HTTP method (default `POST`) |
| `-f / --file` | scan | file of target URLs, one per line |
| `--concurrency N` | scan | parallel targets with `-f` (default 1 = sequential) |
| `--proxy HOST:PORT` | all | route probes through an HTTP CONNECT proxy (e.g. Burp) |
| `--delay SECONDS` | scan/bypass | pause between probes/paths to avoid rate-limiting |
| `--delay-threshold` | scan | seconds above baseline flagged as a timing hit (default 3) |
| `--timeout` | all | socket timeout in seconds |
| `--retries N` | scan/confirm/bypass | attempts per technique/path |
| `--no-h2` | scan | skip HTTP/2 probes (H2.CL, H2.TE, H2-Tunnel) |
| `--force` | scan | run even if no front-end proxy is detected |
| `--header NAME:VALUE` | scan | add a custom header to all requests (repeatable) |
| `--paths LIST` | bypass | comma-separated WAF-blocked paths (default: built-in 40+) |
| `--poc` | bypass | auto-generate PoC files for every confirmed bypass |
| `--bypass-path PATH` | poc | include a WAF-bypass demo for this path in the generated script |
| `-o / --output` | all | write JSON report / PoC file prefix |
| `-v / --verbose` | scan/confirm | show raw probe payloads and responses |

## Layout

```
main.py                        CLI entry point (argparse)
hrs/
  core/
    scanner.py                 orchestrates all techniques for one target
    transport.py                raw HTTP/1.1 socket transport
    h2transport.py              raw HTTP/2 socket transport (h2 library framing)
    frontend.py                 front-end proxy/CDN detection
    reporter.py                 console output (rich)
  techniques/
    cl_te.py / te_cl.py / te_te.py    classic H1 desync techniques
    cl_zero.py                  CL.0 detection
    cl_zero_confirm.py          CL.0 impact confirmation (2 strategies)
    differential.py             shared differential-confirmation logic
    h2_smuggling.py             H2.CL / H2.TE downgrade smuggling
    h2_tunnel.py                H2 request tunneling
    waf_bypass.py               WAF bypass via smuggling
    probes.py                   raw probe payload builders
  poc/
    generator.py                PoC script / Burp request / evidence.md generator
  utils/helpers.py              shared helpers
```

## Legal

Use only against systems you are authorized to test. HTTP request smuggling can desync a
shared back-end connection and affect requests from other users of the same connection pool —
run scans with sensible `--delay`/`--retries` settings, prefer `confirm`/`poc` (which do not
require touching a live victim) once a technique is suspected, and always get written
authorization before testing production infrastructure.

## License

MIT — see [LICENSE](LICENSE). Contributions and issues welcome.
