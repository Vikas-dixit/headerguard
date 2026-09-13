# HeaderGuard

A defensive cybersecurity tool that checks HTTP security headers and creates readable HTML and JSON reports. Python 3.10+, with no runtime dependencies.

## Quick start

```sh
git clone https://github.com/Vikas-dixit/headerguard.git
cd headerguard
python -m headerguard https://example.com --html reports/report.html --json reports/report.json
```

Open `reports/report.html` in your browser. Optionally install with `python -m pip install .` to use the `headerguard` command.

## Features

- Checks HTTPS, HSTS, Content Security Policy, clickjacking protection and MIME sniffing protection.
- Reviews referrer policy and browser permissions policy.
- Prints explanations and remediation guidance, with standalone HTML and JSON output.
- Verifies TLS certificates, follows at most five redirects, and rejects HTTPS-to-HTTP downgrades.
- Reports the final HTTP status, including error responses.
- Includes local-server integration tests and GitHub Actions tests across Python versions.

```sh
python -m headerguard https://example.com --timeout 15 --fail-on-warning
python -m unittest discover -s tests -v
python examples/generate.py
```

The last command creates synthetic example reports without contacting a website.

## Results and exit codes

PASS means a narrow check passed. WARN indicates a missing or potentially weak setting. REVIEW requires application context or deeper validation. A report is not a security certification; there is deliberately no overall security score.

Exit codes: 0 = completed, 1 = warnings when `--fail-on-warning` is supplied, 2 = input, network or output error. Timeout applies to each blocking socket operation, not the entire scan. Existing files at the supplied output paths are overwritten.

## Scope and limitations

The tool sends GET requests and closes responses without reading their bodies. It inspects only the final response, without crawling or attempting exploits. Redirects can lead to another host. Use it for sites you own or are authorized to assess.

CSP checks are conservative heuristics, not a complete browser policy parser. Multiple policies, duplicate headers, directive overrides and nonce/hash semantics need manual review. Report-only CSP does not enforce restrictions. Permissions policy always requires review. API and non-HTML responses may not need every browser-focused header. Missing Referrer-Policy does not imply unrestricted referrers because browser defaults apply.

Reports include the URL and selected header values. Avoid secrets in URLs and review reports before sharing. Test policy changes against your application's requirements before deploying them.

## Project layout

- `headerguard.py`: network collection, checks, CLI and HTML report rendering.
- `tests/test_headerguard.py`: unit tests and local HTTP server integration tests.
- `examples/`: synthetic example generator and sample reports.
- `.github/workflows/tests.yml`: automated Python test matrix.

## References

- [MDN Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
- [MDN Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
