"""Dependency-free HTTP security header checker (Python 3.10+)."""
import argparse
import html
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urljoin
from urllib.request import Request, build_opener, HTTPRedirectHandler


def validate_url(url):
    parts = urlsplit(url)
    if (parts.scheme not in ('http', 'https') or not parts.hostname
            or parts.username is not None or parts.password is not None
            or any(ord(c) <= 32 or ord(c) == 127 for c in url)):
        raise ValueError('Use an HTTP(S) URL without credentials or whitespace.')
    _ = parts.port
    return url


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, timeout=10, max_redirects=5):
    validate_url(url)
    opener = build_opener(NoRedirect())
    hops = []
    for _ in range(max_redirects + 1):
        try:
            response = opener.open(Request(url, headers={'User-Agent': 'HeaderGuard/1.0'}), timeout=timeout)
        except HTTPError as exc:
            response = exc
        with response:
            status, headers = response.code, response.headers
            location = headers.get('Location')
            if status not in (301, 302, 303, 307, 308) or not location:
                return url, status, headers, hops
            target = validate_url(urljoin(url, location))
            if urlsplit(url).scheme == 'https' and urlsplit(target).scheme == 'http':
                raise ValueError('Refusing HTTPS-to-HTTP redirect.')
            hops.append({'url': url, 'status': status, 'location': target})
            url = target
    raise ValueError('Redirect limit exceeded.')


def analyze(url, headers, status=200, redirects=None):
    h = {k.lower(): v.strip() for k, v in headers.items()}
    findings = []

    def add(name, state, detail, advice):
        findings.append(dict(check=name, status=state, detail=detail, recommendation=advice))

    secure = urlsplit(url).scheme == 'https'
    add('HTTPS', 'pass' if secure else 'warn', 'HTTPS response' if secure else 'Unencrypted HTTP response', 'Serve the site over HTTPS with a valid certificate.')
    sts = h.get('strict-transport-security', '')
    age = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)', sts, re.I)
    add('HSTS', 'pass' if secure and age and int(age[1]) > 0 else 'warn', sts or 'Header missing', 'Configure a positive max-age on HTTPS after testing. HSTS delivered over HTTP is ignored.')
    csp = h.get('content-security-policy', '')
    directives = {}
    for chunk in csp.split(';'):
        words = chunk.split()
        if words:
            directives.setdefault(words[0].lower(), words[1:])
    scripts = directives.get('script-src', directives.get('default-src'))
    risky = any(token in csp.lower() for token in ("'unsafe-inline'", "'unsafe-eval'"))
    broad = scripts is None or any(x in scripts for x in ('*', 'https:', 'http:', 'data:'))
    add('Content Security Policy', 'review' if csp and not risky and not broad else 'warn', csp or 'Enforced CSP missing', 'Review script sources, nonces/hashes, object-src and base-uri. This heuristic is not a complete CSP parser; report-only does not enforce a policy.')
    ancestors = directives.get('frame-ancestors', [])
    xfo = h.get('x-frame-options', '').upper()
    framing = 'review' if ancestors and '*' not in ancestors else ('pass' if not ancestors and xfo in ('DENY', 'SAMEORIGIN') else 'warn')
    add('Clickjacking protection', framing, 'frame-ancestors: ' + ' '.join(ancestors) if ancestors else xfo or 'No framing restriction', 'Use a valid frame-ancestors policy for intended embedding; X-Frame-Options DENY or SAMEORIGIN supports legacy clients.')
    add('MIME sniffing', 'pass' if h.get('x-content-type-options', '').lower() == 'nosniff' else 'warn', h.get('x-content-type-options', 'Header missing'), 'Set X-Content-Type-Options: nosniff and correct Content-Type values.')
    ref = h.get('referrer-policy', '')
    valid = {'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'}
    policies = [p.strip().lower() for p in ref.split(',') if p.strip().lower() in valid]
    safe = bool(policies) and policies[-1] in {'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'}
    add('Referrer policy', 'pass' if safe else 'review', ref or 'Browser defaults apply', 'Consider strict-origin-when-cross-origin or no-referrer according to privacy needs.')
    add('Permissions policy', 'review', h.get('permissions-policy', 'No explicit policy'), 'Review browser feature access. Disable unused features, for example camera=(), microphone=().')
    return {'url': url, 'http_status': status, 'generated_at': datetime.now(timezone.utc).isoformat(), 'redirects': redirects or [], 'findings': findings, 'summary': {s: sum(f['status'] == s for f in findings) for s in ('pass', 'warn', 'review')}}


def render_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    rows = ''.join(f'<article><span class="{esc(f["status"])}">{esc(f["status"].upper())}</span><h2>{esc(f["check"])}</h2><pre>{esc(f["detail"])}</pre><p>{esc(f["recommendation"])}</p></article>' for f in report['findings'])
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>HeaderGuard report</title>
<style>body{{font:16px/1.6 system-ui,sans-serif;background:#101827;color:#e8eef6;max-width:960px;margin:40px auto;padding:0 24px}}h1{{font-size:42px;margin-bottom:0}}h2{{font-size:20px}}article{{background:#1b2739;border:1px solid #35435a;padding:24px;border-radius:12px;margin:18px 0}}span{{float:right;font-weight:bold}}.pass{{color:#7ee2ad}}.warn{{color:#ffbd76}}.review{{color:#a9ccff}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#c9d6e8}}footer{{color:#b5c4d9}}</style>
<h1>HeaderGuard</h1><p>HTTP security header report</p><pre>{esc(report['url'])}<br>HTTP {esc(report['http_status'])} · {esc(report['generated_at'])}</pre><p>{esc(report['summary'])}</p>{rows}<footer>Heuristic inspection of one response, not a security certification. Review findings in application context.</footer></html>'''


def positive_timeout(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('timeout must be finite and positive')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description='Inspect HTTP security headers without exploit attempts.')
    parser.add_argument('url', help='HTTP(S) URL to inspect')
    parser.add_argument('--timeout', type=positive_timeout, default=10, help='Per socket-operation timeout in seconds (default: 10)')
    parser.add_argument('--json', type=Path, dest='json_path', help='Save JSON report')
    parser.add_argument('--html', type=Path, dest='html_path', help='Save standalone HTML report')
    parser.add_argument('--fail-on-warning', action='store_true', help='Exit 1 when warnings are found')
    args = parser.parse_args(argv)
    try:
        url, status, headers, hops = fetch(args.url, args.timeout)
        report = analyze(url, headers, status, hops)
        for path, content in ((args.json_path, json.dumps(report, indent=2)), (args.html_path, render_html(report))):
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content + '\n', encoding='utf-8')
        print(f'HeaderGuard | {url} | HTTP {status}')
        for f in report['findings']:
            print(f'[{f["status"].upper()}] {f["check"]}\n  {f["recommendation"]}')
        print('Summary:', report['summary'])
        return 1 if args.fail_on_warning and report['summary']['warn'] else 0
    except (ValueError, OSError, URLError) as exc:
        print(f'HeaderGuard error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
