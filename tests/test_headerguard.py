import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from headerguard import analyze, fetch, validate_url, main, render_html


class Checks(unittest.TestCase):
    def state(self, headers, name, url='https://example.test'):
        return next(f for f in analyze(url, headers)['findings'] if f['check'] == name)['status']

    def test_hsts(self):
        for value in ('max-age=0', 'max-age=oops', 'max-age=123oops'):
            self.assertEqual(self.state({'Strict-Transport-Security': value}, 'HSTS'), 'warn')
        self.assertEqual(self.state({'Strict-Transport-Security': 'max-age=100'}, 'HSTS'), 'pass')
        self.assertEqual(self.state({'Strict-Transport-Security': 'max-age=100'}, 'HSTS', 'http://example.test'), 'warn')

    def test_csp(self):
        for policy in ('', 'default-src *', "script-src 'unsafe-inline'", "img-src 'self'"):
            self.assertEqual(self.state({'Content-Security-Policy': policy}, 'Content Security Policy'), 'warn')
        self.assertEqual(self.state({'Content-Security-Policy-Report-Only': "default-src 'none'"}, 'Content Security Policy'), 'warn')
        self.assertEqual(self.state({'Content-Security-Policy': "default-src 'self'"}, 'Content Security Policy'), 'review')

    def test_framing(self):
        self.assertEqual(self.state({'X-Frame-Options': 'SAMEORIGIN'}, 'Clickjacking protection'), 'pass')
        self.assertEqual(self.state({'Content-Security-Policy': 'frame-ancestors *', 'X-Frame-Options': 'DENY'}, 'Clickjacking protection'), 'warn')

    def test_referrer(self):
        self.assertEqual(self.state({'Referrer-Policy': 'no-referrer, unsafe-url'}, 'Referrer policy'), 'review')

    def test_invalid_urls(self):
        for url in ('file:///etc/passwd', 'https://user:pass@example.test', 'example.test', 'https://example.test:bad', 'https://example.test/\n'):
            with self.assertRaises(ValueError):
                validate_url(url)

    def test_html_escaping(self):
        result = render_html(analyze('https://example.test/<script>', {'Content-Security-Policy': '<img onerror=alert(1)>'}))
        self.assertNotIn('<script>', result)
        self.assertNotIn('<img', result)
        self.assertIn('&lt;script&gt;', result)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ('/redirect', '/loop'):
            self.send_response(302)
            self.send_header('Location', '/' if self.path == '/redirect' else '/loop')
        else:
            self.send_response(404 if self.path == '/missing' else 200)
            self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()

    def log_message(self, *args):
        pass


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_redirect(self):
        url, status, headers, hops = fetch(self.url + '/redirect')
        self.assertEqual(len(hops), 1)
        self.assertEqual(status, 200)
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')

    def test_loop(self):
        with self.assertRaisesRegex(ValueError, 'Redirect limit'):
            fetch(self.url + '/loop')

    def test_error_response(self):
        self.assertEqual(fetch(self.url + '/missing')[1], 404)

    def test_cli_reports(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            j, h = Path(folder) / 'report.json', Path(folder) / 'report.html'
            self.assertEqual(main([self.url, '--json', str(j), '--html', str(h), '--fail-on-warning']), 1)
            self.assertEqual(json.loads(j.read_text())['http_status'], 200)
            self.assertIn('HeaderGuard', h.read_text())

    def test_cli_invalid_input(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['file:///tmp/test']), 2)


if __name__ == '__main__':
    unittest.main()
