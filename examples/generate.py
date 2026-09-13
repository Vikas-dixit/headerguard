"""Run from repository root: python examples/generate.py."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from headerguard import analyze, render_html

report = analyze('https://demo.example.test (synthetic example)', {
    'Strict-Transport-Security': 'max-age=31536000',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
})
folder = Path(__file__).parent
(folder / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
(folder / 'report.html').write_text(render_html(report), encoding='utf-8')
