#!/usr/bin/env python3
"""Security check for the Metallibs API site (used by security-scan.yml).

The site is plain HTML plus MetallibSupportPkg/manifest.json, so instead of a
dependency scan this checks what actually matters here:

HTML pages (fixed automatically with --apply):
  - a strict Content-Security-Policy <meta> tag is present
  - a no-referrer policy is present
  - links and resources use https:// instead of http://
  - target="_blank" links carry rel="noopener noreferrer"
HTML pages (reported only):
  - inline <script> blocks or on...= event handlers
  - a CSP that allows scripts, 'unsafe-eval' or wildcard sources

manifest.json (reported only, never changed automatically):
  - valid JSON, every entry has the expected fields
  - every download URL is https:// on github.com
  - every sha1sum is a 40-character hex string
  - no duplicate builds

Exit codes: 0 = nothing left to do, 2 = problems remain, 1 = error.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
APPLY = "--apply" in sys.argv

CSP = ("default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'")
CSP_TAG = f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
REFERRER_TAG = '<meta name="referrer" content="no-referrer">'
ALLOWED_HOSTS = {"github.com"}

fixed: list[str] = []
remaining: list[str] = []


def insert_in_head(html: str, tag: str) -> str:
    """Insert a tag right after <meta charset> (or <head>)."""
    m = re.search(r"<meta\s+charset=[^>]*>", html, re.I) or re.search(r"<head[^>]*>", html, re.I)
    if not m:
        return html
    indent = re.search(r"\n([ \t]*)<meta", html)
    pad = indent.group(1) if indent else "  "
    return html[: m.end()] + f"\n{pad}{tag}" + html[m.end():]


def check_html(path: pathlib.Path) -> None:
    rel = path.relative_to(ROOT)
    html = original = path.read_text(encoding="utf-8")

    csp = re.search(r'<meta\s+http-equiv=["\']Content-Security-Policy["\']\s+content=(["\'])(.*?)\1',
                    html, re.I)
    if not csp:
        html = insert_in_head(html, CSP_TAG)
        fixed.append(f"`{rel}`: added Content-Security-Policy")
    else:
        policy = csp.group(2)
        weak = [w for w in ("'unsafe-eval'", "script-src", " * ") if w in f" {policy} "]
        if "default-src 'none'" not in policy and "default-src 'self'" not in policy:
            weak.append("no restrictive default-src")
        if weak:
            remaining.append(f"`{rel}`: Content-Security-Policy is weaker than expected ({', '.join(weak)})")

    if not re.search(r'<meta\s+name=["\']referrer["\']', html, re.I):
        html = insert_in_head(html, REFERRER_TAG)
        fixed.append(f"`{rel}`: added no-referrer policy")

    def to_https(m: re.Match) -> str:
        url = m.group(2)
        if re.match(r"http://(localhost|127\.0\.0\.1)", url):
            return m.group(0)
        return f'{m.group(1)}="https://{url[len("http://"):]}"'

    new = re.sub(r'\b(href|src|action)="(http://[^"]+)"', to_https, html, flags=re.I)
    if new != html:
        fixed.append(f"`{rel}`: switched http:// links to https://")
        html = new

    def add_noopener(m: re.Match) -> str:
        tag = m.group(0)
        if re.search(r'\brel=["\'][^"\']*noopener', tag, re.I):
            return tag
        if re.search(r'\brel=["\']', tag, re.I):
            return re.sub(r'\brel=(["\'])', r'rel=\1noopener noreferrer ', tag, count=1, flags=re.I)
        return tag[:-1].rstrip() + ' rel="noopener noreferrer">'

    new = re.sub(r'<a\b[^>]*\btarget=["\']_blank["\'][^>]*>', add_noopener, html, flags=re.I)
    if new != html:
        fixed.append(f"`{rel}`: added rel=\"noopener noreferrer\" to links opening a new tab")
        html = new

    if re.search(r"<script\b", html, re.I):
        remaining.append(f"`{rel}`: contains a <script> tag (the CSP blocks it; remove it or adjust the CSP on purpose)")
    if re.search(r"<[^>]*\son[a-z]+\s*=", html, re.I):
        remaining.append(f"`{rel}`: contains an inline on...= event handler")

    if html != original:
        if APPLY:
            path.write_text(html, encoding="utf-8")
        else:
            remaining.extend(f for f in fixed if f.startswith(f"`{rel}`"))


def check_manifest() -> None:
    path = ROOT / "MetallibSupportPkg" / "manifest.json"
    rel = path.relative_to(ROOT)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        remaining.append(f"`{rel}`: cannot be read as JSON ({err})")
        return
    if not isinstance(data, list):
        remaining.append(f"`{rel}`: expected a list of entries")
        return
    seen = set()
    for i, entry in enumerate(data):
        where = f"`{rel}` entry {i} ({entry.get('build', '?') if isinstance(entry, dict) else '?'})"
        if not isinstance(entry, dict):
            remaining.append(f"{where}: not an object")
            continue
        missing = [k for k in ("build", "version", "sha1sum", "url") if not entry.get(k)]
        if missing:
            remaining.append(f"{where}: missing {', '.join(missing)}")
        url = str(entry.get("url", ""))
        m = re.match(r"https://([^/]+)/", url)
        if not m:
            remaining.append(f"{where}: download URL is not https://")
        elif m.group(1).lower() not in ALLOWED_HOSTS:
            remaining.append(f"{where}: download URL points to unexpected host {m.group(1)}")
        if entry.get("sha1sum") and not re.fullmatch(r"[0-9a-f]{40}", str(entry["sha1sum"])):
            remaining.append(f"{where}: sha1sum is not a 40-character hex string")
        if entry.get("build") in seen:
            remaining.append(f"{where}: duplicate build")
        seen.add(entry.get("build"))


def main() -> int:
    for page in sorted(ROOT.glob("*.html")):
        check_html(page)
    check_manifest()

    out = []
    if fixed and APPLY:
        out += ["### Fixed automatically", *[f"- {f}" for f in fixed], ""]
    if remaining:
        out += ["### Needs a manual fix", *[f"- {r}" for r in remaining], ""]
    if not out:
        out = ["No problems found."]
    print("\n".join(out))
    return 2 if remaining else 0


if __name__ == "__main__":
    sys.exit(main())
