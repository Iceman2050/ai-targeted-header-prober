"""ai-targeted-header-prober: audit HTTP response headers for AI-targeted
directives and hidden prompt-injection payloads.

Hook (2026-10-16): Signals Corps scanned 217M Common Crawl responses —
7,959 sites send AI-targeted headers, 30 attempting indirect prompt
injection (WebProNews; also The Register). Headers never render in
browsers, so this is an invisible injection channel.

Deterministic fetch + pattern flags. Not a classifier. This probes
third-party sites offensively — only scan sites you are authorized to
test, or your own infrastructure.
"""

import ipaddress
import re
import socket
import urllib.parse
import urllib.request

VERSION = "1.0.0"

# Header names that carry AI-scraper/agent directives.
AI_DIRECTIVE_NAMES = (
    "x-ai-scraper", "x-ai-agent", "x-llm-policy", "x-agent-policy",
    "x-ai-training", "x-ai-index", "ai-agent-policy",
)

# Name fragments suggesting an AI/scraper-targeted header.
AI_NAME_FRAGMENTS = (
    "ai-agent", "ai-scraper", "llm-", "gpt-", "gptbot", "claude",
    "anthropic", "openai", "scraper-directive", "agent-instruction",
)

# Value patterns indicating hidden prompt-injection payloads.
INJECTION_PATTERNS = (
    re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|earlier)\b.{0,40}\binstructions?\b", re.I),
    re.compile(r"\byou are (now|an?)\b", re.I),
    re.compile(r"\bsystem prompt\b", re.I),
    re.compile(r"\bexfiltrat\w*\b", re.I),
    re.compile(r"\bsend (to|data|credentials?)\b", re.I),
    re.compile(r"\bcurl\b.{0,30}http", re.I),
    re.compile(r"\bwget\b.{0,30}http", re.I),
)

# Well-known AI bot tokens (x-robots-tag values naming AI crawlers).
AI_BOT_TOKENS = (
    "gptbot", "chatgpt-user", "claudebot", "anthropic-ai",
    "google-extended", "ccbot", "bytespider", "diffbot",
)


def _is_public_host(host):
    """Reject private/loopback/link-local targets (authorized-testing guard)."""
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except socket.gaierror:
        return False
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        try:
            if not ipaddress.ip_address(sockaddr[0]).is_global:
                return False
        except ValueError:
            return False
    return True


def fetch_headers(url, timeout=10):
    """Fetch a URL's response headers. Returns dict of lowercase header
    names -> value lists. Raises ValueError on unsafe targets."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("only http/https URLs are probed")
    if not _is_public_host(parsed.hostname or ""):
        raise ValueError("refusing non-public target: %s" % parsed.hostname)
    req = urllib.request.Request(
        url, headers={"User-Agent": "ai-targeted-header-prober/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        headers = {}
        for name, value in resp.getheaders():
            headers.setdefault(name.lower(), []).append(value)
    return headers


def flag_headers(headers):
    """Flag AI-targeted directives and injection payloads.

    Returns a list of finding dicts:
    {"header", "value", "flag", "severity", "reason"}.
    Severities: INFO / MEDIUM / HIGH / CRITICAL.
    """
    findings = []
    for name, values in headers.items():
        for value in values:
            nl = name.lower()
            # 1. Known AI-directive header names -> MEDIUM (directive channel).
            if nl in AI_DIRECTIVE_NAMES:
                findings.append({
                    "header": name, "value": value,
                    "flag": "ai-directive-header", "severity": "MEDIUM",
                    "reason": ("Site publishes machine-readable directives "
                               "targeted at AI scrapers/agents in '%s' — a "
                               "channel invisible to human visitors." % name),
                })
                continue
            # 2. Name fragments suggesting AI targeting -> INFO.
            if any(frag in nl for frag in AI_NAME_FRAGMENTS):
                findings.append({
                    "header": name, "value": value,
                    "flag": "ai-suggestive-header", "severity": "INFO",
                    "reason": ("Header name '%s' looks AI/scraper-targeted; "
                               "review what instructions it carries." % name),
                })
            # 3. Injection patterns in ANY header value -> CRITICAL.
            for pat in INJECTION_PATTERNS:
                if pat.search(value):
                    findings.append({
                        "header": name, "value": value,
                        "flag": "hidden-injection-payload",
                        "severity": "CRITICAL",
                        "reason": ("Header value matches a hidden "
                                   "instruction pattern — a likely indirect "
                                   "prompt-injection payload. Per Signals "
                                   "Corps (Oct 2026), 30 sites in the wild "
                                   "attempt this."),
                    })
                    break
            # 4. x-robots-tag naming AI crawlers -> INFO (visibility).
            if nl == "x-robots-tag":
                bots = [b for b in AI_BOT_TOKENS if b in value.lower()]
                if bots:
                    findings.append({
                        "header": name, "value": value,
                        "flag": "ai-crawler-policy", "severity": "INFO",
                        "reason": ("x-robots-tag names AI crawlers: %s — the "
                                   "site is actively managing AI access."
                                   % ", ".join(bots)),
                    })
    return findings


def probe(url, timeout=10):
    """Probe a URL and return a report dict."""
    headers = fetch_headers(url, timeout=timeout)
    findings = flag_headers(headers)
    return {
        "url": url,
        "headers_seen": len(headers),
        "findings": findings,
        "verdict": ("CLEAN — no AI-targeted headers or hidden payloads "
                    "detected" if not findings
                    else "%d finding(s)" % len(findings)),
    }


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(
        description="Audit HTTP response headers for AI-targeted directives "
                    "and hidden prompt-injection payloads.")
    ap.add_argument("url", help="URL to probe (public targets only)")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args(argv)
    try:
        print(json.dumps(probe(args.url, timeout=args.timeout), indent=2))
    except ValueError as e:
        print("ERROR: %s" % e)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
