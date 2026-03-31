"""
Config Extractor - Playwright crawler that extracts URLs from web app JSON configurations.

Navigates to a web app, intercepts JSON config files (network responses + DOM),
and harvests all HTTP/HTTPS URLs found within them.
"""

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import aiohttp

from playwright.async_api import async_playwright, Response, Page

MAX_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


@dataclass
class ConfigSource:
    origin: str
    raw_text: str = ""
    json_payload: object = None
    urls_found: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class AuthHint:
    """Auth evidence from static analysis of config JSON context."""
    method: str          # "api_key" | "bearer" | "oauth" | "basic" | "cookie_session" | "custom_header"
    confidence: str      # "high" | "medium" | "low"
    evidence_key: str    # the JSON key that triggered detection
    evidence_value: str  # redacted value
    source: str          # which ConfigSource.origin it came from


@dataclass
class ProbeResult:
    """Auth evidence from HTTP probing."""
    url: str
    status_code: int | None
    www_authenticate: str | None
    detected_method: str | None  # "basic" | "bearer" | "negotiate" | "none" | "unknown" | "forbidden"
    error: str | None = None


@dataclass
class AuthInfo:
    """Combined auth info for a single URL."""
    url: str
    static_hints: list[AuthHint] = field(default_factory=list)
    probe_result: ProbeResult | None = None
    best_guess: str = "unknown"


# ---------------------------------------------------------------------------
# Auth key patterns for static analysis
# ---------------------------------------------------------------------------

AUTH_KEY_PATTERNS: dict[str, list[re.Pattern]] = {
    "api_key": [re.compile(r"^(api[_-]?key|secret[_-]?key|api[_-]?secret|x[_-]api[_-]key)$", re.I)],
    "bearer": [re.compile(r"^(bearer[_-]?token|access[_-]?token|auth[_-]?token|token)$", re.I)],
    "oauth": [re.compile(r"^(oauth|client[_-]?id|client[_-]?secret|grant[_-]?type|redirect[_-]?uri)$", re.I)],
    "basic": [re.compile(r"^(username|password|user|passwd)$", re.I)],
    "cookie_session": [re.compile(r"^(cookie|session[_-]?id|session[_-]?token|csrf[_-]?token)$", re.I)],
    "custom_header": [re.compile(r"^(authorization|x-api-key|x-auth-token)$", re.I)],
}


def _redact_value(value: str) -> str:
    """Redact a credential value, showing only the first 4 characters."""
    if not isinstance(value, str) or len(value) < 4:
        return "[present]"
    return value[:4] + "***"


def _match_auth_key(key: str) -> str | None:
    """Return the auth method name if key matches any AUTH_KEY_PATTERNS, else None."""
    for method, patterns in AUTH_KEY_PATTERNS.items():
        for pat in patterns:
            if pat.match(key):
                return method
    return None


def find_auth_context(obj, source_origin: str) -> list[AuthHint]:
    """Walk parsed JSON and find auth-related keys that are siblings of URL values."""
    hints: list[AuthHint] = []

    if not isinstance(obj, dict):
        if isinstance(obj, list):
            for item in obj:
                hints.extend(find_auth_context(item, source_origin))
        return hints

    # Check if this dict contains any URL values
    has_url = False
    for v in obj.values():
        if isinstance(v, str) and URL_RE.search(v):
            has_url = True
            break

    # Check sibling keys for auth patterns
    if has_url:
        for key, value in obj.items():
            method = _match_auth_key(key)
            if method:
                val_str = str(value) if not isinstance(value, str) else value
                hints.append(AuthHint(
                    method=method,
                    confidence="high",
                    evidence_key=key,
                    evidence_value=_redact_value(val_str),
                    source=source_origin,
                ))

    # Check child dicts for auth keys (medium confidence) when parent has URLs
    if has_url:
        for key, value in obj.items():
            if isinstance(value, dict):
                for child_key, child_value in value.items():
                    method = _match_auth_key(child_key)
                    if method:
                        val_str = str(child_value) if not isinstance(child_value, str) else child_value
                        hints.append(AuthHint(
                            method=method,
                            confidence="medium",
                            evidence_key=child_key,
                            evidence_value=_redact_value(val_str),
                            source=source_origin,
                        ))

    # Also check if this dict has auth keys and a child dict contains URLs (medium confidence)
    auth_keys_here = {}
    for key, value in obj.items():
        method = _match_auth_key(key)
        if method:
            val_str = str(value) if not isinstance(value, str) else value
            auth_keys_here[key] = (method, val_str)

    if auth_keys_here:
        for key, value in obj.items():
            if isinstance(value, dict):
                child_has_url = False
                for v in value.values():
                    if isinstance(v, str) and URL_RE.search(v):
                        child_has_url = True
                        break
                if child_has_url:
                    for auth_key, (method, val_str) in auth_keys_here.items():
                        # Avoid duplicating hints already added as "high"
                        if not any(h.evidence_key == auth_key and h.confidence == "high" for h in hints):
                            hints.append(AuthHint(
                                method=method,
                                confidence="medium",
                                evidence_key=auth_key,
                                evidence_value=_redact_value(val_str),
                                source=source_origin,
                            ))

    # Recurse into all children
    for value in obj.values():
        if isinstance(value, (dict, list)):
            hints.extend(find_auth_context(value, source_origin))

    return hints


def run_static_auth_analysis(sources: list[ConfigSource]) -> dict[str, AuthInfo]:
    """Run static auth analysis on all config sources, return dict keyed by URL."""
    auth_map: dict[str, AuthInfo] = {}

    # Collect all unique URLs first
    for src in sources:
        for url in src.urls_found:
            if url not in auth_map:
                auth_map[url] = AuthInfo(url=url)

    # Find auth hints from each source's parsed JSON
    for src in sources:
        if src.json_payload is None:
            continue
        hints = find_auth_context(src.json_payload, src.origin)
        if not hints:
            continue

        # Associate hints with URLs found in the same source
        for url in src.urls_found:
            if url in auth_map:
                auth_map[url].static_hints.extend(hints)

    return auth_map


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------

def _parse_www_authenticate(header: str) -> str:
    """Extract the auth scheme from a WWW-Authenticate header value."""
    scheme = header.strip().split()[0].lower() if header else ""
    mapping = {"basic": "basic", "bearer": "bearer", "negotiate": "negotiate", "ntlm": "negotiate"}
    return mapping.get(scheme, scheme or "unknown")


def _host_root_url(url: str) -> str | None:
    """Return scheme://host[:port]/ if the URL has a path beyond /, else None."""
    parsed = urlparse(url)
    if parsed.path and parsed.path.rstrip("/"):
        root = f"{parsed.scheme}://{parsed.netloc}/"
        return root
    return None


async def _do_probe_request(
    session: aiohttp.ClientSession,
    url: str,
    timeout: float,
) -> tuple[int, str | None, str]:
    """Make a HEAD (or GET fallback) request. Return (status_code, www_authenticate, location)."""
    async with session.head(url, timeout=aiohttp.ClientTimeout(total=timeout),
                            allow_redirects=False) as resp:
        status = resp.status
        if status == 405:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=False) as resp2:
                return (resp2.status,
                        resp2.headers.get("WWW-Authenticate"),
                        resp2.headers.get("Location", ""))
        return status, resp.headers.get("WWW-Authenticate"), resp.headers.get("Location", "")


def _classify_probe(status: int, www_auth: str | None, location: str = "") -> str:
    """Classify a probe response into a detected auth method string."""
    if status == 401:
        return _parse_www_authenticate(www_auth) if www_auth else "unknown"
    if status == 403:
        return "forbidden"
    if 200 <= status < 300:
        return "none"
    if 300 <= status < 400:
        if any(kw in location.lower() for kw in ("oauth", "authorize", "login", "auth")):
            return "oauth"
        return "redirect"
    if status == 400:
        return "bad_request"
    if status == 404:
        return "not_found"
    if status == 407:
        return "proxy_auth"
    if 500 <= status < 600:
        return "server_error"
    return "unknown"


async def _probe_single(
    session: aiohttp.ClientSession,
    url: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> ProbeResult:
    """Probe a single URL for auth requirements."""
    async with semaphore:
        try:
            status, www_auth, location = await _do_probe_request(session, url, timeout)
            method = _classify_probe(status, www_auth, location)

            # On 400/403/404, the specific path may not work or may block
            # unauthenticated requests — the host root can still reveal
            # the service's auth requirements more clearly
            if status in (400, 403, 404):
                root = _host_root_url(url)
                if root:
                    try:
                        root_status, root_www_auth, root_location = await _do_probe_request(session, root, timeout)
                        root_method = _classify_probe(root_status, root_www_auth, root_location)
                        # Use root result if it reveals auth info
                        if root_method not in ("bad_request", "forbidden", "not_found", "server_error", "unknown"):
                            return ProbeResult(
                                url=url,
                                status_code=root_status,
                                www_authenticate=root_www_auth,
                                detected_method=root_method,
                            )
                    except Exception:
                        pass  # root fallback failed, keep original result

            return ProbeResult(
                url=url,
                status_code=status,
                www_authenticate=www_auth,
                detected_method=method,
            )
        except Exception as e:
            return ProbeResult(
                url=url,
                status_code=None,
                www_authenticate=None,
                detected_method=None,
                error=str(e),
            )


async def probe_urls(
    urls: list[str],
    timeout: float = 5.0,
    max_concurrent: int = 10,
) -> list[ProbeResult]:
    """Probe a list of URLs for authentication requirements."""
    unique_urls = list(dict.fromkeys(urls))  # deduplicate, preserve order
    semaphore = asyncio.Semaphore(max_concurrent)
    async with aiohttp.ClientSession(
        headers={"User-Agent": "ConfigExtractor/1.0"},
    ) as session:
        tasks = [_probe_single(session, url, semaphore, timeout) for url in unique_urls]
        return await asyncio.gather(*tasks)


def merge_probe_results(auth_map: dict[str, AuthInfo], probes: list[ProbeResult]) -> None:
    """Merge probe results into the auth map."""
    for probe in probes:
        if probe.url in auth_map:
            auth_map[probe.url].probe_result = probe


def reconcile_auth(auth_map: dict[str, AuthInfo]) -> None:
    """Set best_guess on each AuthInfo by reconciling static hints and probe results."""
    for info in auth_map.values():
        probe = info.probe_result
        high_hints = [h for h in info.static_hints if h.confidence == "high"]
        any_hints = [h for h in info.static_hints if h.confidence in ("medium", "low")]

        # Priority 1: Probe WWW-Authenticate header (most authoritative)
        if probe and probe.www_authenticate:
            info.best_guess = _parse_www_authenticate(probe.www_authenticate)
        # Priority 2: High-confidence static hint
        elif high_hints:
            info.best_guess = high_hints[0].method
        # Priority 3: Probe returned 200 — no auth needed
        elif probe and probe.status_code and 200 <= probe.status_code < 300:
            info.best_guess = "none"
        # Priority 4: Probe detected a method (redirect to oauth, etc.)
        elif probe and probe.detected_method and probe.detected_method not in ("unknown", "forbidden", None):
            info.best_guess = probe.detected_method
        # Priority 5: Medium/low confidence static hint
        elif any_hints:
            info.best_guess = any_hints[0].method
        # Priority 6: Probe says forbidden (auth required but method unclear)
        elif probe and probe.detected_method == "forbidden":
            info.best_guess = "unknown (forbidden)"
        # else: stays "unknown"


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>}\]\)]+')


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)")


def extract_urls(obj, seen: set[str] | None = None) -> list[str]:
    """Recursively extract http/https URLs from a parsed JSON structure."""
    if seen is None:
        seen = set()
    urls: list[str] = []

    if isinstance(obj, str):
        for m in URL_RE.findall(obj):
            clean = _clean_url(m)
            if clean not in seen:
                seen.add(clean)
                urls.append(clean)
    elif isinstance(obj, dict):
        for v in obj.values():
            urls.extend(extract_urls(v, seen))
    elif isinstance(obj, list):
        for item in obj:
            urls.extend(extract_urls(item, seen))
    return urls


def extract_urls_from_text(text: str) -> list[str]:
    """Regex fallback: pull URLs directly from raw text."""
    seen: set[str] = set()
    urls: list[str] = []
    for m in URL_RE.findall(text):
        clean = _clean_url(m)
        if clean not in seen:
            seen.add(clean)
            urls.append(clean)
    return urls


# ---------------------------------------------------------------------------
# JSON sanitization (JS object -> JSON best-effort)
# ---------------------------------------------------------------------------

def sanitize_js_object(text: str) -> str:
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)   # line comments
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)   # block comments
    text = re.sub(r"'", '"', text)                            # single -> double quotes
    text = re.sub(r",\s*([}\]])", r"\1", text)               # trailing commas
    return text


def try_parse_json(text: str) -> tuple[object | None, str | None]:
    """Try to parse text as JSON, with JS-object sanitization fallback."""
    try:
        return json.loads(text), None
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return json.loads(sanitize_js_object(text)), None
    except (json.JSONDecodeError, ValueError) as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# Network interception
# ---------------------------------------------------------------------------

def _is_json_response(response: Response) -> bool:
    ct = response.headers.get("content-type", "")
    if "json" in ct:
        return True
    if response.url.split("?")[0].split("#")[0].endswith(".json"):
        return True
    return False


def _exceeds_size_limit(response: Response) -> bool:
    cl = response.headers.get("content-length", "")
    if cl.isdigit() and int(cl) > MAX_PAYLOAD_BYTES:
        return True
    return False


async def capture_response(
    response: Response,
    captured: list[tuple[str, str]],
) -> None:
    if response.status < 200 or response.status >= 300:
        return
    if not _is_json_response(response):
        return
    if _exceeds_size_limit(response):
        print(f"  [skip] Response too large: {response.url}", file=sys.stderr)
        return
    try:
        body = await response.text()
        if len(body) > MAX_PAYLOAD_BYTES:
            print(f"  [skip] Body too large: {response.url}", file=sys.stderr)
            return
        captured.append((response.url, body))
    except Exception:
        pass  # body unavailable (e.g. page navigated away)


def process_network_captures(captured: list[tuple[str, str]]) -> list[ConfigSource]:
    sources: list[ConfigSource] = []
    for url, body in captured:
        parsed, err = try_parse_json(body)
        if parsed is not None:
            urls = extract_urls(parsed)
        else:
            urls = extract_urls_from_text(body)
        if urls:
            sources.append(ConfigSource(
                origin=f"network: {url}",
                raw_text=body[:200],
                json_payload=parsed,
                urls_found=urls,
                error=err,
            ))
    return sources


# ---------------------------------------------------------------------------
# DOM scanning
# ---------------------------------------------------------------------------

# Regex to find JS variable assignments that look like config objects/arrays
CONFIG_ASSIGN_RE = re.compile(
    r'(?:window\.[\w.]+|(?:var|let|const)\s+\w+)\s*=\s*(\{[\s\S]*\}|\[[\s\S]*\])\s*;',
)


async def extract_from_dom(page: Page, captured_urls: set[str]) -> list[ConfigSource]:
    sources: list[ConfigSource] = []

    # Strategy A: <script type="application/json">
    for el in await page.query_selector_all('script[type="application/json"]'):
        text = (await el.inner_text()).strip()
        if not text:
            continue
        parsed, err = try_parse_json(text)
        if parsed is not None:
            urls = extract_urls(parsed)
        else:
            urls = extract_urls_from_text(text)
        if urls:
            sources.append(ConfigSource(
                origin="dom: <script type=\"application/json\">",
                raw_text=text[:200],
                json_payload=parsed,
                urls_found=urls,
                error=err,
            ))

    # Strategy B: inline scripts with global variable assignments
    for el in await page.query_selector_all("script:not([src])"):
        script_type = await el.get_attribute("type")
        if script_type and script_type != "text/javascript":
            continue
        text = (await el.inner_text()).strip()
        if not text or len(text) < 10:
            continue
        for match in CONFIG_ASSIGN_RE.finditer(text):
            json_str = match.group(1)
            parsed, err = try_parse_json(json_str)
            if parsed is not None:
                urls = extract_urls(parsed)
            else:
                urls = extract_urls_from_text(json_str)
            if urls:
                # Identify which variable was assigned
                assign_text = text[max(0, match.start() - 40):match.start() + 60]
                assign_label = assign_text.split("=")[0].strip()[-40:]
                sources.append(ConfigSource(
                    origin=f"dom: inline script ({assign_label})",
                    raw_text=json_str[:200],
                    json_payload=parsed,
                    urls_found=urls,
                    error=err,
                ))

    # Strategy C: <script src="*.json"> or <link href="*.json">
    for el in await page.query_selector_all(
        'script[src$=".json"], link[href$=".json"]'
    ):
        src = await el.get_attribute("src") or await el.get_attribute("href")
        if not src:
            continue
        abs_url = urljoin(page.url, src)
        if abs_url in captured_urls:
            continue  # already captured via network interception
        try:
            resp = await page.context.request.get(abs_url)
            body = await resp.text()
            parsed, err = try_parse_json(body)
            if parsed is not None:
                urls = extract_urls(parsed)
            else:
                urls = extract_urls_from_text(body)
            if urls:
                sources.append(ConfigSource(
                    origin=f"dom: referenced file {src}",
                    raw_text=body[:200],
                    json_payload=parsed,
                    urls_found=urls,
                    error=err,
                ))
        except Exception as e:
            print(f"  [warn] Could not fetch {abs_url}: {e}", file=sys.stderr)

    return sources


# ---------------------------------------------------------------------------
# Crawler orchestrator
# ---------------------------------------------------------------------------

async def crawl(
    url: str,
    timeout: int = 30000,
    wait_after_load: int = 5000,
    headed: bool = False,
) -> list[ConfigSource]:
    captured: list[tuple[str, str]] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=not headed)
        context = await browser.new_context()
        page = await context.new_page()

        page.on("response", lambda resp: asyncio.ensure_future(
            capture_response(resp, captured)
        ))

        print(f"Navigating to {url} ...")
        try:
            await page.goto(url, wait_until="networkidle", timeout=timeout)
        except Exception as e:
            print(f"  [warn] Navigation issue: {e}", file=sys.stderr)
            print("  Continuing with data captured so far...", file=sys.stderr)

        if wait_after_load > 0:
            print(f"Waiting {wait_after_load}ms for additional requests...")
            await page.wait_for_timeout(wait_after_load)

        # Process network captures
        print(f"Captured {len(captured)} JSON network responses.")
        network_sources = process_network_captures(captured)

        # Scan DOM
        captured_urls = {url for url, _ in captured}
        dom_sources = await extract_from_dom(page, captured_urls)

        await browser.close()

    return network_sources + dom_sources


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_results(
    sources: list[ConfigSource],
    auth_map: dict[str, AuthInfo] | None = None,
) -> None:
    if not sources:
        print("\nNo JSON configurations with URLs were found.")
        return

    all_urls: set[str] = set()
    print(f"\n{'=' * 70}")
    for src in sources:
        print(f"\n  Source: {src.origin}")
        if src.error:
            print(f"  (JSON parse error — used regex fallback: {src.error})")
        print(f"  URLs found: {len(src.urls_found)}")
        for u in src.urls_found:
            print(f"    {u}")
            all_urls.add(u)
    hosts: set[str] = set()
    for u in all_urls:
        host = urlparse(u).hostname
        if host:
            hosts.add(host)
    sorted_hosts = sorted(hosts)

    print(f"\n{'=' * 70}")
    print(f"Total config sources: {len(sources)}")
    print(f"Total unique URLs:    {len(all_urls)}")
    if sorted_hosts:
        print(f"\nUnique hosts ({len(sorted_hosts)}):")
        for h in sorted_hosts:
            print(f"    {h}")
    print(f"{'=' * 70}")

    # Auth analysis section
    if auth_map:
        print(f"\n{'=' * 70}")
        print("Authentication Analysis")
        print(f"{'=' * 70}")
        for url in sorted(auth_map):
            info = auth_map[url]
            print(f"\n  {url}")
            if info.static_hints:
                # Show the highest-confidence hint
                best = sorted(info.static_hints,
                              key=lambda h: {"high": 0, "medium": 1, "low": 2}.get(h.confidence, 3))[0]
                print(f"    Static:  {best.method} ({best.confidence}, key: \"{best.evidence_key}\")")
            else:
                print("    Static:  (none)")
            if info.probe_result:
                probe = info.probe_result
                if probe.error:
                    print(f"    Probe:   error — {probe.error}")
                elif probe.www_authenticate:
                    print(f"    Probe:   {probe.status_code} — WWW-Authenticate: {probe.www_authenticate}")
                else:
                    label = probe.detected_method or "unknown"
                    print(f"    Probe:   {probe.status_code} — {label}")
            print(f"    Verdict: {info.best_guess}")
        print(f"\n{'=' * 70}")

    print()


def write_results(
    sources: list[ConfigSource],
    path: str,
    auth_map: dict[str, AuthInfo] | None = None,
) -> None:
    all_urls: set[str] = set()
    entries = []
    for src in sources:
        entries.append({
            "source": src.origin,
            "urls": src.urls_found,
            "error": src.error,
        })
        all_urls.update(src.urls_found)

    hosts: set[str] = set()
    for u in all_urls:
        host = urlparse(u).hostname
        if host:
            hosts.add(host)

    output: dict = {
        "sources": entries,
        "unique_hosts": sorted(hosts),
    }

    if auth_map:
        auth_section: dict = {}
        for url, info in sorted(auth_map.items()):
            entry: dict = {"best_guess": info.best_guess}
            if info.static_hints:
                entry["static_hints"] = [
                    {
                        "method": h.method,
                        "confidence": h.confidence,
                        "evidence_key": h.evidence_key,
                    }
                    for h in info.static_hints
                ]
            if info.probe_result:
                p = info.probe_result
                entry["probe"] = {
                    "status_code": p.status_code,
                    "www_authenticate": p.www_authenticate,
                    "detected_method": p.detected_method,
                    "error": p.error,
                }
            auth_section[url] = entry
        output["auth"] = auth_section

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"Results written to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract URLs from a web app's JSON configuration files.",
    )
    parser.add_argument("url", help="Target web app URL")
    parser.add_argument("-o", "--output", help="Write results to a JSON file")
    parser.add_argument(
        "--timeout", type=int, default=30000,
        help="Navigation timeout in ms (default: 30000)",
    )
    parser.add_argument(
        "--wait-after-load", type=int, default=5000,
        help="Extra wait time in ms for lazy XHR (default: 5000)",
    )
    parser.add_argument(
        "--headed", action="store_true",
        help="Run browser in headed mode (visible window)",
    )
    parser.add_argument(
        "--probe", action="store_true",
        help="Probe discovered URLs for authentication requirements",
    )
    parser.add_argument(
        "--probe-timeout", type=int, default=5,
        help="Per-URL probe timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--probe-concurrency", type=int, default=10,
        help="Max concurrent probe requests (default: 10)",
    )
    args = parser.parse_args()

    sources = asyncio.run(crawl(
        url=args.url,
        timeout=args.timeout,
        wait_after_load=args.wait_after_load,
        headed=args.headed,
    ))

    # Auth analysis
    auth_map = run_static_auth_analysis(sources)

    if args.probe:
        all_urls = []
        for src in sources:
            all_urls.extend(src.urls_found)
        unique_urls = list(dict.fromkeys(all_urls))
        print(f"Probing {len(unique_urls)} URLs for authentication methods...")
        probes = asyncio.run(probe_urls(
            unique_urls,
            timeout=float(args.probe_timeout),
            max_concurrent=args.probe_concurrency,
        ))
        merge_probe_results(auth_map, probes)

    reconcile_auth(auth_map)

    print_results(sources, auth_map)

    if args.output:
        write_results(sources, args.output, auth_map)


if __name__ == "__main__":
    main()
