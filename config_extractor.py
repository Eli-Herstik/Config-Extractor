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

from playwright.async_api import async_playwright, Response, Page

MAX_PAYLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


@dataclass
class ConfigSource:
    origin: str
    raw_text: str = ""
    json_payload: object = None
    urls_found: list[str] = field(default_factory=list)
    error: str | None = None


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

def print_results(sources: list[ConfigSource]) -> None:
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
    print(f"{'=' * 70}\n")


def write_results(sources: list[ConfigSource], path: str) -> None:
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

    output = {
        "sources": entries,
        "unique_hosts": sorted(hosts),
    }
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
    args = parser.parse_args()

    sources = asyncio.run(crawl(
        url=args.url,
        timeout=args.timeout,
        wait_after_load=args.wait_after_load,
        headed=args.headed,
    ))

    print_results(sources)

    if args.output:
        write_results(sources, args.output)


if __name__ == "__main__":
    main()
