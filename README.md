# miniProxy

*by Joshua Dick — modernized fork*

*[http://joshdick.github.io/miniProxy](http://joshdick.github.io/miniProxy)*

> **Note:** Upstream miniProxy was archived on April 26th, 2020 and is no longer maintained by its original author. This fork modernizes the codebase (PHP 8.1+, `.env` configuration, modular `src/` classes, and security hardening). Use at your own risk; see the [GNU GPL v3 license](https://www.gnu.org/licenses/gpl-3.0.html).

---

## About miniProxy

miniProxy is a simple web proxy written in PHP that can allow you to bypass Internet content filters, or to browse the internet anonymously. miniProxy is licensed under the [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.html). miniProxy is the successor to [PageForward](http://pageforward.sf.net).

## Prerequisites

* PHP 8.1 or later with the `curl`, `mbstring`, `dom`, and `xml` extensions (PHP 8.4+ recommended — see [Performance](#performance))
* Any web server that runs PHP (or PHP's built-in server for local use)

## Installation and Use

1. Copy this project to your web server (document root must include `miniProxy.php` **and** the `src/` folder).
2. Optionally copy `.env.example` to `.env` and adjust the settings (see below). Without a `.env` file, sane defaults are used.
3. Access `miniProxy.php` directly in a browser. You'll be presented with a landing page to enter a URL.

Quick local test:

```bash
php -S localhost:8080
# then open http://localhost:8080/miniProxy.php
```

## Configuration (.env)

All settings are configured via environment variables, typically through a `.env` file in the project root. See [.env.example](.env.example) for the full list with defaults:

| Variable | Default | Description |
| --- | --- | --- |
| `WHITELIST_PATTERNS` | *(empty = allow all)* | Comma-separated regexes limiting which URLs may be proxied |
| `BLACKLIST_PATTERNS` | *(empty)* | Comma-separated regexes blocking URLs (takes priority over the whitelist) |
| `FORCE_CORS` | `false` | Enable cross-origin resource sharing for proxied sites |
| `DISALLOW_LOCAL` | `true` | Block local/private network targets (SSRF protection) |
| `ANONYMIZE` | `true` | Suppress the client's IP in `X-Forwarded-For` |
| `BLOCK_HEADERS` | *(empty = forward all)* | Comma-separated request headers stripped before forwarding (case-insensitive, in addition to built-in hop-by-hop headers) |
| `START_URL` | *(empty = landing page)* | URL proxied by default when no target is given |
| `LANDING_EXAMPLE_URL` | `https://example.net` | Example URL shown on the landing page |
| `MAX_RESPONSE_SIZE` | `10485760` | Maximum upstream response size in bytes |
| `CONNECT_TIMEOUT` | `10` | cURL connection timeout (seconds) |
| `REQUEST_TIMEOUT` | `30` | cURL total request timeout (seconds) |
| `MAX_REDIRECTS` | `5` | Maximum redirects followed (each hop is re-validated) |
| `DNS_CACHE_TTL` | `300` | Seconds to cache validated DNS results per request (`0` disables) |
| `ALLOWED_METHODS` | `GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS` | HTTP methods allowed upstream |
| `LOG_FILE` | *(empty = disabled)* | Path to a log file; each request appended with timestamp, IP, method, URL, status, bytes, duration |
| `LOG_LEVEL` | `access` | Minimum verbosity: `error`, `access`, `info`, or `debug` |

Real environment variables take priority over `.env` values.

### Logging

Set `LOG_FILE` to enable per-request logging. Level `access` logs one line per
request (`IP METHOD URL STATUS BYTES SECONDS`); `info` additionally logs
redirect hops and responses; `debug` adds DNS validation results, upstream
request/response details, and forwarded/stripped header *names only* (values
are never logged, so credentials stay out of logs). The file rotates once it
exceeds 20 MB (previous copy kept as `.log.1`).

## Project Structure

```
miniProxy.php       Front controller: .env loading, routing, redirect loop, output
src/
  Config.php        Configuration value object
  ProxyClient.php   Hardened cURL client (DNS pinning, TLS verification, timeouts)
  UrlValidator.php  Whitelist/blacklist + SSRF protection (private IPs, metadata endpoints)
  HeaderFilter.php  Request/response header filtering, redirect Location parsing
  Logger.php        Leveled file logger (error/access/info/debug)
  ContentRewriter.php  HTML/CSS/srcset URL rewriting, XHR interception
  ErrorHandler.php  Error responses and the landing page
.env.example        Documented configuration template
```

## Security Features

* DNS pinning via `CURLOPT_RESOLVE` (prevents DNS rebinding)
* Re-validation of every redirect hop (prevents SSRF via open redirects)
* Private/reserved IP range and cloud metadata endpoint blocking
* Strict TLS certificate verification
* Response header whitelist (no `Set-Cookie`/HSTS/CSP leakage from proxied sites)
* Response size and timeout limits

## Performance

On PHP 8.4+ the proxy automatically takes advantage of:

* **New HTML5 parser** — proxified HTML is parsed with `Dom\HTMLDocument` (lexbor-based), which is significantly faster and more standards-compliant than the legacy `DOMDocument` parser used as fallback on older PHP versions.
* **UTF-8 fast path** — valid UTF-8 responses (the overwhelmingly common case) skip character-set detection entirely via `mb_check_encoding()`; only non-UTF-8 responses fall back to detection + conversion, and are scrubbed with `mb_scrub()` so the parser always receives well-formed input.
* **O(1) header filtering** — the response header whitelist uses hash lookups instead of linear scans.
* **Per-request DNS cache** — a redirect chain that revisits the same host (or round-trips between hosts) resolves each hostname at most once per request (TTL: `DNS_CACHE_TTL`, default 300s). Cached IPs stay pinned via `CURLOPT_RESOLVE`, keeping the DNS-rebinding window equal to the cache TTL.
* **304 Not Modified passthrough** — browser validator headers (`If-None-Match` / `If-Modified-Since`) are forwarded upstream; a `304` response is relayed immediately with an empty body and no HTML parsing or rewriting.

For production deployments, enable OPcache (always) and optionally the JIT (off unless a buffer size is configured):

```ini
opcache.enable=1
opcache.jit=tracing
opcache.jit_buffer_size=64M
```

## Known Limitations

* `<object>` tags are not handled
* No cookie support
* Basic AJAX support, but only for browsers that use `XMLHttpRequest`

## Contact and Feedback

If you'd like to contribute to miniProxy or file a bug or feature request, please visit [its GitHub page](https://github.com/joshdick/miniProxy).

