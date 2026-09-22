<?php

declare(strict_types=1);

namespace MiniProxy;

/**
 * Configuration for the miniProxy application.
 *
 * All proxy behavior is controlled through this class.
 * Modify the default values or instantiate with custom settings.
 */
class Config
{
    /**
     * URL whitelist patterns (regex).
     *
     * If non-empty, only URLs matching at least one pattern will be proxied.
     * If empty (default), all URLs are allowed (subject to blacklist and local checks).
     *
     * @var list<string>
     */
    public array $whitelistPatterns = [];

    /**
     * URL blacklist patterns (regex).
     *
     * URLs matching any pattern will be blocked. Blacklist takes priority over whitelist.
     *
     * @var list<string>
     */
    public array $blacklistPatterns = [];

    /** Enable CORS (cross-origin resource sharing) for proxied sites. */
    public bool $forceCORS = false;

    /** Block access to local/private network addresses (SSRF protection). */
    public bool $disallowLocal = true;

    /** Hide the client's IP address from proxied sites (suppress X-Forwarded-For). */
    public bool $anonymize = true;

    /** Default URL to proxy when miniProxy is accessed without a target URL. */
    public string $startURL = '';

    /** Example URL shown on the landing page. */
    public string $landingExampleURL = 'https://example.net';

    // --- Security Limits ---

    /** Maximum proxied response size in bytes (default: 10 MB). */
    public int $maxResponseSize = 10_485_760;

    /** cURL connection timeout in seconds. */
    public int $connectTimeout = 10;

    /** cURL total request timeout in seconds. */
    public int $requestTimeout = 30;

    /** Maximum number of HTTP redirects to follow (with re-validation at each hop). */
    public int $maxRedirects = 5;

    /**
     * Allowed HTTP methods.
     *
     * @var list<string>
     */
    public array $allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

    /**
     * Additional request headers to strip before forwarding to the destination.
     *
     * Names are matched case-insensitively and are removed in addition to the
     * built-in hop-by-hop headers. Use this to stop sensitive client headers
     * (e.g. Authorization, Cookie) from reaching proxied sites.
     *
     * @var list<string>
     */
    public array $blockRequestHeaders = [];

    /** Path to a log file for request/error logging. Empty = logging disabled. */
    public string $logFile = '';

    /**
     * Minimum log verbosity: 'error', 'access', 'info' or 'debug'.
     *
     * 'debug' logs everything; 'error' logs only errors.
     */
    public string $logLevel = 'access';

    /**
     * How long (in seconds) validated DNS results are cached per request.
     *
     * A request that visits the same host multiple times (e.g. a redirect chain
     * bouncing between hosts) resolves each host at most once per request.
     * Set to 0 to disable caching. Cached IPs remain pinned via CURLOPT_RESOLVE,
     * so this bounds the DNS rebinding TOCTOU window to the cache TTL.
     */
    public int $dnsCacheTtl = 300;

    /**
     * Builds a regex that matches all HTTP[S] URLs for a given hostname,
     * including subdomains.
     *
     * Usage: Config::getHostnamePattern('example.net')
     * Returns: @^https?://([a-z0-9-]+\.)*example\.net@i
     */
    public static function getHostnamePattern(string $hostname): string
    {
        $escapedHostname = str_replace('.', '\\.', $hostname);
        return '@^https?://([a-z0-9-]+\\.)*' . $escapedHostname . '@i';
    }
}
