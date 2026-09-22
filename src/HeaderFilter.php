<?php

declare(strict_types=1);

namespace MiniProxy;

/**
 * Handles filtering and transformation of HTTP headers for proxy operations.
 *
 * Request headers: Strips hop-by-hop headers and rewrites Origin.
 * Response headers: Uses a whitelist approach to prevent forwarding dangerous
 * headers (Set-Cookie, HSTS, CSP) from proxied sites to the client.
 */
class HeaderFilter
{
    /**
     * Headers stripped from browser requests before forwarding to the destination.
     * These are either hop-by-hop headers or headers that cURL should set itself.
     *
     * @var list<string>
     */
    private const STRIPPED_REQUEST_HEADERS = [
        'accept-encoding', // Let cURL negotiate compression
        'content-length',  // cURL recalculates this
        'host',            // cURL sets this from the URL
        'origin',          // Rewritten to match destination
    ];

    /**
     * Response headers allowed to be forwarded to the client (whitelist).
     *
     * Headers NOT on this list are silently dropped. This prevents forwarding
     * dangerous headers like Set-Cookie (session fixation on proxy domain),
     * Strict-Transport-Security (HSTS hijacking), and Content-Security-Policy
     * (may conflict with proxy rewriting).
     *
     * Stored as a name => true map for O(1) lookups in forwardResponseHeaders().
     *
     * @var array<string, true>
     */
    private const ALLOWED_RESPONSE_HEADERS = [
        'content-type' => true,
        'cache-control' => true,
        'expires' => true,
        'last-modified' => true,
        'etag' => true,
        'pragma' => true,
        'date' => true,
        'vary' => true,
        'content-language' => true,
        'content-disposition' => true,
        'accept-ranges' => true,
        'age' => true,
        'retry-after' => true,
    ];

    /**
     * Extracts the target URL from a 3xx response's Location header.
     *
     * Values are parsed leniently per RFC 7231: surrounding whitespace is
     * removed and the value must be a non-empty printable string.
     *
     * @param string $rawHeaders Raw response headers (possibly multiple blocks).
     * @return string|null The redirect target URL, or null if absent/invalid.
     */
    public static function getRedirectLocation(string $rawHeaders): ?string
    {
        foreach (preg_split('/\r?\n/', $rawHeaders) ?: [] as $line) {
            $colonPos = strpos($line, ':');
            if ($colonPos === false) {
                continue;
            }
            if (strtolower(trim(substr($line, 0, $colonPos))) !== 'location') {
                continue;
            }
            $value = trim(substr($line, $colonPos + 1));
            if (preg_match('/^[\x21-\x7E]+$/', $value) !== 1) {
                continue; // Reject empty/control-character injection
            }
            return $value;
        }

        return null;
    }

    /**
     * Prepares request headers for forwarding to the destination server.
     *
     * Strips hop-by-hop headers, adds X-Forwarded-For (if not anonymizing),
     * and rewrites the Origin header to match the destination.
     *
     * @param string       $destinationUrl The target URL being proxied.
     * @param bool         $anonymize      Whether to hide the client's IP.
     * @param list<string> $blockedHeaders Additional header names to strip (case-insensitive).
     * @return array{headers: list<string>, removed: list<string>}
     */
    public static function prepareRequestHeaders(
        string $destinationUrl,
        bool $anonymize,
        array $blockedHeaders = []
    ): array {
        $browserHeaders = self::getAllHeaders();
        $blockedLower = array_map('strtolower', $blockedHeaders);
        $stripList = array_merge(self::STRIPPED_REQUEST_HEADERS, $blockedLower);
        $removedKeys = self::removeKeys($browserHeaders, $stripList);
        $removedLower = array_map('strtolower', $removedKeys);

        // Convert associative array to indexed array of "Name: Value" strings for cURL
        $curlHeaders = [];
        foreach ($browserHeaders as $name => $value) {
            $curlHeaders[] = $name . ': ' . $value;
        }

        // Add X-Forwarded-For if not anonymizing
        if (!$anonymize) {
            $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
            if ($remoteAddr !== '') {
                $curlHeaders[] = 'X-Forwarded-For: ' . $remoteAddr;
            }
        }

        // Rewrite Origin header to point to the actual destination
        if (in_array('origin', $removedLower, true) && !in_array('origin', $blockedLower, true)) {
            $urlParts = parse_url($destinationUrl);
            if ($urlParts !== false && isset($urlParts['scheme'], $urlParts['host'])) {
                $port = isset($urlParts['port']) ? ':' . $urlParts['port'] : '';
                $curlHeaders[] = 'Origin: ' . $urlParts['scheme'] . '://' . $urlParts['host'] . $port;
            }
        }

        // Log header names only (never values) to avoid leaking credentials
        Logger::debug('Forwarding headers: ' . ($curlHeaders === [] ? 'none' : implode(', ', array_map(
            static fn(string $h): string => explode(':', $h, 2)[0],
            $curlHeaders
        ))));
        if ($removedLower !== [] || $blockedLower !== []) {
            Logger::debug('Stripped headers: ' . implode(', ', array_unique(array_merge($removedLower, $blockedLower))));
        }

        return ['headers' => $curlHeaders, 'removed' => $removedLower];
    }

    /**
     * Filters and forwards response headers using a whitelist approach.
     *
     * Only headers on the ALLOWED_RESPONSE_HEADERS list are forwarded.
     * The HTTP status line (e.g., "HTTP/1.1 200 OK") is always forwarded.
     *
     * @param list<string> $headerLines Raw header lines from the proxied response.
     */
    public static function forwardResponseHeaders(array $headerLines): void
    {
        foreach ($headerLines as $header) {
            $header = trim($header);
            if ($header === '') {
                continue;
            }

            // Always forward the HTTP status line
            if (str_starts_with($header, 'HTTP/')) {
                header($header, true);
                continue;
            }

            $colonPos = strpos($header, ':');
            if ($colonPos === false) {
                continue;
            }

            $headerName = strtolower(trim(substr($header, 0, $colonPos)));
            if (isset(self::ALLOWED_RESPONSE_HEADERS[$headerName])) {
                header($header, false);
            } else {
                Logger::debug('Dropped response header: ' . $headerName);
            }
        }
    }

    /**
     * Gets all HTTP request headers.
     *
     * Uses the native getallheaders() when available (Apache, PHP-FPM 7.0+),
     * with a fallback that reconstructs headers from $_SERVER for other SAPIs.
     *
     * @return array<string, string>
     */
    private static function getAllHeaders(): array
    {
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            return $headers !== false ? $headers : [];
        }

        // Fallback: reconstruct headers from $_SERVER variables
        $result = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $headerName = str_replace(
                    ' ',
                    '-',
                    ucwords(strtolower(str_replace('_', ' ', substr($key, 5))))
                );
                $result[$headerName] = (string) $value;
            }
        }

        return $result;
    }

    /**
     * Removes keys from an associative array using case-insensitive matching.
     *
     * @param array<string, string> $assoc       The array to modify (by reference).
     * @param list<string>          $keysToRemove Keys to remove (case-insensitive).
     * @return list<string> The original-cased keys that were actually removed.
     */
    private static function removeKeys(array &$assoc, array $keysToRemove): array
    {
        $keyMap = [];
        foreach (array_keys($assoc) as $key) {
            $keyMap[strtolower($key)] = $key;
        }

        $removedKeys = [];
        foreach ($keysToRemove as $key) {
            $lowerKey = strtolower($key);
            if (isset($keyMap[$lowerKey])) {
                unset($assoc[$keyMap[$lowerKey]]);
                $removedKeys[] = $keyMap[$lowerKey];
            }
        }

        return $removedKeys;
    }
}
