<?php

declare(strict_types=1);

namespace MiniProxy;

/**
 * Executes HTTP requests via cURL with security hardening.
 *
 * Security features:
 * - DNS pinning via CURLOPT_RESOLVE (prevents DNS rebinding)
 * - Explicit TLS certificate verification
 * - Connection and request timeouts
 * - Response size limits (CURLOPT_MAXFILESIZE)
 * - No automatic redirect following (handled by caller with re-validation)
 * - HTTP method allowlist enforcement
 * - Raw body forwarding for non-form POST data (JSON, XML, etc.)
 */
class ProxyClient
{
    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Executes an HTTP request to the destination URL.
     *
     * @param string      $url        The destination URL.
     * @param string|null $method     HTTP method to send upstream. Falls back to
     *                                $_SERVER['REQUEST_METHOD'] when null. The caller
     *                                is responsible for redirect method downgrades.
     * @param string|null $resolvedIp Pre-resolved IP address for DNS pinning.
     * @param string|null $host       The original hostname (for CURLOPT_RESOLVE).
     * @param int|null    $port       The destination port (for CURLOPT_RESOLVE).
     * @return array{headers: string, body: string, responseInfo: array<string, mixed>}
     */
    public function execute(
        string $url,
        ?string $method = null,
        ?string $resolvedIp = null,
        ?string $host = null,
        ?int $port = null
    ): array {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0 (compatible; miniProxy)';

        $ch = curl_init();
        if ($ch === false) {
            ErrorHandler::sendError(500, 'Failed to initialize cURL.');
        }

        // ── Security: DNS Pinning ──
        // Forces cURL to connect to the pre-validated IP address, preventing
        // DNS rebinding attacks where the DNS record changes between our
        // validation check and cURL's own resolution.
        if ($resolvedIp !== null && $host !== null && $port !== null) {
            // IPv6 addresses must be bracketed inside CURLOPT_RESOLVE entries.
            $ipForResolve = str_contains($resolvedIp, ':') ? '[' . $resolvedIp . ']' : $resolvedIp;
            curl_setopt($ch, CURLOPT_RESOLVE, ["{$host}:{$port}:{$ipForResolve}"]);
            Logger::debug('DNS pinned ' . $host . ':' . $port . ' -> ' . $resolvedIp);
        }

        // ── Security: TLS Verification ──
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        // ── Security: Timeouts and Size Limits ──
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->config->connectTimeout);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->config->requestTimeout);
        curl_setopt($ch, CURLOPT_MAXFILESIZE, $this->config->maxResponseSize);

        // ── Security: Disable Automatic Redirect Following ──
        // Redirects are handled by the main loop with URL re-validation
        // at each hop to prevent redirect-based SSRF.
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 0);

        // ── Request Configuration ──
        curl_setopt($ch, CURLOPT_USERAGENT, $userAgent);
        curl_setopt($ch, CURLOPT_ENCODING, '');    // Accept all encodings, let cURL decompress
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        // ── Capture Response Headers Separately ──
        // Using CURLOPT_HEADERFUNCTION avoids the expensive substr() operation
        // on potentially large response strings to split headers from body.
        $responseHeaders = '';
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, function (\CurlHandle $ch, string $header) use (&$responseHeaders): int {
            $responseHeaders .= $header;
            return strlen($header);
        });

        // ── Prepare and Forward Request Headers ──
        $headerData = HeaderFilter::prepareRequestHeaders(
            $url,
            $this->config->anonymize,
            $this->config->blockRequestHeaders
        );
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headerData['headers']);

        // ── Configure HTTP Method and Body ──
        $this->configureMethod($ch, $method ?? ($_SERVER['REQUEST_METHOD'] ?? 'GET'));

        // ── Set Request URL ──
        curl_setopt($ch, CURLOPT_URL, $url);

        Logger::debug('Upstream request ' . ($method ?? ($_SERVER['REQUEST_METHOD'] ?? 'GET')) . ' ' . $url);

        // ── Execute Request ──
        $responseBody = curl_exec($ch);
        if ($responseBody === false) {
            $error = curl_error($ch);
            $errno = curl_errno($ch);
            unset($ch); // curl_close() is deprecated in PHP 8.5

            if ($errno === CURLE_FILESIZE_EXCEEDED) {
                ErrorHandler::sendError(413, 'The proxied resource exceeds the maximum allowed size.');
            }
            if ($errno === CURLE_OPERATION_TIMEDOUT || $errno === CURLE_OPERATION_TIMEOUTED) {
                ErrorHandler::sendError(504, 'The proxied server did not respond in time.');
            }

            ErrorHandler::sendError(502, 'Proxy request failed: ' . $error);
        }

        $responseInfo = curl_getinfo($ch);
        unset($ch); // curl_close() is deprecated in PHP 8.5

        Logger::debug(
            'Upstream response ' . $url . ' -> HTTP ' . ($responseInfo['http_code'] ?? 0)
            . ' ' . strlen((string) $responseBody) . ' bytes in '
            . round((float) ($responseInfo['total_time'] ?? 0), 3) . 's (final URL: ' . ($responseInfo['url'] ?? $url) . ')'
        );

        return [
            'headers' => $responseHeaders,
            'body' => (string) $responseBody,
            'responseInfo' => $responseInfo,
        ];
    }

    /**
     * Configures the cURL handle for the request's HTTP method.
     *
     * Enforces an allowlist of HTTP methods. Preserves raw POST body for
     * non-form-encoded content types (JSON, XML, multipart) instead of
     * re-encoding through parse_str/http_build_query.
     *
     * @param \CurlHandle $ch     The cURL handle to configure.
     * @param string      $method The HTTP method to send upstream.
     */
    private function configureMethod(\CurlHandle $ch, string $method): void
    {
        if (!in_array($method, $this->config->allowedMethods, true)) {
            ErrorHandler::sendError(405, 'HTTP method not allowed: ' . $method);
        }

        switch ($method) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);

                $rawBody = file_get_contents('php://input');
                if ($rawBody === false) {
                    $rawBody = '';
                }

                $contentType = $_SERVER['CONTENT_TYPE'] ?? '';

                // Only parse and strip miniProxyFormAction from URL-encoded form data.
                // All other content types (JSON, XML, multipart) are forwarded verbatim.
                if (str_contains($contentType, 'application/x-www-form-urlencoded')) {
                    $postData = [];
                    parse_str($rawBody, $postData);
                    if (isset($postData['miniProxyFormAction'])) {
                        unset($postData['miniProxyFormAction']);
                    }
                    $rawBody = http_build_query($postData);
                }

                curl_setopt($ch, CURLOPT_POSTFIELDS, $rawBody);
                break;

            case 'PUT':
            case 'PATCH':
            case 'DELETE':
                // Use CURLOPT_CUSTOMREQUEST instead of deprecated CURLOPT_PUT
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

                $rawBody = file_get_contents('php://input');
                if ($rawBody !== false && $rawBody !== '') {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $rawBody);
                }
                break;

            case 'HEAD':
                curl_setopt($ch, CURLOPT_NOBODY, true);
                break;

            case 'OPTIONS':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'OPTIONS');
                break;

            // GET is the cURL default — no special configuration needed
        }
    }
}
