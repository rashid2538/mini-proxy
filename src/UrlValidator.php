<?php

declare(strict_types=1);

namespace MiniProxy;

/**
 * Validates URLs against whitelist/blacklist patterns and SSRF protections.
 *
 * Security features:
 * - Whitelist/blacklist pattern matching
 * - DNS resolution with IP validation (prevents DNS rebinding)
 * - Private/reserved IP range blocking
 * - IPv6-mapped IPv4 address detection
 * - Cloud metadata endpoint blocking (AWS, GCP, Azure)
 * - Fail-closed on DNS resolution failures
 */
class UrlValidator
{
    private Config $config;

    /**
     * Per-request DNS cache: hostname => ['ip' => string, 'expires' => float].
     *
     * Scoped to this validator instance (one HTTP request), so entries never
     * outlive the request that created them — a cheap TTL on top is still kept
     * to bound pinning staleness within long redirect chains.
     *
     * @var array<string, array{ip: string, expires: float}>
     */
    private array $dnsCache = [];

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Validates whether a URL is allowed to be proxied.
     *
     * Returns validation result including the resolved IP for DNS pinning.
     * When $disallowLocal is true, the resolved IP should be passed to
     * ProxyClient::execute() to prevent DNS rebinding attacks.
     *
     * @param string $url The URL to validate.
     * @return array{valid: bool, resolved_ip: string|null, host: string|null, port: int|null}
     */
    public function validate(string $url): array
    {
        $invalid = ['valid' => false, 'resolved_ip' => null, 'host' => null, 'port' => null];

        if (!$this->passesWhitelist($url) || !$this->passesBlacklist($url)) {
            return $invalid;
        }

        $parsedUrl = parse_url($url);
        if ($parsedUrl === false || !isset($parsedUrl['host'])) {
            return $invalid;
        }

        $host = $parsedUrl['host'];
        $scheme = $parsedUrl['scheme'] ?? 'http';
        $port = $parsedUrl['port'] ?? ($scheme === 'https' ? 443 : 80);

        if (!$this->config->disallowLocal) {
            return ['valid' => true, 'resolved_ip' => null, 'host' => $host, 'port' => $port];
        }

        // Resolve DNS and validate IP — the resolved IP will be pinned in cURL
        // to prevent DNS rebinding attacks (TOCTOU between validation and request)
        $resolvedIp = $this->resolveAndValidateHost($host);
        if ($resolvedIp === null) {
            return $invalid;
        }

        return ['valid' => true, 'resolved_ip' => $resolvedIp, 'host' => $host, 'port' => $port];
    }

    /**
     * Checks if the URL passes the whitelist.
     * An empty whitelist means all URLs are allowed.
     */
    private function passesWhitelist(string $url): bool
    {
        if (count($this->config->whitelistPatterns) === 0) {
            return true;
        }

        foreach ($this->config->whitelistPatterns as $pattern) {
            if (preg_match($pattern, $url) === 1) {
                Logger::debug('URL matched whitelist pattern ' . $pattern);
                return true;
            }
        }

        Logger::error('URL rejected: does not match any whitelist pattern: ' . $url);
        return false;
    }

    /**
     * Checks if the URL passes the blacklist.
     * An empty blacklist means no URLs are blocked.
     */
    private function passesBlacklist(string $url): bool
    {
        foreach ($this->config->blacklistPatterns as $pattern) {
            if (preg_match($pattern, $url) === 1) {
                Logger::error('URL rejected: matched blacklist pattern ' . $pattern . ': ' . $url);
                return false;
            }
        }

        return true;
    }

    /**
     * Resolves a hostname to an IP address and validates it is not private/reserved.
     *
     * Implements fail-closed behavior: if DNS resolution fails or any resolved IP
     * is private/reserved, the host is rejected.
     *
     * Results are cached per request (TTL: Config::$dnsCacheTtl) so a redirect
     * chain that revisits a host resolves it only once. The cached IP is the
     * one pinned via CURLOPT_RESOLVE, keeping the DNS rebinding window equal
     * to the cache TTL instead of the gap between hops.
     *
     * @param string $host The hostname or IP address to resolve and validate.
     * @return string|null The validated IP address, or null if validation fails.
     */
    private function resolveAndValidateHost(string $host): ?string
    {
        $cacheKey = strtolower($host);

        // If the host is already an IP address, validate it directly (never cached — it's free)
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            if ($this->isPrivateOrReservedIp($host)) {
                Logger::error('URL rejected: ' . $host . ' is a private/reserved IP');
                return null;
            }
            return $host;
        }

        $cached = $this->dnsCache[$cacheKey] ?? null;
        if ($cached !== null && $cached['expires'] > microtime(true)) {
            return $cached['ip'];
        }

        $resolvedIp = $this->resolveHost($host);

        if ($resolvedIp !== null && $this->config->dnsCacheTtl > 0) {
            $this->dnsCache[$cacheKey] = [
                'ip' => $resolvedIp,
                'expires' => microtime(true) + $this->config->dnsCacheTtl,
            ];
        }

        return $resolvedIp;
    }

    /**
     * Performs the actual DNS resolution and IP validation (uncached).
     *
     * Protected so tests can override it with a stub resolver.
     *
     * @param string $host The hostname to resolve and validate.
     * @return string|null The validated IP address, or null if validation fails.
     */
    protected function resolveHost(string $host): ?string
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            if ($this->isPrivateOrReservedIp($host)) {
                Logger::error('URL rejected: ' . $host . ' is a private/reserved IP');
                return null;
            }
            return $host;
        }

        // Resolve DNS records
        $dnsRecords = @dns_get_record($host, DNS_A + DNS_AAAA);
        if ($dnsRecords === false || $dnsRecords === []) {
            // Fail-closed: unresolvable hosts are blocked
            Logger::error('URL rejected: DNS resolution failed for ' . $host);
            return null;
        }

        // Validate ALL resolved IPs — block if any are private/reserved
        foreach ($dnsRecords as $record) {
            $ip = match ($record['type'] ?? '') {
                'A' => $record['ip'] ?? null,
                'AAAA' => $record['ipv6'] ?? null,
                default => null,
            };

            if ($ip === null || $this->isPrivateOrReservedIp($ip)) {
                Logger::error('URL rejected: ' . $host . ' resolves to private/reserved IP ' . ($ip ?? '?'));
                return null;
            }
        }

        // Return the first A record for CURLOPT_RESOLVE pinning (preferred for compatibility)
        foreach ($dnsRecords as $record) {
            if (($record['type'] ?? '') === 'A' && isset($record['ip'])) {
                Logger::debug('Resolved ' . $host . ' -> ' . $record['ip']);
                return $record['ip'];
            }
        }

        // Fallback to first AAAA record
        foreach ($dnsRecords as $record) {
            if (($record['type'] ?? '') === 'AAAA' && isset($record['ipv6'])) {
                Logger::debug('Resolved ' . $host . ' -> ' . $record['ipv6']);
                return $record['ipv6'];
            }
        }

        return null;
    }

    /**
     * Determines if an IP address is private, reserved, or a known cloud metadata endpoint.
     *
     * Checks:
     * - RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
     * - Loopback (127.0.0.0/8, ::1)
     * - Link-local (169.254.0.0/16, fe80::/10)
     * - Cloud metadata endpoints (169.254.169.254, fd00:ec2::254, etc.)
     * - IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
     *
     * @param string $ip The IP address to check.
     * @return bool True if the IP is private/reserved/blocked.
     */
    private function isPrivateOrReservedIp(string $ip): bool
    {
        // Explicit cloud metadata endpoint blocking
        $blockedIps = [
            '169.254.169.254',  // AWS/GCP/Azure metadata
            'fd00:ec2::254',    // AWS EC2 IPv6 metadata
            '169.254.170.2',    // AWS ECS task metadata
        ];
        if (in_array($ip, $blockedIps, true)) {
            return true;
        }

        // IPv6 loopback
        if ($ip === '::1') {
            return true;
        }

        // IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
        $lowerIp = strtolower($ip);
        if (str_starts_with($lowerIp, '::ffff:')) {
            $mappedIpv4 = substr($ip, 7);
            if (
                filter_var($mappedIpv4, FILTER_VALIDATE_IP) !== false
                && filter_var($mappedIpv4, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
            ) {
                return true;
            }
        }

        // Standard private/reserved range check via PHP's built-in filter
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }
}
