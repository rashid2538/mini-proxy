<?php
declare(strict_types=1);

/**
 * Standalone test harness for miniProxy (no PHPUnit dependency).
 *
 * Covers:
 * 1. Per-request DNS cache in UrlValidator (hit, TTL expiry, case handling)
 * 2. HeaderFilter::getRedirectLocation (used by the redirect/304 logic)
 *
 * Run: php test/proxy_test.php
 */

require __DIR__ . '/../src/Config.php';
require __DIR__ . '/../src/UrlValidator.php';
require __DIR__ . '/../src/HeaderFilter.php';
require __DIR__ . '/../src/Logger.php';

use MiniProxy\Config;
use MiniProxy\UrlValidator;
use MiniProxy\HeaderFilter;
use MiniProxy\Logger;

$failures = 0;

function check(string $name, bool $condition): void
{
    global $failures;
    echo ($condition ? 'PASS' : 'FAIL'), '  ', $name, "\n";
    if (!$condition) {
        $failures++;
    }
}

// ── Stub resolver: counts real DNS resolutions ──

final class CountingValidator extends UrlValidator
{
    public array $resolvedHosts = [];

    protected function resolveHost(string $host): ?string
    {
        $this->resolvedHosts[] = $host;
        return '93.184.216.34'; // stand-in for a validated public IP
    }
}

// ── Test 1: DNS cache — same host resolved once per request ──

$config = new Config();
check('dnsCacheTtl default is 300', $config->dnsCacheTtl === 300);

$validator = new CountingValidator($config);

$v1 = $validator->validate('http://example.com/');
check('first validate() resolves DNS', count($validator->resolvedHosts) === 1);
check('first result carries pinned IP', ($v1['resolved_ip'] ?? null) === '93.184.216.34');

$v2 = $validator->validate('http://example.com/other');
check('second call uses cache (no re-resolution)', count($validator->resolvedHosts) === 1);
check('cached result carries same pinned IP', ($v2['resolved_ip'] ?? null) === '93.184.216.34');

$validator->validate('http://EXAMPLE.com/x');
check('cache key is case-insensitive', count($validator->resolvedHosts) === 1);

$validator->validate('http://other.example.com/x');
check('different host resolves independently', count($validator->resolvedHosts) === 2);

// ── Test 2: TTL expiry forces re-resolution ──

$validator = new CountingValidator($config);
$validator->validate('http://example.com/');
check('pre-expiry: one resolution', count($validator->resolvedHosts) === 1);

// Expire all cache entries by rewriting their expiry into the past,
// via a closure bound to the validator instance (test-only access).
$expire = \Closure::bind(
    static function (UrlValidator $validator): void {
        $cache = \Closure::bind(
            static fn(UrlValidator $v): array => $v->dnsCache,
            null,
            UrlValidator::class
        )($validator);
        foreach ($cache as $key => $entry) {
            \Closure::bind(
                static function (UrlValidator $v) use ($key): void {
                    $v->dnsCache[$key]['expires'] = 0.0;
                },
                null,
                UrlValidator::class
            )($validator);
        }
    },
    null,
    null
);
$expire($validator);

$validator->validate('http://example.com/');
check('expired entry triggers re-resolution', count($validator->resolvedHosts) === 2);

// ── Test 3: TTL = 0 disables caching ──

$configNoCache = new Config();
$configNoCache->dnsCacheTtl = 0;
$validatorNoCache = new CountingValidator($configNoCache);
$validatorNoCache->validate('http://example.com/');
$validatorNoCache->validate('http://example.com/');
check('dnsCacheTtl=0 disables caching', count($validatorNoCache->resolvedHosts) === 2);

// ── Test 4: IP-literal hosts never touch DNS (and never hit the cache path) ──

$configLocal = new Config();
$configLocal->disallowLocal = false;
$ipValidator = new CountingValidator($configLocal);
$ipValidator->validate('http://93.184.216.34/');
$ipValidator->validate('http://93.184.216.34/');
check('IP-literal host skips resolver entirely', count($ipValidator->resolvedHosts) === 0);

// ── Test 5: redirect Location extraction (feeds the redirect loop) ──

$raw = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.net/secure\r\nContent-Type: text/html\r\n";
check('absolute Location extracted', HeaderFilter::getRedirectLocation($raw) === 'https://example.net/secure');

$rel = "HTTP/1.1 302 Found\r\nlocation:  /relative/path?q=1\r\n";
check('relative Location extracted (case-insensitive name)', HeaderFilter::getRedirectLocation($rel) === '/relative/path?q=1');

$none = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
check('no Location returns null', HeaderFilter::getRedirectLocation($none) === null);

$empty = "HTTP/1.1 302 Found\r\nLocation: \r\n";
check('empty Location rejected', HeaderFilter::getRedirectLocation($empty) === null);

$inject = "HTTP/1.1 302 Found\r\nLocation: http://evil.test/\r\nX-Inject: x\r\n";
check('CRLF injection attempt rejected', HeaderFilter::getRedirectLocation($inject) === 'http://evil.test/');

// ── Test 6: request header blocklist (forwarded to the destination) ──

$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer secret-token';
$_SERVER['HTTP_X_API_KEY'] = 'key-value';
$_SERVER['HTTP_ORIGIN'] = 'https://proxy.test';

$prepared = HeaderFilter::prepareRequestHeaders('https://example.net/path', true, ['authorization']);
$forwarded = implode("\n", $prepared['headers']);
check('blocked header is not forwarded', !str_contains($forwarded, 'Bearer secret-token'));
check('unblocked header is forwarded', str_contains($forwarded, 'X-Api-Key: key-value'));
check('origin still rewritten by default', str_contains($forwarded, 'Origin: https://example.net'));

$preparedNoBlock = HeaderFilter::prepareRequestHeaders('https://example.net/path', true);
$forwardedNoBlock = implode("\n", $preparedNoBlock['headers']);
check('empty blocklist forwards headers', str_contains($forwardedNoBlock, 'Authorization: Bearer secret-token'));

$preparedOriginBlock = HeaderFilter::prepareRequestHeaders('https://example.net/path', true, ['origin']);
$forwardedOriginBlock = implode("\n", $preparedOriginBlock['headers']);
check('blocked origin is not rewritten', !str_contains($forwardedOriginBlock, 'Origin:'));

unset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['HTTP_X_API_KEY'], $_SERVER['HTTP_ORIGIN']);

// ── Test 7: Logger leveling + output format ──

$logPath = sys_get_temp_dir() . '/miniproxy_test_' . getmypid() . '.log';
@unlink($logPath);

Logger::setLogFile($logPath);
Logger::setLevel('access');
Logger::access('1.2.3.4', 'GET', 'https://example.test/path?q=1', 200, 1234, 0.123);
Logger::error('boom');
Logger::debug('hidden debug line');
Logger::setLogFile('');
Logger::info('disabled no-op');

Logger::setLogFile($logPath);
$content = file_get_contents($logPath);
check('access line: IP METHOD URL STATUS BYTES SECONDS', str_contains($content, 'ACCESS 1.2.3.4 GET https://example.test/path?q=1 200 1234 0.123'));
check('error line written at access level', (bool) preg_match('/\[.*\] ERROR.*boom/s', $content));
check('debug filtered at access level', !str_contains($content, 'hidden debug line'));
check('disabled logger writes nothing', !str_contains($content, 'disabled no-op'));
check('accessEnabled true at access level', Logger::accessEnabled());

Logger::setLevel('error');
Logger::access('9.9.9.9', 'GET', 'https://filtered.test/', 200, 0, 0.0);
check('access filtered at error level', !str_contains(file_get_contents($logPath) ?: '', 'filtered.test'));
check('accessEnabled false at error level', !Logger::accessEnabled());

Logger::setLevel('debug');
Logger::debug('now visible');
$content = file_get_contents($logPath);
check('debug line written at debug level', str_contains($content, 'now visible'));
check('debug line label', (bool) preg_match('/DEBUG\s+now visible/', $content));

Logger::setLogFile('');
Logger::setLevel('access');
@unlink($logPath);

echo "\n", $failures === 0 ? "ALL TESTS PASSED" : "{$failures} TEST(S) FAILED", "\n";
exit($failures === 0 ? 0 : 1);
