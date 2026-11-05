<?php
declare(strict_types=1);

/*
miniProxy - A simple PHP web proxy. <https://github.com/joshdick/miniProxy>
Written and maintained by Joshua Dick <http://joshdick.net>.
miniProxy is licensed under the GNU GPL v3 <https://www.gnu.org/licenses/gpl-3.0.html>.

Modernized front controller: configuration is loaded from the .env file and all
logic lives in the classes under src/. Environment variables (and their defaults)
are documented in .env.example.
*/

namespace MiniProxy;

// ────────────────────────────── Bootstrap ──────────────────────────────

if (version_compare(PHP_VERSION, '8.1.0', '<')) {
    http_response_code(500);
    die('miniProxy requires PHP version 8.1.0 or later.');
}

if (php_sapi_name() === 'cli') {
    $_SERVER['SERVER_PORT'] = 0;
}

// Never let PHP warnings/deprecations corrupt proxied responses.
error_reporting(E_ALL);
ini_set('display_errors', 'stderr');

foreach (['curl', 'mbstring', 'dom', 'xml'] as $requiredExtension) {
    if (!extension_loaded($requiredExtension)) {
        http_response_code(500);
        die('miniProxy requires PHP\'s "' . $requiredExtension . '" extension. Please install/enable it on your server and try again.');
    }
}

// Composer autoloader when available; otherwise a minimal PSR-4 fallback
// for the MiniProxy\ namespace so the script also works as a standalone file.
$composerAutoloader = __DIR__ . '/vendor/autoload.php';
if (is_file($composerAutoloader)) {
    require_once $composerAutoloader;
} else {
    spl_autoload_register(static function (string $class): void {
        if (str_starts_with($class, __NAMESPACE__ . '\\')) {
            $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen(__NAMESPACE__ . '\\'))) . '.php';
            if (is_file($file)) {
                require_once $file;
            }
        }
    });
}

/**
 * Minimal .env loader (no external dependencies).
 *
 * Parses KEY=VALUE lines, skipping blank lines and #-comments, and stores the
 * results in $_ENV/getenv(). Existing real environment variables take priority.
 * Values may be single/double quoted; double-quoted values understand escape
 * sequences and inline " # ..." comments.
 */
function loadEnv(string $envFile): void
{
    if (!is_file($envFile) || !is_readable($envFile)) {
        return;
    }

    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }

        [$key, $value] = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);

        if ($key === '') {
            continue;
        }

        if (strlen($value) >= 2 && (($value[0] === '"' && str_ends_with($value, '"')) || ($value[0] === "'" && str_ends_with($value, "'")))) {
            $quote = $value[0];
            $value = substr($value, 1, -1);
            if ($quote === '"') {
                $value = stripcslashes($value);
            }
        } elseif (($commentPos = strpos($value, ' #')) !== false) {
            $value = trim(substr($value, 0, $commentPos));
        }

        if (getenv($key) !== false) {
            continue; // Real environment variables take priority over .env
        }

        $_ENV[$key] = $value;
        putenv($key . '=' . $value);
    }
}

function envBool(string $key, bool $default): bool
{
    $value = getenv($key);
    if ($value === false || $value === '') {
        return $default;
    }
    return in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
}

function envInt(string $key, int $default): int
{
    $value = getenv($key);
    return ($value === false || $value === '' || !ctype_digit($value)) ? $default : (int) $value;
}

/**
 * Builds a Config from environment variables (falling back to .env defaults).
 */
function configFromEnv(): Config
{
    $config = new Config();

    $patterns = static fn(string $key): array => array_values(array_filter(
        array_map('trim', explode(',', (string) getenv($key))),
        static fn(string $p): bool => $p !== ''
    ));

    $config->whitelistPatterns = $patterns('WHITELIST_PATTERNS');
    $config->blacklistPatterns = $patterns('BLACKLIST_PATTERNS');
    $config->forceCORS = envBool('FORCE_CORS', $config->forceCORS);
    $config->disallowLocal = envBool('DISALLOW_LOCAL', $config->disallowLocal);
    $config->anonymize = envBool('ANONYMIZE', $config->anonymize);

    $startURL = getenv('START_URL');
    if ($startURL !== false && trim($startURL) !== '') {
        $config->startURL = trim($startURL);
    }
    $landingExampleURL = getenv('LANDING_EXAMPLE_URL');
    if ($landingExampleURL !== false && trim($landingExampleURL) !== '') {
        $config->landingExampleURL = trim($landingExampleURL);
    }

    $config->maxResponseSize = envInt('MAX_RESPONSE_SIZE', $config->maxResponseSize);
    $config->connectTimeout = envInt('CONNECT_TIMEOUT', $config->connectTimeout);
    $config->requestTimeout = envInt('REQUEST_TIMEOUT', $config->requestTimeout);
    $config->maxRedirects = envInt('MAX_REDIRECTS', $config->maxRedirects);

    $allowedMethods = $patterns('ALLOWED_METHODS');
    if ($allowedMethods !== []) {
        $config->allowedMethods = array_map('strtoupper', $allowedMethods);
    }

    $config->blockRequestHeaders = array_map('strtolower', $patterns('BLOCK_HEADERS'));

    $config->logFile = trim((string) getenv('LOG_FILE'));

    $logLevel = strtolower(trim((string) getenv('LOG_LEVEL')));
    if (in_array($logLevel, ['debug', 'info', 'access', 'error'], true)) {
        $config->logLevel = $logLevel;
    }

    return $config;
}

// ────────────────────────────── Routing ──────────────────────────────

loadEnv(__DIR__ . '/.env');
$config = configFromEnv();

$requestMethod = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

// ────────────────────────────── Request logging ──────────────────────────────

// The logger is static and best-effort: it is wired here from the config and
// used by ErrorHandler for failures. When access logging is active the response
// is buffered so every exit path (including error pages) is logged exactly once
// with its byte count and duration before it is flushed at shutdown.
Logger::setLogFile($config->logFile);
Logger::setLevel($config->logLevel);
$startTime = microtime(true);
if (Logger::accessEnabled()) {
    ob_start();
    register_shutdown_function(static function () use (&$url, $requestMethod, $startTime): void {
        $status = http_response_code() ?: 200;
        $bytes = ob_get_length() !== false ? (int) ob_get_length() : 0;
        $target = $url !== '' ? $url : ($_SERVER['REQUEST_URI'] ?? '-');

        Logger::access(
            $_SERVER['REMOTE_ADDR'] ?? '-',
            $requestMethod,
            $target,
            $status,
            $bytes,
            microtime(true) - $startTime
        );

        while (ob_get_level() > 0) {
            ob_end_flush();
        }
    });
}

// The front controller serves page navigations (GET/HEAD) and proxied form
// submissions (POST). Other methods are rejected here; ProxyClient enforces
// the configured method allowlist for the upstream request.
if (!in_array($requestMethod, ['GET', 'HEAD', 'POST'], true)) {
    ErrorHandler::sendError(405, 'miniProxy only accepts GET, HEAD and POST requests.');
}

$usingDefaultPort = (!isset($_SERVER['HTTPS']) && ($_SERVER['SERVER_PORT'] ?? '') === '80')
    || (isset($_SERVER['HTTPS']) && ($_SERVER['SERVER_PORT'] ?? '') === '443');
$prefixPort = $usingDefaultPort ? '' : ':' . $_SERVER['SERVER_PORT'];
// Use HTTP_HOST to support client-configured DNS (instead of SERVER_NAME), but remove the port if one is present.
$prefixHost = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
$prefixHost = str_contains($prefixHost, ':') ? implode(':', explode(':', $prefixHost, -1)) : $prefixHost;

define('PROXY_PREFIX', 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $prefixHost . $prefixPort . $_SERVER['SCRIPT_NAME'] . '?');

// HEAD requests cannot carry a body, so the upstream request is sent as GET.
$upstreamMethod = $requestMethod === 'HEAD' ? 'GET' : $requestMethod;
$_SERVER['REQUEST_METHOD'] = $upstreamMethod;

// NOTE: no output compression here — cURL already negotiated/decompressed any
// upstream gzip, and explicit Content-Length headers must stay accurate.

// ─────────────────────── Target URL extraction ───────────────────────

// Extract and sanitize the requested URL, handling cases where forms have been
// rewritten to point back at the proxy (hidden miniProxyFormAction field).
if (isset($_POST['miniProxyFormAction'])) {
    $url = $_POST['miniProxyFormAction'];
    unset($_POST['miniProxyFormAction']);
} else {
    $queryParams = [];
    parse_str($_SERVER['QUERY_STRING'] ?? '', $queryParams);
    if (isset($queryParams['miniProxyFormAction'])) {
        $formAction = $queryParams['miniProxyFormAction'];
        unset($queryParams['miniProxyFormAction']);
        $url = $formAction . '?' . http_build_query($queryParams);
    } else {
        // Everything after the first "?" is the target URL. Don't slice by
        // strlen(SCRIPT_NAME): "/?url" is served as "/index.php" and would lose chars.
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        $qPos = strpos($requestUri, '?');
        $url = $qPos === false ? '' : substr($requestUri, $qPos + 1);
    }
}

if (empty($url)) {
    if (empty($config->startURL)) {
        ErrorHandler::renderLandingPage(PROXY_PREFIX, $config->landingExampleURL);
    }
    $url = $config->startURL;
} elseif (strpos($url, ':/') !== strpos($url, '://')) {
    // Work around web servers (e.g. IIS 8.5) that collapse // in URLs to /.
    // See https://github.com/joshdick/miniProxy/pull/14
    $pos = strpos($url, ':/');
    $url = substr_replace($url, '://', $pos, strlen(':/'));
}

$scheme = parse_url($url, PHP_URL_SCHEME);
if (empty($scheme)) {
    if (str_starts_with($url, '//')) {
        // Assume protocol-relative URLs are HTTP.
        $url = 'http:' . $url;
    } else {
        // Assume scheme-less URLs (just a host) are HTTP.
        $url = 'http://' . $url;
    }
} elseif (!preg_match('/^https?$/i', $scheme)) {
    ErrorHandler::sendError(400, 'Error: Detected a "' . htmlspecialchars($scheme, ENT_QUOTES) . '" URL. miniProxy exclusively supports http[s] URLs.');
}

// ─────────────────── Fetch loop with re-validation ───────────────────

Logger::info('Proxying ' . $requestMethod . ' ' . $url);

$urlValidator = new UrlValidator($config);
$proxyClient = new ProxyClient($config);

$response = null;
$finalURL = $url;

// Genuine redirect status codes. Other 3xx codes (300/304/305/306) either have
// no single followable Location or must not be followed by a proxy.
$isRedirectStatus = static fn(int $code): bool =>
    in_array($code, [301, 302, 303, 307, 308], true);

// Guard: with maxRedirects = 0 the loop below must execute exactly once.
$hopLimit = max(0, $config->maxRedirects);

// Method for the upstream request; may be downgraded on redirects per RFC 7231:
// 303 always switches to GET; 301/302 switch a POST to GET (what curl's
// FOLLOWLOCATION would have done when redirect following was automatic).
$methodForUpstream = $upstreamMethod;

for ($redirectCount = 0; $redirectCount <= $hopLimit; $redirectCount++) {
    $validation = $urlValidator->validate($finalURL);
    if (!$validation['valid']) {
        ErrorHandler::sendError(403, 'Error: The requested URL was disallowed by the server administrator.');
    }

    // Re-parse inside the loop: redirects can switch scheme/port.
    $parts = parse_url($finalURL);
    if ($parts === false || !isset($parts['host'])) {
        ErrorHandler::sendError(400, 'Error: Invalid URL.');
    }
    $defaultPort = (($parts['scheme'] ?? 'http') === 'https') ? 443 : 80;
    $port = $parts['port'] ?? $defaultPort;

    if ($validation['resolved_ip'] !== null) {
        $response = $proxyClient->execute($finalURL, $methodForUpstream, $validation['resolved_ip'], $parts['host'], $port);
    } else {
        $response = $proxyClient->execute($finalURL, $methodForUpstream);
    }

    $statusCode = (int) ($response['responseInfo']['http_code'] ?? 0);

    $redirectTarget = $isRedirectStatus($statusCode)
        ? HeaderFilter::getRedirectLocation($response['headers'])
        : null; // e.g. a 304 or 300 must not be treated as a followable redirect

    if ($redirectTarget === null) {
        break; // Not a redirect: serve this response as-is.
    }

    if ($redirectCount === $hopLimit) {
        ErrorHandler::sendError(502, 'Error: Too many redirects.');
    }

    Logger::info('Redirect ' . $statusCode . ' ' . $finalURL . ' -> ' . $redirectTarget);

    // Resolve the Location value against the current URL (RFC 7231 §7.1.2):
    // it is allowed to be relative or protocol-relative.
    if (preg_match('#^https?://#i', $redirectTarget)) {
        $finalURL = $redirectTarget;
    } elseif (str_starts_with($redirectTarget, '//')) {
        $finalURL = (($parts['scheme'] ?? 'http') === 'https' ? 'https:' : 'http:') . $redirectTarget;
    } else {
        $finalURL = (new ContentRewriter(PROXY_PREFIX))->rel2abs($redirectTarget, $finalURL);
    }

    // RFC 7231 method downgrades on redirect.
    if ($statusCode === 303 || ($methodForUpstream === 'POST' && in_array($statusCode, [301, 302], true))) {
        $methodForUpstream = 'GET';
        $_SERVER['REQUEST_METHOD'] = 'GET';
    }
}

assert($response !== null);

Logger::info('Response ' . $statusCode . ' for ' . $finalURL);

$responseHeaders = $response['headers'];
$responseBody = $response['body'];
$responseInfo = $response['responseInfo'];
$responseURL = (string) ($responseInfo['url'] ?? $finalURL);

// ────────────────────── Response header handling ──────────────────────

// cURL reports headers for every request it makes; with FOLLOWLOCATION disabled
// the last block corresponds to the final response we are about to serve.
$responseHeaderBlocks = array_filter(explode("\r\n\r\n", $responseHeaders));
$lastHeaderBlock = end($responseHeaderBlocks);
if ($lastHeaderBlock === false) {
    $lastHeaderBlock = '';
}
$headerLines = explode("\r\n", $lastHeaderBlock);

HeaderFilter::forwardResponseHeaders($headerLines);

// Prevent robots from indexing proxified pages.
header('X-Robots-Tag: noindex, nofollow', true);
header('X-Proxy-Url: ' . $responseURL, true);

if ($config->forceCORS) {
    // Based on code found at: http://stackoverflow.com/a/9866124/278810
    // These headers are sent after the original response headers so their
    // values are the ones that actually reach the browser.
    header('Access-Control-Allow-Origin: *', true);
    header('Access-Control-Allow-Credentials: true', true);

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])) {
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS', true);
        }
        if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])) {
            header('Access-Control-Allow-Headers: ' . $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'], true);
        }
        exit(0);
    }
}

// ────────────────── 304 Not Modified passthrough ──────────────────
// The upstream resource is unchanged, so there is nothing to rewrite or send.
// Forward the cached-response headers (validators like ETag/Last-Modified and
// Cache-Control are on the response whitelist) with an empty body.
if ($statusCode === 304) {
    exit(0);
}

// HEAD: headers were already forwarded; report the true body size and stop.
if ($requestMethod === 'HEAD') {
    header('Content-Length: ' . strlen($responseBody), true);
    exit(0);
}

$contentType = (string) ($responseInfo['content_type'] ?? '');

if (stripos($contentType, 'text/css') !== false) {
    // CSS: proxify url() references so assets also route through the proxy.
    $rewritten = (new ContentRewriter(PROXY_PREFIX))->proxifyCSS($responseBody, $finalURL);
    Logger::debug('Rewrote CSS: ' . strlen($responseBody) . ' -> ' . strlen($rewritten) . ' bytes');
    header('Content-Length: ' . strlen($rewritten), true);
    echo $rewritten;
} elseif (stripos($contentType, 'text/html') !== false) {
    // Presumably a web page: parse and proxify the DOM.
    $rewritten = (new ContentRewriter(PROXY_PREFIX))->rewriteHtml($responseBody, $finalURL);
    Logger::debug('Rewrote HTML: ' . strlen($responseBody) . ' -> ' . strlen($rewritten) . ' bytes');
    header('Content-Length: ' . strlen($rewritten), true);
    echo $rewritten;
} else {
    // Not a web page or CSS (images, JavaScript, etc.): serve unmodified.
    Logger::debug('Serving ' . $contentType . ' unmodified (' . strlen($responseBody) . ' bytes)');
    header('Content-Length: ' . strlen($responseBody), true);
    echo $responseBody;
}
