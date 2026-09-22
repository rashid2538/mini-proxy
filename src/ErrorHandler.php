<?php

declare(strict_types=1);

namespace MiniProxy;

/**
 * Handles error responses and the landing page.
 *
 * All output is properly escaped to prevent XSS. Uses HTTP status codes
 * and structured HTML responses instead of raw die() calls.
 */
class ErrorHandler
{
    /**
     * Sends an HTTP error response and terminates execution.
     *
     * @param int    $statusCode HTTP status code (e.g. 400, 403, 502).
     * @param string $message    Human-readable error message (will be HTML-escaped).
     */
    public static function sendError(int $statusCode, string $message): never
    {
        Logger::error('Error ' . $statusCode . ': ' . $message);

        http_response_code($statusCode);
        header('Content-Type: text/html; charset=UTF-8');

        $safeMessage = htmlspecialchars($message, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        echo <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Proxy Error {$statusCode}</title>
            <style>
                body { font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; color: #333; }
                h1 { color: #c0392b; }
                p { line-height: 1.6; }
                hr { border: none; border-top: 1px solid #eee; margin: 20px 0; }
                small { color: #999; }
            </style>
        </head>
        <body>
            <h1>Error {$statusCode}</h1>
            <p>{$safeMessage}</p>
            <hr>
            <p><small>miniProxy</small></p>
        </body>
        </html>
        HTML;
        exit(1);
    }

    /**
     * Renders the miniProxy landing page with a URL input form.
     *
     * All dynamic values are properly escaped for their respective contexts
     * (HTML attributes, JavaScript strings) to prevent XSS.
     *
     * @param string $proxyPrefix The proxy's base URL prefix.
     * @param string $exampleURL  The example URL to display and use as default.
     */
    public static function renderLandingPage(string $proxyPrefix, string $exampleURL): never
    {
        $safePrefix = htmlspecialchars($proxyPrefix, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $safeExample = htmlspecialchars($exampleURL, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $jsPrefix = json_encode($proxyPrefix, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $jsExample = json_encode($proxyPrefix . $exampleURL, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        echo <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>miniProxy</title>
            <style>
                body { font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; color: #333; }
                h1 { color: #2c3e50; }
                a { color: #2980b9; }
                input[type="text"] { padding: 8px; font-size: 14px; }
                input[type="submit"] { padding: 8px 16px; font-size: 14px; cursor: pointer; }
                form { margin-top: 10px; }
            </style>
        </head>
        <body>
            <h1>Welcome to miniProxy!</h1>
            <p>miniProxy can be directly invoked like this:
                <a href="{$safePrefix}{$safeExample}">{$safePrefix}{$safeExample}</a>
            </p>
            <p>Or, you can simply enter a URL below:</p>
            <form id="proxyForm" autocomplete="off">
                <input id="site" type="text" size="50" placeholder="https://example.com" />
                <input type="submit" value="Proxy It!" />
            </form>
            <script>
                document.getElementById('proxyForm').addEventListener('submit', function(e) {
                    e.preventDefault();
                    var site = document.getElementById('site').value;
                    window.location.href = site ? {$jsPrefix} + site : {$jsExample};
                });
            </script>
        </body>
        </html>
        HTML;
        exit(0);
    }
}
