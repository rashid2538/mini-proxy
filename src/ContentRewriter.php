<?php

declare(strict_types=1);

namespace MiniProxy;

/**
 * Rewrites URLs in HTML and CSS content to route through the proxy.
 *
 * Handles:
 * - HTML: Forms, links, images, srcset, styles, meta refresh, XHR interception
 * - CSS: url() references, @import rules
 * - Relative-to-absolute URL conversion
 *
 * Supports both the modern Dom\HTMLDocument (PHP 8.4+ HTML5 parser) and
 * the legacy DOMDocument (libxml-based HTML4 parser) with automatic detection.
 */
class ContentRewriter
{
    private string $proxyPrefix;

    public function __construct(string $proxyPrefix)
    {
        $this->proxyPrefix = $proxyPrefix;
    }

    /**
     * Converts a relative URL to an absolute URL given a base URL.
     *
     * Handles protocol-relative URLs, query-only and fragment-only references,
     * and normalizes path segments (., ..).
     *
     * @param string $rel  The relative URL to resolve.
     * @param string $base The base URL to resolve against.
     * @return string The absolute URL.
     */
    public function rel2abs(string $rel, string $base): string
    {
        if ($rel === '') {
            $rel = '.';
        }

        // Already absolute or protocol-relative
        if (parse_url($rel, PHP_URL_SCHEME) !== null || str_starts_with($rel, '//')) {
            return $rel;
        }

        // Fragment-only or query-only
        if ($rel[0] === '#' || $rel[0] === '?') {
            return $base . $rel;
        }

        $parts = parse_url($base);
        if ($parts === false) {
            return $rel;
        }

        $scheme = $parts['scheme'] ?? 'http';
        $host = $parts['host'] ?? '';
        $path = isset($parts['path']) ? (string) preg_replace('#/[^/]*$#', '', $parts['path']) : '/';
        $port = isset($parts['port']) && $parts['port'] !== 80 ? ':' . $parts['port'] : '';

        $auth = '';
        if (isset($parts['user'])) {
            $auth = $parts['user'];
            if (isset($parts['pass'])) {
                $auth .= ':' . $parts['pass'];
            }
            $auth .= '@';
        }

        if ($rel[0] === '/') {
            $path = '';
        }

        // Build dirty absolute URL, then normalize path segments
        $abs = "{$auth}{$host}{$port}{$path}/{$rel}";

        // Replace '//' or '/./' or '/foo/../' with '/'
        for ($n = 1; $n > 0;) {
            $abs = (string) preg_replace(
                ['#(/\.?/)#', '#/(?!\.\.)[^/]+/\.\./#'],
                '/',
                $abs,
                -1,
                $n
            );
        }

        return $scheme . '://' . $abs;
    }

    /**
     * Proxifies url() references in CSS text.
     *
     * Normalizes @import rules to use url() wrapper, then rewrites all
     * url() references to route through the proxy. Data URIs are preserved.
     *
     * @param string $css     The CSS text to process.
     * @param string $baseURL The base URL for resolving relative references.
     * @return string The proxified CSS text.
     */
    public function proxifyCSS(string $css, string $baseURL): string
    {
        // Normalize @import rules without url() wrapper to use url()
        $sourceLines = explode("\n", $css);
        $normalizedLines = [];
        foreach ($sourceLines as $line) {
            if (preg_match('/@import\s+url/i', $line)) {
                $normalizedLines[] = $line;
            } else {
                $normalizedLines[] = (string) preg_replace_callback(
                    '/(@import\s+)([^\s;]+)([\s;])/i',
                    static fn(array $matches): string => $matches[1] . 'url(' . $matches[2] . ')' . $matches[3],
                    $line
                );
            }
        }

        $normalizedCSS = implode("\n", $normalizedLines);

        return (string) preg_replace_callback(
            '/url\((.*?)\)/i',
            function (array $matches) use ($baseURL): string {
                $url = $matches[1];

                // Remove surrounding quotes (optional in CSS)
                if (str_starts_with($url, "'")) {
                    $url = trim($url, "'");
                } elseif (str_starts_with($url, '"')) {
                    $url = trim($url, '"');
                }

                // Don't proxify data: URIs (actual binary data, not HTTP resources)
                if (str_starts_with(strtolower($url), 'data:')) {
                    return 'url(' . $url . ')';
                }

                return 'url(' . $this->proxyPrefix . $this->rel2abs($url, $baseURL) . ')';
            },
            $normalizedCSS
        );
    }

    /**
     * Proxifies srcset attributes (normally on <img> tags).
     *
     * Each source in the srcset is split into URL and descriptor parts,
     * the URL is made absolute and proxified, then reassembled.
     *
     * @param string $srcset  The srcset attribute value.
     * @param string $baseURL The base URL for resolving relative references.
     * @return string The proxified srcset value.
     */
    public function proxifySrcset(string $srcset, string $baseURL): string
    {
        $sources = array_map('trim', explode(',', $srcset));

        $proxifiedSources = array_map(function (string $source) use ($baseURL): string {
            $source = trim($source);
            if ($source === '') {
                return '';
            }

            $lastSpace = strrpos($source, ' ');
            if ($lastSpace === false) {
                // No descriptor — entire string is a URL
                return $this->proxyPrefix . $this->rel2abs(ltrim($source, '/'), $baseURL);
            }

            $url = trim(substr($source, 0, $lastSpace));
            $descriptor = trim(substr($source, $lastSpace + 1));
            $proxifiedUrl = $this->proxyPrefix . $this->rel2abs(ltrim($url, '/'), $baseURL);

            return $proxifiedUrl . ' ' . $descriptor;
        }, $sources);

        // Filter out empty entries from trailing commas
        $proxifiedSources = array_filter($proxifiedSources, static fn(string $s): bool => $s !== '');

        return implode(', ', $proxifiedSources);
    }

    /**
     * Rewrites an HTML response body to route all URLs through the proxy.
     *
     * Detects character encoding and normalizes to UTF-8 before parsing.
     * Uses Dom\HTMLDocument (PHP 8.4+ HTML5 parser) when available,
     * falling back to DOMDocument (legacy HTML4 parser).
     *
     * @param string $html    The HTML response body.
     * @param string $baseURL The base URL of the original page.
     * @return string The rewritten HTML.
     */
    public function rewriteHtml(string $html, string $baseURL): string
    {
        // Fast path (PHP 8.4+ performance): valid UTF-8 is by far the most common
        // case — verify it with mb_check_encoding (O(n) single pass) and skip
        // the expensive mb_detect_encoding() heuristic scan entirely.
        // Invalid UTF-8 is sanitized with mb_scrub (substitution character) so the
        // HTML5 parser always receives well-formed input.
        if (!mb_check_encoding($html, 'UTF-8')) {
            $detectedEncoding = mb_detect_encoding($html, 'UTF-8, ISO-8859-1');
            if ($detectedEncoding !== false && $detectedEncoding !== 'UTF-8') {
                $converted = mb_convert_encoding($html, 'UTF-8', $detectedEncoding);
                if ($converted !== false) {
                    $html = $converted;
                }
            }
            // Scrub any remaining ill-formed byte sequences.
            $html = mb_scrub($html, 'UTF-8');
        }

        // Use modern HTML5 parser when available
        if (class_exists(\Dom\HTMLDocument::class)) {
            return $this->rewriteWithModernDom($html, $baseURL);
        }

        return $this->rewriteWithLegacyDom($html, $baseURL);
    }

    /**
     * Rewrites HTML using the modern Dom\HTMLDocument (PHP 8.4+).
     *
     * Benefits: HTML5-compliant parsing, native CSS selector support,
     * standards-compliant DOM structure.
     */
    private function rewriteWithModernDom(string $html, string $baseURL): string
    {
        // Note: the new HTML5 parser does not emit libxml warnings, so no
        // additional suppression flags are needed here.
        $doc = \Dom\HTMLDocument::createFromString($html, LIBXML_NOERROR);

        // ── Rewrite <form> actions ──
        foreach ($doc->querySelectorAll('form') as $form) {
            $action = $form->getAttribute('action') ?? '';
            $action = $action === '' ? $baseURL : $this->rel2abs($action, $baseURL);
            $form->setAttribute('action', rtrim($this->proxyPrefix, '?'));

            $input = $doc->createElement('input');
            $input->setAttribute('type', 'hidden');
            $input->setAttribute('name', 'miniProxyFormAction');
            $input->setAttribute('value', $action);
            $form->appendChild($input);
        }

        // ── Proxify <meta http-equiv="refresh"> tags ──
        foreach ($doc->querySelectorAll('meta[http-equiv]') as $element) {
            $httpEquiv = $element->getAttribute('http-equiv') ?? '';
            if (strcasecmp($httpEquiv, 'refresh') === 0) {
                $content = $element->getAttribute('content') ?? '';
                if ($content !== '') {
                    $splitContent = preg_split('/=/', $content, 2);
                    if (isset($splitContent[1])) {
                        $newUrl = $this->proxyPrefix . $this->rel2abs(trim($splitContent[1]), $baseURL);
                        $element->setAttribute('content', $splitContent[0] . '=' . $newUrl);
                    }
                }
            }
        }

        // ── Proxify <style> tag contents ──
        foreach ($doc->querySelectorAll('style') as $style) {
            $style->textContent = $this->proxifyCSS($style->textContent ?? '', $baseURL);
        }

        // ── Proxify inline style attributes ──
        foreach ($doc->querySelectorAll('[style]') as $element) {
            $styleValue = $element->getAttribute('style') ?? '';
            $element->setAttribute('style', $this->proxifyCSS($styleValue, $baseURL));
        }

        // ── Proxify srcset attributes ──
        foreach ($doc->querySelectorAll('img[srcset]') as $element) {
            $srcsetValue = $element->getAttribute('srcset') ?? '';
            $element->setAttribute('srcset', $this->proxifySrcset($srcsetValue, $baseURL));
        }

        // ── Proxify href and src attributes ──
        $this->proxifyAttributeModern($doc, 'href', $baseURL, '/^(about|javascript|magnet|mailto):|#/i');
        $this->proxifyAttributeModern($doc, 'src', $baseURL, '/^(data):/i');

        // ── Inject XHR interceptor script ──
        $head = $doc->querySelector('head');
        $body = $doc->querySelector('body');
        $prependElem = $head ?? $body;

        if ($prependElem !== null) {
            $scriptElem = $doc->createElement('script');
            $scriptElem->textContent = $this->getXhrInterceptorScript($baseURL);
            $scriptElem->setAttribute('type', 'text/javascript');
            $prependElem->insertBefore($scriptElem, $prependElem->firstChild);
        }

        return "<!-- Proxified page constructed by miniProxy -->\n" . $doc->saveHTML();
    }

    /**
     * Rewrites HTML using the legacy DOMDocument (fallback for < PHP 8.4
     * or when Dom\HTMLDocument is unavailable).
     */
    private function rewriteWithLegacyDom(string $html, string $baseURL): string
    {
        $doc = new \DOMDocument();
        libxml_use_internal_errors(true);
        $doc->loadHTML('<?xml encoding="UTF-8">' . $html);
        libxml_clear_errors();

        $xpath = new \DOMXPath($doc);

        // ── Rewrite <form> actions ──
        foreach ($xpath->query('//form') ?: [] as $form) {
            /** @var \DOMElement $form */
            $action = $form->getAttribute('action');
            $action = $action === '' ? $baseURL : $this->rel2abs($action, $baseURL);
            $form->setAttribute('action', rtrim($this->proxyPrefix, '?'));

            $actionInput = $doc->createDocumentFragment();
            $escapedAction = htmlspecialchars($action, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $actionInput->appendXML(
                '<input type="hidden" name="miniProxyFormAction" value="' . $escapedAction . '" />'
            );
            $form->appendChild($actionInput);
        }

        // ── Proxify <meta http-equiv="refresh"> tags ──
        foreach ($xpath->query('//meta[@http-equiv]') ?: [] as $element) {
            /** @var \DOMElement $element */
            if (strcasecmp($element->getAttribute('http-equiv'), 'refresh') === 0) {
                $content = $element->getAttribute('content');
                if ($content !== '') {
                    $splitContent = preg_split('/=/', $content, 2);
                    if (isset($splitContent[1])) {
                        $newUrl = $this->proxyPrefix . $this->rel2abs(trim($splitContent[1]), $baseURL);
                        $element->setAttribute('content', $splitContent[0] . '=' . $newUrl);
                    }
                }
            }
        }

        // ── Proxify <style> tag contents ──
        foreach ($xpath->query('//style') ?: [] as $style) {
            /** @var \DOMElement $style */
            $style->nodeValue = $this->proxifyCSS($style->nodeValue ?? '', $baseURL);
        }

        // ── Proxify inline style attributes ──
        foreach ($xpath->query('//*[@style]') ?: [] as $element) {
            /** @var \DOMElement $element */
            $element->setAttribute('style', $this->proxifyCSS($element->getAttribute('style'), $baseURL));
        }

        // ── Proxify srcset attributes ──
        foreach ($xpath->query('//img[@srcset]') ?: [] as $element) {
            /** @var \DOMElement $element */
            $element->setAttribute('srcset', $this->proxifySrcset($element->getAttribute('srcset'), $baseURL));
        }

        // ── Proxify href and src attributes ──
        $proxifyAttributes = ['href', 'src'];
        foreach ($proxifyAttributes as $attrName) {
            foreach ($xpath->query('//*[@' . $attrName . ']') ?: [] as $element) {
                /** @var \DOMElement $element */
                $attrContent = $element->getAttribute($attrName);

                if ($attrName === 'href' && preg_match('/^(about|javascript|magnet|mailto):|#/i', $attrContent)) {
                    continue;
                }
                if ($attrName === 'src' && preg_match('/^(data):/i', $attrContent)) {
                    continue;
                }

                $attrContent = $this->rel2abs($attrContent, $baseURL);
                $element->setAttribute($attrName, $this->proxyPrefix . $attrContent);
            }
        }

        // ── Inject XHR interceptor script ──
        $head = $xpath->query('//head')?->item(0);
        $body = $xpath->query('//body')?->item(0);
        $prependElem = $head ?? $body;

        if ($prependElem !== null) {
            $scriptElem = $doc->createElement('script', $this->getXhrInterceptorScript($baseURL));
            $scriptElem->setAttribute('type', 'text/javascript');
            $prependElem->insertBefore($scriptElem, $prependElem->firstChild);
        }

        return "<!-- Proxified page constructed by miniProxy -->\n" . $doc->saveHTML();
    }

    /**
     * Proxifies all elements with a given attribute in a modern DOM document.
     *
     * @param \Dom\HTMLDocument $doc         The document to process.
     * @param string            $attrName    The attribute name (e.g., 'href', 'src').
     * @param string            $baseURL     The base URL for resolving relative references.
     * @param string            $skipPattern Regex pattern for attribute values to skip.
     */
    private function proxifyAttributeModern(\Dom\HTMLDocument $doc, string $attrName, string $baseURL, string $skipPattern): void
    {
        foreach ($doc->querySelectorAll('[' . $attrName . ']') as $element) {
            $attrContent = $element->getAttribute($attrName) ?? '';
            if (preg_match($skipPattern, $attrContent)) {
                continue;
            }
            $attrContent = $this->rel2abs($attrContent, $baseURL);
            $element->setAttribute($attrName, $this->proxyPrefix . $attrContent);
        }
    }

    /**
     * Returns the JavaScript code for intercepting XMLHttpRequest.open() calls.
     *
     * This script wraps XMLHttpRequest.prototype.open to ensure all AJAX request
     * URLs are converted to absolute URLs and routed through the proxy.
     *
     * @param string $baseURL The base URL of the original page.
     * @return string The JavaScript source code.
     */
    private function getXhrInterceptorScript(string $baseURL): string
    {
        // Use json_encode for safe JavaScript string embedding (prevents XSS)
        $jsBaseUrl = json_encode($baseURL, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $jsProxyPrefix = json_encode($this->proxyPrefix, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return <<<JAVASCRIPT
        (function() {
            if (window.XMLHttpRequest) {
                function parseURI(url) {
                    var m = String(url).replace(/^\s+|\s+$/g, "").match(/^([^:\/?#]+:)?(\/\/(?:[^:@]*(?::[^:@]*)?@)?(([^:\/?#]*)(?::(\d*))?))?([^?#]*)(\?[^#]*)?(#[\s\S]*)?/);
                    return (m ? {
                        href: m[0] || "", protocol: m[1] || "", authority: m[2] || "",
                        host: m[3] || "", hostname: m[4] || "", port: m[5] || "",
                        pathname: m[6] || "", search: m[7] || "", hash: m[8] || ""
                    } : null);
                }
                function rel2abs(base, href) {
                    function removeDotSegments(input) {
                        var output = [];
                        input.replace(/^(\.\.?(\/|$))+/, "")
                            .replace(/\/(\.(\/|$))+/g, "/")
                            .replace(/\/\.\.$/, "/../")
                            .replace(/\/?[^\/]*/g, function(p) {
                                if (p === "/..") { output.pop(); } else { output.push(p); }
                            });
                        return output.join("").replace(/^\//, input.charAt(0) === "/" ? "/" : "");
                    }
                    href = parseURI(href || "");
                    base = parseURI(base || "");
                    return !href || !base ? null : (href.protocol || base.protocol) +
                        (href.protocol || href.authority ? href.authority : base.authority) +
                        removeDotSegments(href.protocol || href.authority || href.pathname.charAt(0) === "/" ? href.pathname : (href.pathname ? ((base.authority && !base.pathname ? "/" : "") + base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1) + href.pathname) : base.pathname)) +
                        (href.protocol || href.authority || href.pathname ? href.search : (href.search || base.search)) +
                        href.hash;
                }
                var proxied = window.XMLHttpRequest.prototype.open;
                window.XMLHttpRequest.prototype.open = function() {
                    if (arguments[1] !== null && arguments[1] !== undefined) {
                        var url = arguments[1];
                        url = rel2abs({$jsBaseUrl}, url);
                        if (url.indexOf({$jsProxyPrefix}) == -1) {
                            url = {$jsProxyPrefix} + url;
                        }
                        arguments[1] = url;
                    }
                    return proxied.apply(this, [].slice.call(arguments));
                };
            }
        })();
        JAVASCRIPT;
    }
}
