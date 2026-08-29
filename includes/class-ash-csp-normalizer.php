<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-csp-normalizer.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 05:17:35
 * Description : Normalizes URLs and classifies discovered resources for CSP
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

if (!defined('ABSPATH')) {
    exit;
}

class ASH_CSP_Normalizer {
    const DANGEROUS_VALUES = array(
        '*',
        'http:',
        'https:',
        "'unsafe-inline'",
        "'unsafe-eval'",
        'unsafe-inline',
        'unsafe-eval',
    );

    const DIRECTIVE_MAP = array(
        'script' => 'script-src',
        'javascript' => 'script-src',
        'script-src' => 'script-src',
        'script-src-elem' => 'script-src',
        'script-src-attr' => 'script-src',
        'link' => 'style-src',
        'css' => 'style-src',
        'stylesheet' => 'style-src',
        'style' => 'style-src',
        'style-src' => 'style-src',
        'style-src-elem' => 'style-src',
        'style-src-attr' => 'style-src',
        'img' => 'img-src',
        'image' => 'img-src',
        'img-src' => 'img-src',
        'font' => 'font-src',
        'font-src' => 'font-src',
        'xmlhttprequest' => 'connect-src',
        'xhr' => 'connect-src',
        'fetch' => 'connect-src',
        'beacon' => 'connect-src',
        'ping' => 'connect-src',
        'websocket' => 'connect-src',
        'eventsource' => 'connect-src',
        'connect-src' => 'connect-src',
        'iframe' => 'frame-src',
        'frame' => 'frame-src',
        'subdocument' => 'frame-src',
        'embed' => 'frame-src',
        'frame-src' => 'frame-src',
        'child-src' => 'frame-src',
        'video' => 'media-src',
        'audio' => 'media-src',
        'media' => 'media-src',
        'track' => 'media-src',
        'media-src' => 'media-src',
        'worker' => 'worker-src',
        'sharedworker' => 'worker-src',
        'serviceworker' => 'worker-src',
        'worker-src' => 'worker-src',
        'form' => 'form-action',
        'form-action' => 'form-action',
        'object' => 'object-src',
        'applet' => 'object-src',
        'object-src' => 'object-src',
        'base' => 'base-uri',
        'base-uri' => 'base-uri',
        'default-src' => 'default-src',
    );

    /**
     * Extract a scheme+host origin from a URL and drop path/query.
     *
     * @param string $url Raw URL or CSP blocked-uri value.
     * @return string Empty string when the value cannot be used as an origin.
     */
    public static function origin_from_url($url) {
        $url = trim((string) $url);
        if ($url === '' || $url === "'none'" || $url === 'none') {
            return '';
        }

        $special = self::special_token($url);
        if ($special !== '') {
            return $special;
        }

        if (strpos($url, '//') === 0) {
            $url = 'https:' . $url;
        }

        $parts = wp_parse_url($url);
        if (!is_array($parts) || empty($parts['host'])) {
            return '';
        }

        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : 'https';
        if (!in_array($scheme, array('http', 'https', 'ws', 'wss'), true)) {
            return '';
        }

        $host = strtolower($parts['host']);
        if ($host === '') {
            return '';
        }

        $origin = $scheme . '://' . $host;
        $port = isset($parts['port']) ? (int) $parts['port'] : 0;
        if ($port > 0 && !self::is_default_port($scheme, $port)) {
            $origin .= ':' . $port;
        }

        return $origin;
    }

    /**
     * Map a resource type or CSP directive name onto a canonical directive.
     *
     * @param string $type Initiator type, MIME hint, or CSP directive.
     * @return string Canonical directive or "unknown".
     */
    public static function classify($type) {
        $type = strtolower(trim((string) $type));
        $type = str_replace('_', '-', $type);
        if ($type !== '' && isset(self::DIRECTIVE_MAP[$type])) {
            return self::DIRECTIVE_MAP[$type];
        }
        return 'unknown';
    }

    /**
     * Whether a token is a dangerous CSP keyword that must never be auto-applied.
     *
     * @param string $value Origin or keyword.
     * @return bool
     */
    public static function is_dangerous($value) {
        $value = strtolower(trim((string) $value));
        return in_array($value, self::DANGEROUS_VALUES, true);
    }

    /**
     * Sanitize a page path for storage. Query strings are dropped.
     *
     * @param string $page Raw page identifier.
     * @return string
     */
    public static function page_path($page) {
        $page = trim((string) $page);
        if ($page === '') {
            return '/';
        }

        $parts = wp_parse_url($page);
        if (is_array($parts) && isset($parts['path']) && $parts['path'] !== '') {
            $page = $parts['path'];
        } else {
            $page = strtok($page, '?#');
        }

        $page = sanitize_text_field($page);
        if ($page === '') {
            return '/';
        }

        return substr($page, 0, 180);
    }

    /**
     * Whether an origin belongs to the current site.
     *
     * @param string $origin Normalized origin.
     * @return bool
     */
    public static function is_site_origin($origin) {
        $origin_host = wp_parse_url($origin, PHP_URL_HOST);
        $site_host = wp_parse_url(home_url(), PHP_URL_HOST);
        if (!is_string($origin_host) || !is_string($site_host) || $origin_host === '' || $site_host === '') {
            return false;
        }

        $origin_host = strtolower($origin_host);
        $site_host = strtolower($site_host);
        if ($origin_host === $site_host) {
            return true;
        }

        return (strpos($origin_host, 'www.') === 0 && substr($origin_host, 4) === $site_host)
            || (strpos($site_host, 'www.') === 0 && substr($site_host, 4) === $origin_host);
    }

    /**
     * Whether a CSP directive value already allows the given origin.
     *
     * @param string $policy_value Raw directive field value.
     * @param string $origin Normalized origin.
     * @return bool
     */
    public static function policy_covers_origin($policy_value, $origin) {
        $origin = rtrim(trim((string) $origin), '/');
        if ($origin === '' || trim((string) $policy_value) === '') {
            return false;
        }

        $tokens = preg_split('/\s+/', trim((string) $policy_value), -1, PREG_SPLIT_NO_EMPTY);
        foreach ($tokens as $token) {
            if (self::token_covers_origin($token, $origin)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $token Single CSP source expression.
     * @param string $origin Normalized origin.
     * @return bool
     */
    private static function token_covers_origin($token, $origin) {
        $token = rtrim(trim($token), '/');
        if ($token === '') {
            return false;
        }

        if (strcasecmp($token, $origin) === 0) {
            return true;
        }

        $keyword = strtolower(trim($token, "'\""));
        if ($keyword === 'self' && self::is_site_origin($origin)) {
            return true;
        }
        if ($token === '*' || $keyword === '*') {
            return true;
        }
        if ($token === 'https:' && strpos($origin, 'https://') === 0) {
            return true;
        }
        if ($token === 'http:' && strpos($origin, 'http://') === 0) {
            return true;
        }

        $parsed_token = wp_parse_url($token);
        $token_scheme = '';
        $token_host = strtolower($token);
        if (is_array($parsed_token) && !empty($parsed_token['scheme']) && !empty($parsed_token['host'])) {
            $token_scheme = strtolower($parsed_token['scheme']);
            $token_host = strtolower($parsed_token['host']);
        }

        $origin_host = strtolower((string) wp_parse_url($origin, PHP_URL_HOST));
        $origin_scheme = strtolower((string) wp_parse_url($origin, PHP_URL_SCHEME));
        if ($origin_host === '') {
            return false;
        }
        if ($token_scheme !== '' && $token_scheme !== $origin_scheme) {
            return false;
        }

        if (strpos($token_host, '*.') === 0) {
            $suffix = substr($token_host, 1);
            return substr($origin_host, -strlen($suffix)) === $suffix;
        }

        return $token_host === $origin_host;
    }

    /**
     * Unique storage key for an origin+directive pair.
     *
     * @param string $origin Origin.
     * @param string $directive Directive.
     * @return string
     */
    public static function origin_key($origin, $directive) {
        return md5(strtolower($origin) . '|' . strtolower($directive));
    }

    /**
     * Map CSP special blocked-uri values onto warning tokens.
     *
     * @param string $url Raw blocked-uri.
     * @return string
     */
    private static function special_token($url) {
        $raw = strtolower(trim($url, " \t\n\r\0\x0B'\""));
        if ($raw === 'inline' || $raw === 'unsafe-inline') {
            return "'unsafe-inline'";
        }
        if ($raw === 'eval' || $raw === 'unsafe-eval') {
            return "'unsafe-eval'";
        }
        if ($raw === 'data' || $raw === 'data:') {
            return 'data:';
        }
        if ($raw === 'blob' || $raw === 'blob:') {
            return 'blob:';
        }
        if ($raw === '*' || $raw === 'http:' || $raw === 'https:') {
            return $raw;
        }
        return '';
    }

    /**
     * @param string $scheme URL scheme.
     * @param int    $port Port number.
     * @return bool
     */
    private static function is_default_port($scheme, $port) {
        if (($scheme === 'http' || $scheme === 'ws') && $port === 80) {
            return true;
        }
        if (($scheme === 'https' || $scheme === 'wss') && $port === 443) {
            return true;
        }
        return false;
    }
}
