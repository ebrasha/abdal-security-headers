<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-header-settings.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-31 21:01:47
 * Description : Shared allowlists, sanitization, and header value builders for configurable security headers
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

class ASH_Header_Settings {
    const PRELOAD_MIN_MAX_AGE = 31536000;
    const MAX_AGE_CAP = 630720000;
    const MAX_CUSTOM_DIRECTIVES = 40;
    const MAX_ORIGINS = 25;
    const MAX_ORIGIN_LENGTH = 255;
    const MAX_REPORT_URL_LENGTH = 2048;

    /**
     * Permissions-Policy directives supported in the editor.
     *
     * @return array
     */
    public static function directive_names() {
        return array(
            'accelerometer',
            'ambient-light-sensor',
            'autoplay',
            'bluetooth',
            'browsing-topics',
            'camera',
            'display-capture',
            'encrypted-media',
            'fullscreen',
            'gamepad',
            'geolocation',
            'gyroscope',
            'hid',
            'idle-detection',
            'local-fonts',
            'magnetometer',
            'microphone',
            'midi',
            'otp-credentials',
            'payment',
            'picture-in-picture',
            'publickey-credentials-create',
            'publickey-credentials-get',
            'screen-wake-lock',
            'serial',
            'speaker-selection',
            'storage-access',
            'usb',
            'web-share',
            'window-management',
            'xr-spatial-tracking',
        );
    }

    /**
     * Directives that older plugin versions always denied.
     *
     * @return array
     */
    public static function legacy_denied_directives() {
        return array(
            'accelerometer',
            'camera',
            'geolocation',
            'gyroscope',
            'magnetometer',
            'microphone',
            'payment',
            'usb',
        );
    }

    /**
     * HSTS max-age preset values in seconds, excluding Custom.
     *
     * @return array
     */
    public static function max_age_preset_values() {
        return array(
            '86400',
            '604800',
            '2592000',
            '15768000',
            '31536000',
            '63072000',
        );
    }

    /**
     * X-XSS-Protection stored policy keys.
     *
     * @return array
     */
    public static function xss_policies() {
        return array(
            '0',
            '1',
            '1_mode_block',
            '1_report',
        );
    }

    /**
     * X-Frame-Options values offered in the UI.
     *
     * @return array
     */
    public static function x_frame_options_policies() {
        return array(
            'DENY',
            'SAMEORIGIN',
        );
    }

    /**
     * Referrer-Policy tokens.
     *
     * @return array
     */
    public static function referrer_policies() {
        return array(
            'no-referrer',
            'no-referrer-when-downgrade',
            'origin',
            'origin-when-cross-origin',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'unsafe-url',
        );
    }

    /**
     * Permissions-Policy allowlist modes.
     *
     * @return array
     */
    public static function pp_policies() {
        return array(
            'not_set',
            'deny',
            'self',
            'all',
            'custom',
        );
    }

    /**
     * Defaults merged on activation for missing header-config keys only.
     *
     * Existing installs without the new keys keep the previously emitted values.
     *
     * @param mixed $existing Current ash_options value.
     * @return array
     */
    public static function activation_defaults($existing) {
        $existing = is_array($existing) ? $existing : array();
        $is_existing = array_key_exists('x_xss_protection', $existing);
        $xss_enabled = $is_existing && isset($existing['x_xss_protection']) && (string) $existing['x_xss_protection'] === '1';

        return array(
            'xss_policy' => $xss_enabled ? '1_mode_block' : '0',
            'xss_report_url' => '',
            'hsts_max_age' => '31536000',
            'hsts_include_subdomains' => $is_existing ? '1' : '0',
            'hsts_preload' => $is_existing ? '1' : '0',
            'x_frame_options_policy' => 'SAMEORIGIN',
            'referrer_policy_value' => 'strict-origin-when-cross-origin',
            'pp_directives' => self::default_pp_directives(true),
            'pp_custom' => array(),
        );
    }

    /**
     * Fill missing header-config keys in memory without writing the database.
     *
     * @param mixed $options Stored ash_options.
     * @return array
     */
    public static function hydrate($options) {
        if (!is_array($options)) {
            $options = array();
        }

        $legacy_header_config = !array_key_exists('xss_policy', $options)
            && !array_key_exists('hsts_max_age', $options)
            && !array_key_exists('pp_directives', $options);

        if (!isset($options['xss_policy']) || !self::is_xss_policy($options['xss_policy'])) {
            $xss_enabled = isset($options['x_xss_protection']) && (string) $options['x_xss_protection'] === '1';
            $options['xss_policy'] = $xss_enabled ? '1_mode_block' : '0';
        }

        if (!isset($options['xss_report_url']) || !is_string($options['xss_report_url'])) {
            $options['xss_report_url'] = '';
        }

        if (!isset($options['hsts_max_age']) || !self::is_max_age_value($options['hsts_max_age'])) {
            $options['hsts_max_age'] = '31536000';
        } else {
            $options['hsts_max_age'] = (string) absint($options['hsts_max_age']);
        }

        if (!isset($options['hsts_include_subdomains'])) {
            $options['hsts_include_subdomains'] = $legacy_header_config ? '1' : '0';
        } else {
            $options['hsts_include_subdomains'] = ((string) $options['hsts_include_subdomains'] === '1') ? '1' : '0';
        }

        if (!isset($options['hsts_preload'])) {
            $options['hsts_preload'] = $legacy_header_config ? '1' : '0';
        } else {
            $options['hsts_preload'] = ((string) $options['hsts_preload'] === '1') ? '1' : '0';
        }

        $normalized_hsts = self::apply_hsts_preload_rules(
            (int) $options['hsts_max_age'],
            $options['hsts_include_subdomains'] === '1',
            $options['hsts_preload'] === '1'
        );
        $options['hsts_max_age'] = (string) $normalized_hsts['max_age'];
        $options['hsts_include_subdomains'] = $normalized_hsts['include_subdomains'] ? '1' : '0';
        $options['hsts_preload'] = $normalized_hsts['preload'] ? '1' : '0';

        if (!isset($options['x_frame_options_policy']) || !self::is_x_frame_options_policy($options['x_frame_options_policy'])) {
            $options['x_frame_options_policy'] = 'SAMEORIGIN';
        }

        if (!isset($options['referrer_policy_value']) || !self::is_referrer_policy($options['referrer_policy_value'])) {
            $options['referrer_policy_value'] = 'strict-origin-when-cross-origin';
        }

        $use_legacy_pp = !isset($options['pp_directives']) || !is_array($options['pp_directives']);
        $options['pp_directives'] = self::hydrate_pp_directives(
            isset($options['pp_directives']) ? $options['pp_directives'] : array(),
            $use_legacy_pp
        );
        $options['pp_custom'] = self::hydrate_pp_custom(isset($options['pp_custom']) ? $options['pp_custom'] : array());

        return $options;
    }

    /**
     * Sanitize header-screen fields from Settings API input. Enable flags are already merged.
     *
     * @param array $input Submitted ash_options slice.
     * @param array $sanitized Options being saved (existing + header enables).
     * @return array
     */
    public static function sanitize_headers_input($input, $sanitized) {
        if (!is_array($input)) {
            $input = array();
        }
        if (!is_array($sanitized)) {
            $sanitized = array();
        }

        $policy = isset($input['xss_policy']) ? (string) $input['xss_policy'] : '0';
        $sanitized['xss_policy'] = self::is_xss_policy($policy) ? $policy : '0';

        $report_url = isset($input['xss_report_url']) ? (string) $input['xss_report_url'] : '';
        $sanitized['xss_report_url'] = self::sanitize_report_url($report_url);

        $preset = isset($input['hsts_max_age_preset']) ? (string) $input['hsts_max_age_preset'] : '31536000';
        $preset_values = self::max_age_preset_values();
        if ($preset === 'custom') {
            $max_age = isset($input['hsts_max_age_custom']) ? absint($input['hsts_max_age_custom']) : self::PRELOAD_MIN_MAX_AGE;
        } elseif (in_array($preset, $preset_values, true)) {
            $max_age = absint($preset);
        } else {
            $max_age = self::PRELOAD_MIN_MAX_AGE;
        }
        if ($max_age > self::MAX_AGE_CAP) {
            $max_age = self::MAX_AGE_CAP;
        }

        $include_subdomains = isset($input['hsts_include_subdomains']) && (string) $input['hsts_include_subdomains'] === '1';
        $preload = isset($input['hsts_preload']) && (string) $input['hsts_preload'] === '1';
        $normalized_hsts = self::apply_hsts_preload_rules($max_age, $include_subdomains, $preload);
        $sanitized['hsts_max_age'] = (string) $normalized_hsts['max_age'];
        $sanitized['hsts_include_subdomains'] = $normalized_hsts['include_subdomains'] ? '1' : '0';
        $sanitized['hsts_preload'] = $normalized_hsts['preload'] ? '1' : '0';

        $xfo = isset($input['x_frame_options_policy']) ? (string) $input['x_frame_options_policy'] : 'SAMEORIGIN';
        $sanitized['x_frame_options_policy'] = self::is_x_frame_options_policy($xfo) ? $xfo : 'SAMEORIGIN';

        $referrer = isset($input['referrer_policy_value']) ? (string) $input['referrer_policy_value'] : 'strict-origin-when-cross-origin';
        $sanitized['referrer_policy_value'] = self::is_referrer_policy($referrer) ? $referrer : 'strict-origin-when-cross-origin';

        $submitted_directives = isset($input['pp_directives']) && is_array($input['pp_directives']) ? $input['pp_directives'] : array();
        $directives = array();
        foreach (self::directive_names() as $name) {
            $item = isset($submitted_directives[$name]) && is_array($submitted_directives[$name]) ? $submitted_directives[$name] : array();
            $directives[$name] = self::sanitize_directive_state($item);
        }
        $sanitized['pp_directives'] = $directives;

        $submitted_custom = isset($input['pp_custom']) && is_array($input['pp_custom']) ? $input['pp_custom'] : array();
        $sanitized['pp_custom'] = self::sanitize_pp_custom($submitted_custom);

        return $sanitized;
    }

    /**
     * Build the X-XSS-Protection header value.
     *
     * @param array $options Hydrated options.
     * @return string
     */
    public static function build_xss_protection($options) {
        $policy = isset($options['xss_policy']) ? (string) $options['xss_policy'] : '0';
        if ($policy === '1') {
            return '1';
        }
        if ($policy === '1_mode_block') {
            return '1; mode=block';
        }
        if ($policy === '1_report') {
            $url = self::sanitize_report_url(isset($options['xss_report_url']) ? $options['xss_report_url'] : '');
            if ($url === '' || strpos($url, ';') !== false) {
                return '1';
            }
            return '1; report=' . $url;
        }
        return '0';
    }

    /**
     * Build the Strict-Transport-Security header value.
     *
     * @param array $options Hydrated options.
     * @return string
     */
    public static function build_hsts($options) {
        $max_age = isset($options['hsts_max_age']) ? absint($options['hsts_max_age']) : self::PRELOAD_MIN_MAX_AGE;
        $include = isset($options['hsts_include_subdomains']) && (string) $options['hsts_include_subdomains'] === '1';
        $preload = isset($options['hsts_preload']) && (string) $options['hsts_preload'] === '1';
        $normalized = self::apply_hsts_preload_rules($max_age, $include, $preload);

        $parts = array('max-age=' . $normalized['max_age']);
        if ($normalized['include_subdomains']) {
            $parts[] = 'includeSubDomains';
        }
        if ($normalized['preload']) {
            $parts[] = 'preload';
        }

        return implode('; ', $parts);
    }

    /**
     * Build the Permissions-Policy header value. Empty string means do not send.
     *
     * @param array $options Hydrated options.
     * @return string
     */
    public static function build_permissions_policy($options) {
        $parts = array();
        $directives = isset($options['pp_directives']) && is_array($options['pp_directives']) ? $options['pp_directives'] : array();

        foreach (self::directive_names() as $name) {
            $state = isset($directives[$name]) && is_array($directives[$name]) ? $directives[$name] : array();
            $serialized = self::serialize_directive($name, $state);
            if ($serialized !== '') {
                $parts[] = $serialized;
            }
        }

        $custom = isset($options['pp_custom']) && is_array($options['pp_custom']) ? $options['pp_custom'] : array();
        foreach ($custom as $item) {
            if (!is_array($item) || empty($item['name'])) {
                continue;
            }
            $name = self::sanitize_directive_name($item['name']);
            if ($name === '') {
                continue;
            }
            $serialized = self::serialize_directive($name, $item);
            if ($serialized !== '') {
                $parts[] = $serialized;
            }
        }

        return implode(', ', $parts);
    }

    /**
     * Build the X-Frame-Options header value.
     *
     * @param array $options Hydrated options.
     * @return string
     */
    public static function build_x_frame_options($options) {
        $policy = isset($options['x_frame_options_policy']) ? (string) $options['x_frame_options_policy'] : 'SAMEORIGIN';
        return self::is_x_frame_options_policy($policy) ? $policy : 'SAMEORIGIN';
    }

    /**
     * Build the Referrer-Policy header value.
     *
     * @param array $options Hydrated options.
     * @return string
     */
    public static function build_referrer_policy($options) {
        $policy = isset($options['referrer_policy_value']) ? (string) $options['referrer_policy_value'] : 'strict-origin-when-cross-origin';
        return self::is_referrer_policy($policy) ? $policy : 'strict-origin-when-cross-origin';
    }

    /**
     * Default Permissions-Policy editor state for built-in directives.
     *
     * @param bool $legacy_denies Whether to deny the historical eight features.
     * @return array
     */
    public static function default_pp_directives($legacy_denies = true) {
        $denied = $legacy_denies ? array_flip(self::legacy_denied_directives()) : array();
        $directives = array();
        foreach (self::directive_names() as $name) {
            if (isset($denied[$name])) {
                $directives[$name] = array(
                    'enabled' => '1',
                    'policy' => 'deny',
                    'origins' => array(),
                );
            } else {
                $directives[$name] = self::empty_directive_state();
            }
        }
        return $directives;
    }

    /**
     * @return array
     */
    public static function empty_directive_state() {
        return array(
            'enabled' => '0',
            'policy' => 'not_set',
            'origins' => array(),
        );
    }

    /**
     * @param mixed $value Policy key.
     * @return bool
     */
    public static function is_xss_policy($value) {
        return in_array((string) $value, self::xss_policies(), true);
    }

    /**
     * @param mixed $value Policy token.
     * @return bool
     */
    public static function is_x_frame_options_policy($value) {
        return in_array((string) $value, self::x_frame_options_policies(), true);
    }

    /**
     * @param mixed $value Policy token.
     * @return bool
     */
    public static function is_referrer_policy($value) {
        return in_array((string) $value, self::referrer_policies(), true);
    }

    /**
     * @param mixed $value Seconds.
     * @return bool
     */
    public static function is_max_age_value($value) {
        if (is_int($value)) {
            return $value >= 0 && $value <= self::MAX_AGE_CAP;
        }
        if (!is_string($value) || $value === '' || !ctype_digit($value)) {
            return false;
        }
        $age = (int) $value;
        return $age >= 0 && $age <= self::MAX_AGE_CAP;
    }

    /**
     * Enforce preload requirements: includeSubDomains and max-age >= 1 year.
     *
     * @param int  $max_age Seconds.
     * @param bool $include_subdomains Whether includeSubDomains is on.
     * @param bool $preload Whether preload is on.
     * @return array
     */
    public static function apply_hsts_preload_rules($max_age, $include_subdomains, $preload) {
        $max_age = (int) $max_age;
        if ($max_age < 0) {
            $max_age = 0;
        }
        if ($max_age > self::MAX_AGE_CAP) {
            $max_age = self::MAX_AGE_CAP;
        }

        if ($preload) {
            $include_subdomains = true;
            if ($max_age < self::PRELOAD_MIN_MAX_AGE) {
                $max_age = self::PRELOAD_MIN_MAX_AGE;
            }
        }

        return array(
            'max_age' => $max_age,
            'include_subdomains' => (bool) $include_subdomains,
            'preload' => (bool) $preload,
        );
    }

    /**
     * @param string $url Candidate reporting URL.
     * @return string
     */
    public static function sanitize_report_url($url) {
        $url = trim((string) $url);
        if ($url === '' || strlen($url) > self::MAX_REPORT_URL_LENGTH) {
            return '';
        }
        $clean = esc_url_raw($url, array('http', 'https'));
        if ($clean === '' || strpos($clean, ' ') !== false || strpos($clean, ';') !== false) {
            return '';
        }
        return $clean;
    }

    /**
     * @param mixed $name Feature name.
     * @return string
     */
    public static function sanitize_directive_name($name) {
        $name = strtolower(trim((string) $name));
        if ($name === '' || !preg_match('/^[a-z][a-z0-9-]{1,62}$/', $name)) {
            return '';
        }
        return $name;
    }

    /**
     * @param mixed $raw Newline list or array of origins.
     * @return array
     */
    public static function sanitize_origins($raw) {
        if (is_string($raw)) {
            $lines = preg_split('/\r\n|\r|\n/', $raw);
        } elseif (is_array($raw)) {
            $lines = $raw;
        } else {
            return array();
        }

        $origins = array();
        foreach ($lines as $line) {
            if (count($origins) >= self::MAX_ORIGINS) {
                break;
            }
            $origin = self::sanitize_origin_token($line);
            if ($origin === '' || in_array($origin, $origins, true)) {
                continue;
            }
            $origins[] = $origin;
        }

        return $origins;
    }

    /**
     * @param mixed $value One origin line.
     * @return string `self` or an http(s) origin, otherwise empty.
     */
    public static function sanitize_origin_token($value) {
        $value = trim((string) $value);
        if ($value === '' || strlen($value) > self::MAX_ORIGIN_LENGTH) {
            return '';
        }

        $lower = strtolower($value);
        if ($lower === 'self' || $lower === "'self'" || $lower === '"self"') {
            return 'self';
        }
        if ($lower === '*' || $lower === 'none' || $lower === '()') {
            return '';
        }

        $first = substr($value, 0, 1);
        $last = substr($value, -1);
        if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
            $value = substr($value, 1, -1);
        }

        $url = esc_url_raw($value, array('http', 'https'));
        if ($url === '') {
            return '';
        }

        $parts = wp_parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return '';
        }
        if (!empty($parts['user']) || !empty($parts['pass'])) {
            return '';
        }
        if (!empty($parts['query']) || !empty($parts['fragment'])) {
            return '';
        }
        if (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/') {
            return '';
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        $port = isset($parts['port']) ? ':' . absint($parts['port']) : '';

        return $scheme . '://' . $host . $port;
    }

    /**
     * @param array $item Raw directive state.
     * @return array
     */
    public static function sanitize_directive_state($item) {
        if (!is_array($item)) {
            $item = array();
        }

        $policy = isset($item['policy']) ? sanitize_key((string) $item['policy']) : 'not_set';
        if (!in_array($policy, self::pp_policies(), true)) {
            $policy = 'not_set';
        }

        return array(
            'enabled' => (isset($item['enabled']) && (string) $item['enabled'] === '1') ? '1' : '0',
            'policy' => $policy,
            'origins' => self::sanitize_origins(isset($item['origins']) ? $item['origins'] : array()),
        );
    }

    /**
     * @param array $list Submitted custom directives.
     * @return array
     */
    public static function sanitize_pp_custom($list) {
        if (!is_array($list)) {
            return array();
        }

        $builtin = array_flip(self::directive_names());
        $seen = array();
        $custom = array();

        foreach ($list as $item) {
            if (count($custom) >= self::MAX_CUSTOM_DIRECTIVES) {
                break;
            }
            if (!is_array($item)) {
                continue;
            }
            $name = self::sanitize_directive_name(isset($item['name']) ? $item['name'] : '');
            if ($name === '' || isset($builtin[$name]) || isset($seen[$name])) {
                continue;
            }
            $seen[$name] = true;
            $state = self::sanitize_directive_state($item);
            $state['name'] = $name;
            $custom[] = $state;
        }

        return $custom;
    }

    /**
     * @param mixed $stored Stored built-in map.
     * @param bool  $use_legacy_denies Fill missing keys from the historical deny list.
     * @return array
     */
    private static function hydrate_pp_directives($stored, $use_legacy_denies) {
        $defaults = self::default_pp_directives($use_legacy_denies);
        if (!is_array($stored)) {
            return $defaults;
        }

        $directives = array();
        foreach (self::directive_names() as $name) {
            if (isset($stored[$name]) && is_array($stored[$name])) {
                $directives[$name] = self::sanitize_directive_state($stored[$name]);
            } else {
                $directives[$name] = $defaults[$name];
            }
        }

        return $directives;
    }

    /**
     * @param mixed $stored Stored custom list.
     * @return array
     */
    private static function hydrate_pp_custom($stored) {
        return self::sanitize_pp_custom(is_array($stored) ? $stored : array());
    }

    /**
     * @param string $name Feature name.
     * @param array  $state Directive state.
     * @return string Empty when the directive must be omitted.
     */
    private static function serialize_directive($name, $state) {
        $state = self::sanitize_directive_state($state);
        if ($state['enabled'] !== '1' || $state['policy'] === 'not_set') {
            return '';
        }

        if ($state['policy'] === 'deny') {
            return $name . '=()';
        }
        if ($state['policy'] === 'self') {
            return $name . '=(self)';
        }
        if ($state['policy'] === 'all') {
            return $name . '=*';
        }

        $allowlist = self::build_custom_allowlist($state['origins']);
        if ($allowlist === '') {
            return '';
        }

        return $name . '=' . $allowlist;
    }

    /**
     * @param array $origins Sanitized origin tokens.
     * @return string
     */
    private static function build_custom_allowlist($origins) {
        $tokens = array();
        $has_self = false;
        $urls = array();

        foreach ($origins as $origin) {
            if ($origin === 'self') {
                $has_self = true;
                continue;
            }
            $urls[] = $origin;
        }

        if ($has_self) {
            $tokens[] = 'self';
        }
        foreach ($urls as $url) {
            $tokens[] = '"' . $url . '"';
        }

        if (empty($tokens)) {
            return '';
        }

        return '(' . implode(' ', $tokens) . ')';
    }
}
