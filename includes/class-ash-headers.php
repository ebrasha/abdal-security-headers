<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name    : class-ash-headers.php
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2024-03-19 12:00:00
 * Description  : Handles the security headers implementation for Abdal Security Headers plugin
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

class ASH_Headers {
    private $options;

    public function __construct() {
        $this->options = get_option('ash_options', array());
        if (!is_array($this->options)) {
            $this->options = array();
        }
        if (class_exists('ASH_Header_Settings')) {
            $this->options = ASH_Header_Settings::hydrate($this->options);
        }
        
        // Add headers
        add_action('send_headers', array($this, 'set_security_headers'), 1);
    }

    /**
     * Format CSP value to ensure proper spacing and quotes
     */
    private function format_csp_value($value) {
        // Split the value by spaces
        $parts = preg_split('/\s+/', trim($value));
        $formatted_parts = array();
        
        foreach ($parts as $part) {
            $part = trim($part);
            
            // If already quoted, keep as is
            if (preg_match("/^'.*'$/", $part)) {
                $formatted_parts[] = $part;
            }
            // Special keywords that need quotes if not already quoted
            elseif (in_array($part, ['self', 'unsafe-inline', 'unsafe-eval', 'none'])) {
                $formatted_parts[] = "'" . $part . "'";
            }
            // Special values that don't need quotes
            elseif (in_array($part, ['data:', 'blob:', '*']) || strpos($part, 'data:') === 0 || strpos($part, 'blob:') === 0) {
                $formatted_parts[] = $part;
            }
            // URLs and other values - preserve exactly as entered
            else {
                // Ensure URLs end with trailing slash
                $formatted_parts[] = rtrim($part, '/') . '/';
            }
        }
        
        return implode(' ', $formatted_parts);
    }

    public function set_security_headers() {
        if (headers_sent()) {
            return;
        }

        if (!empty($this->options['x_xss_protection']) && (string) $this->options['x_xss_protection'] === '1') {
            $xss_value = class_exists('ASH_Header_Settings')
                ? ASH_Header_Settings::build_xss_protection($this->options)
                : '1; mode=block';
            $this->send_security_header('X-XSS-Protection', $xss_value);
        }

        if (!empty($this->options['x_content_type_options']) && (string) $this->options['x_content_type_options'] === '1') {
            $this->send_security_header('X-Content-Type-Options', 'nosniff');
        }

        if (!empty($this->options['strict_transport_security']) && (string) $this->options['strict_transport_security'] === '1' && is_ssl()) {
            $hsts_value = class_exists('ASH_Header_Settings')
                ? ASH_Header_Settings::build_hsts($this->options)
                : 'max-age=31536000; includeSubDomains; preload';
            $this->send_security_header('Strict-Transport-Security', $hsts_value);
        }

        if (!empty($this->options['permissions_policy']) && (string) $this->options['permissions_policy'] === '1') {
            $pp_value = class_exists('ASH_Header_Settings')
                ? ASH_Header_Settings::build_permissions_policy($this->options)
                : 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()';
            $this->send_security_header('Permissions-Policy', $pp_value);
        }

        if (!empty($this->options['x_frame_options']) && (string) $this->options['x_frame_options'] === '1') {
            $xfo_value = class_exists('ASH_Header_Settings')
                ? ASH_Header_Settings::build_x_frame_options($this->options)
                : 'SAMEORIGIN';
            $this->send_security_header('X-Frame-Options', $xfo_value);
        }

        if (!empty($this->options['referrer_policy']) && (string) $this->options['referrer_policy'] === '1') {
            $referrer_value = class_exists('ASH_Header_Settings')
                ? ASH_Header_Settings::build_referrer_policy($this->options)
                : 'strict-origin-when-cross-origin';
            $this->send_security_header('Referrer-Policy', $referrer_value);
        }

        // Content-Security-Policy is frontend-only so wp-admin assets are never blocked.
        // Learning/monitoring uses Report-Only instead of a blocking policy.
        $assistant_learning = class_exists('ASH_CSP_Assistant') && ASH_CSP_Assistant::is_learning();
        if (!$this->is_wordpress_admin_request() && !empty($this->options['content_security_policy']) && !$assistant_learning) {
            $csp_directives = array();
            
            // Define all CSP directives to check
            $directives = array(
                'default-src', 'script-src', 'style-src', 'img-src',
                'connect-src', 'font-src', 'object-src', 'media-src',
                'frame-src', 'worker-src', 'form-action', 'base-uri',
                'sandbox', 'report-uri', 'report-to'
            );

            // Build CSP directives from user settings with proper formatting
            foreach ($directives as $directive) {
                $option_key = 'csp_' . str_replace('-', '_', $directive);
                if (!empty($this->options[$option_key])) {
                    $formatted_value = $this->format_csp_value($this->options[$option_key]);
                    $csp_directives[] = $directive . ' ' . $formatted_value;
                }
            }

            // Apply CSP header if directives exist
            if (!empty($csp_directives)) {
                $csp_value = implode('; ', array_map('trim', $csp_directives));
                // First try with Content-Security-Policy
                @header("Content-Security-Policy: " . $csp_value);
                // Also send as X-Content-Security-Policy for older browsers
                @header("X-Content-Security-Policy: " . $csp_value);
                // And as X-WebKit-CSP for even older browsers
                @header("X-WebKit-CSP: " . $csp_value);
            }
        }
    }

    /**
     * Detect wp-admin requests even if send_headers runs before the main query.
     *
     * @return bool
     */
    private function is_wordpress_admin_request() {
        if (is_admin()) {
            return true;
        }

        if (defined('WP_ADMIN') && WP_ADMIN) {
            return true;
        }

        $request_uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        if ($request_uri !== '' && strpos($request_uri, '/wp-admin/') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Send a security header after stripping CR/LF from the value.
     *
     * @param string $name Header name.
     * @param string $value Header value.
     * @return void
     */
    private function send_security_header($name, $value) {
        $value = str_replace(array("\r", "\n"), '', (string) $value);
        if ($value === '') {
            return;
        }
        header($name . ': ' . $value);
    }
} 