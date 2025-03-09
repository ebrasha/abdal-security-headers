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
        $this->options = get_option('ash_options');
        
        // Add headers
        add_action('send_headers', array($this, 'set_security_headers'), 1);
        
        // Additional security features
        if (!empty($this->options['remove_x_powered_by'])) {
            add_action('init', array($this, 'remove_x_powered_by'));
        }
        
        if (!empty($this->options['hide_wp_version'])) {
            add_action('init', array($this, 'hide_wp_version'));
        }
        
        if (!empty($this->options['remove_login_errors'])) {
            add_filter('login_errors', array($this, 'remove_login_errors'));
        }
        
        // Enhanced XML-RPC Protection
        if (!empty($this->options['disable_xmlrpc'])) {
            // Disable XML-RPC functionality
            add_filter('xmlrpc_enabled', '__return_false');
            // Remove all XML-RPC methods
            add_filter('xmlrpc_methods', array($this, 'ash_disable_xmlrpc_methods'));
            // Block direct access to xmlrpc.php
            add_action('init', array($this, 'ash_block_xmlrpc_access'));
            // Remove X-Pingback header
            add_filter('wp_headers', array($this, 'remove_x_pingback'));
        }
        
        // Enhanced REST API Protection
        if (!empty($this->options['restrict_rest_api'])) {
            // Disable REST API completely
            add_filter('rest_authentication_errors', array($this, 'ash_disable_rest_api'));
            // Remove REST API links and headers
            add_action('after_setup_theme', array($this, 'ash_disable_rest_api_access'));
        }
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

        if (!empty($this->options['x_xss_protection'])) {
            @header('X-XSS-Protection: 1; mode=block');
        }
        
        if (!empty($this->options['x_content_type_options'])) {
            @header('X-Content-Type-Options: nosniff');
        }
        
        if (!empty($this->options['strict_transport_security'])) {
            @header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
        
        if (!empty($this->options['permissions_policy'])) {
            @header("Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()");
        }
        
        if (!empty($this->options['x_frame_options'])) {
            @header('X-Frame-Options: SAMEORIGIN');
        }
        
        if (!empty($this->options['referrer_policy'])) {
            @header('Referrer-Policy: strict-origin-when-cross-origin');
        }
        
        // Remove X-Powered-By if enabled
        if (!empty($this->options['remove_x_powered_by'])) {
            header_remove('X-Powered-By');
        }

        // Content-Security-Policy
        if (!empty($this->options['content_security_policy'])) {
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

    public function remove_x_powered_by() {
        @ini_set('expose_php', 'Off');
        if (function_exists('header_remove')) {
            header_remove('X-Powered-By');
        }
    }

    public function hide_wp_version() {
        // Remove version from head
        remove_action('wp_head', 'wp_generator');
        
        // Remove version from RSS
        add_filter('the_generator', '__return_empty_string');
        
        // Remove version from scripts and styles
        add_filter('style_loader_src', array($this, 'remove_version_from_source'));
        add_filter('script_loader_src', array($this, 'remove_version_from_source'));
    }

    public function remove_version_from_source($src) {
        if (strpos($src, 'ver=')) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }

    public function remove_login_errors() {
        return esc_html__('Invalid login credentials.', 'abdal-security-headers');
    }

    public function remove_x_pingback($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    /**
     * Disable all XML-RPC methods
     */
    public function ash_disable_xmlrpc_methods($methods) {
        return array();
    }

    /**
     * Block direct access to xmlrpc.php with 403 Forbidden
     */
    public function ash_block_xmlrpc_access() {
        if (strpos($_SERVER['REQUEST_URI'], 'xmlrpc.php') !== false) {
            header('HTTP/1.1 403 Forbidden');
            exit;
        }
    }

    /**
     * Disable REST API completely with error message
     */
    public function ash_disable_rest_api($access) {
        return new WP_Error(
            'rest_disabled',
            esc_html__('REST API is disabled.', 'abdal-security-headers'),
            array('status' => 403)
        );
    }

    /**
     * Remove REST API links and discovery
     */
    public function ash_disable_rest_api_access() {
        // Remove REST API info from head
        remove_action('wp_head', 'rest_output_link_wp_head');
        // Remove oEmbed discovery links
        remove_action('wp_head', 'wp_oembed_add_discovery_links');
        // Remove REST API from HTTP headers
        remove_action('template_redirect', 'rest_output_link_header', 11);
    }
} 