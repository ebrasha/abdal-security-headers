<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name    : abdal-security-headers.php
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2024-03-19 12:00:00
 * Description  :WordPress Security Headers Manager plugin, featuring full security headers control, advanced security features, and Content Security Policy (CSP).
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

/**
 * Plugin Name: Abdal Security Headers
 * Plugin URI: https://github.com/ebrasha/abdal-security-headers
 * Description:  WordPress Security Headers Manager plugin, featuring full security headers control, advanced security features, and Content Security Policy (CSP).
 * Version: 5.1.1
 * Author: Ebrahim Shafiei (EbraSha)
 * Author URI: https://github.com/ebrasha
 * Text Domain: abdal-security-headers
 * Domain Path: /languages
 * License: GPL v3
 */

// Prevent direct access to this file
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('ASH_VERSION', '3.5.0');
define('ASH_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('ASH_PLUGIN_URL', plugin_dir_url(__FILE__));

// Load text domain for translations
function ash_load_textdomain() {
    load_plugin_textdomain(
        'abdal-security-headers',
        false,
        dirname(plugin_basename(__FILE__)) . '/languages/'
    );
}
add_action('plugins_loaded', 'ash_load_textdomain');

// Include required files
require_once ASH_PLUGIN_DIR . 'includes/class-ash-admin.php';
require_once ASH_PLUGIN_DIR . 'includes/class-ash-headers.php';

// Initialize the plugin
function ash_init() {
    // Initialize admin
    if (is_admin()) {
        new ASH_Admin();
    }
    
    // Initialize headers
    new ASH_Headers();
}
add_action('plugins_loaded', 'ash_init');

// Activation hook
register_activation_hook(__FILE__, 'ash_activate');
function ash_activate() {
    $site_url = get_site_url();
    
    // Get existing options
    $existing_options = get_option('ash_options', array());
    
    // Set default options
    $default_options = array(
        'x_xss_protection' => '1',
        'x_content_type_options' => '1',
        'strict_transport_security' => '1',
        'permissions_policy' => '1',
        'x_frame_options' => '1',
        'referrer_policy' => '1',
        'content_security_policy' => '1',
        'remove_x_powered_by' => '0',
        'hide_wp_version' => '0',
        'remove_login_errors' => '0',
        'disable_xmlrpc' => '0',
        'remove_x_pingback' => '0',
        'restrict_rest_api' => '0',
        'csp_default_src' => "'self' ".$site_url,
        'csp_script_src' => "'self' ".$site_url,
        'csp_style_src' => "'self' ".$site_url,
        'csp_img_src' => "'self' ".$site_url,
        'csp_connect_src' => "'self' ".$site_url,
        'csp_font_src' => "'self' ".$site_url,
        'csp_object_src' => "'self' ".$site_url,
        'csp_media_src' => "'self' ".$site_url,
        'csp_frame_src' => "'self' ".$site_url,
        'csp_worker_src' => "'self' ".$site_url,
        'csp_form_action' => " * ",
        'csp_base_uri' => '',
        'csp_sandbox' => '',
        'csp_report_uri' => '',
        'csp_report_to' => ''
    );
    
    // Merge existing options with defaults
    // This ensures we only set default values for options that don't already exist
    $final_options = wp_parse_args($existing_options, $default_options);
    
    // Update options in database
    update_option('ash_options', $final_options);
}

// Deactivation hook
register_deactivation_hook(__FILE__, 'ash_deactivate');
function ash_deactivate() {
    // No need to do anything here
}

// Uninstall hook for complete cleanup
register_uninstall_hook(__FILE__, 'ash_uninstall');
function ash_uninstall() {
    // Remove all plugin options and any other plugin-related data
    delete_option('ash_options');
    
    // Clean up any additional plugin data if needed
    // For example, delete custom post types, taxonomies, etc.
    
    // Clear any scheduled cron jobs if they exist
    wp_clear_scheduled_hook('ash_scheduled_tasks');
} 