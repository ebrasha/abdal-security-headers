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
 * Version: 5.4.2
 * Author: Ebrahim Shafiei (EbraSha)
 * Author URI: https://github.com/ebrasha
 * Text Domain: abdal-security-headers
 * Domain Path: /languages
 * License: GPLv2 or later
 */


// Prevent direct access to this file
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('ASH_VERSION', '5.4.2');
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
require_once ASH_PLUGIN_DIR . 'includes/class-ash-csp-normalizer.php';
require_once ASH_PLUGIN_DIR . 'includes/class-ash-csp-repository.php';
require_once ASH_PLUGIN_DIR . 'includes/class-ash-csp-static-detector.php';
require_once ASH_PLUGIN_DIR . 'includes/class-ash-csp-disk-scanner.php';
require_once ASH_PLUGIN_DIR . 'includes/class-ash-csp-assistant.php';

// Initialize the plugin
function ash_init() {
    // Initialize admin
    if (is_admin()) {
        new ASH_Admin();
    }

    ASH_CSP_Assistant::instance();

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
        'content_security_policy' => '0',
        'remove_x_powered_by' => '1',
        'hide_wp_version' => '1',
        'remove_login_errors' => '1',
        'disable_xmlrpc' => '1',
        'remove_x_pingback' => '1',
        'restrict_rest_api' => '1',
        'csp_default_src' => "'self' ".$site_url,
        'csp_script_src' => "'self' blob:  'unsafe-inline' 'unsafe-eval'  *.google.com *.gstatic.com *.googletagmanager.com *.google-analytics.com *.facebook.net *.twitter.com *.youtube.com *.vimeo.com *.cloudflare.com *.bootstrapcdn.com *.jsdelivr.net *.fontawesome.com  ".$site_url,
        'csp_style_src' => "'self' 'unsafe-inline'   *.googleapis.com *.bootstrapcdn.com *.jsdelivr.net *.fontawesome.com  ".$site_url,
        'csp_img_src' => "'self' data: blob:  *.gravatar.com *.google.com *.gstatic.com *.wp.com *.cloudflare.com *.facebook.com *.twitter.com  *.x.com  *.youtube.com *.vimeo.com  ".$site_url,
        'csp_connect_src' => "'self'   *.google-analytics.com *.googletagmanager.com *.facebook.net *.twitter.com  *.x.com  *.paypal.com *.stripe.com *.woocommerce.com  ".$site_url,
        'csp_font_src' => "'self' data:  *.googleapis.com *.gstatic.com *.fontawesome.com  ".$site_url,
        'csp_object_src' => "'self' ".$site_url,
        'csp_media_src' => "'self' ".$site_url,
        'csp_frame_src' => "'self' *.google.com *.youtube.com *.vimeo.com *.facebook.com *.twitter.com  *.x.com  ".$site_url,
        'csp_worker_src' => '',
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

    require_once ASH_PLUGIN_DIR . 'includes/class-ash-csp-repository.php';
    ASH_CSP_Repository::install();
    if (!wp_next_scheduled('ash_csp_assistant_cron')) {
        wp_schedule_event(time() + 60, 'hourly', 'ash_csp_assistant_cron');
    }
}

// Deactivation hook
register_deactivation_hook(__FILE__, 'ash_deactivate');
function ash_deactivate() {
    wp_clear_scheduled_hook('ash_csp_assistant_cron');
}

// Uninstall hook for complete cleanup
register_uninstall_hook(__FILE__, 'ash_uninstall');
function ash_uninstall() {
    delete_option('ash_options');
    delete_option('ash_csp_assistant_state');
    delete_option('ash_csp_db_version');
    wp_clear_scheduled_hook('ash_scheduled_tasks');
    wp_clear_scheduled_hook('ash_csp_assistant_cron');

    global $wpdb;
    $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'ash_csp_sources');
} 