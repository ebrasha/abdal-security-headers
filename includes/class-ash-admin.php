<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name    : class-ash-admin.php
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2024-03-19 12:00:00
 * Description  : Admin interface class for managing security headers
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

class ASH_Admin {
    private $options;

    public function __construct() {
        add_action('admin_menu', array($this, 'add_plugin_page'));
        add_action('admin_init', array($this, 'page_init'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        $this->options = get_option('ash_options');
    }

    public function enqueue_admin_assets($hook) {
        if ($hook != 'settings_page_abdal-security-headers') {
            return;
        }
        
        // Enqueue Bootstrap
        wp_enqueue_style('bootstrap', 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css');
        wp_enqueue_script('bootstrap', 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js', array('jquery'), null, true);
        
        // Enqueue SweetAlert2
        wp_enqueue_style('sweetalert2', 'https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css');
        wp_enqueue_script('sweetalert2', 'https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.all.min.js', array(), null, true);
        
        // Enqueue our custom styles
        wp_enqueue_style('ash-admin-styles', ASH_PLUGIN_URL . 'assets/css/admin.css', array('bootstrap', 'sweetalert2'), ASH_VERSION);
        
        // Enqueue our custom scripts
        wp_enqueue_script('ash-admin-scripts', ASH_PLUGIN_URL . 'assets/js/admin.js', array('jquery', 'bootstrap', 'sweetalert2'), ASH_VERSION, true);

        // Add translation strings for JavaScript
        wp_localize_script('ash-admin-scripts', 'ashStrings', array(
            'confirmSave' => esc_html__('Are you sure you want to save these settings?', 'abdal-security-headers'),
            'yes' => esc_html__('Yes', 'abdal-security-headers'),
            'no' => esc_html__('No', 'abdal-security-headers'),
            'success' => esc_html__('Settings saved successfully', 'abdal-security-headers'),
            'ok' => esc_html__('OK', 'abdal-security-headers'),
            'error' => esc_html__('Error', 'abdal-security-headers'),
            'errorMessage' => esc_html__('An error occurred while saving the settings. Please try again.', 'abdal-security-headers')
        ));
    }

    public function add_plugin_page() {
        add_options_page(
            esc_html__('Abdal Security Headers', 'abdal-security-headers'),
            esc_html__('Security Headers', 'abdal-security-headers'),
            'manage_options',
            'abdal-security-headers',
            array($this, 'create_admin_page')
        );
    }

    public function create_admin_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Abdal Security Headers', 'abdal-security-headers'); ?></h1>
            <div class="ash-container">
                <form method="post" action="options.php" id="ash-settings-form">
                    <?php settings_fields('ash_options_group'); ?>
                    
                    <div class="ash-section">
                        <h2><?php echo esc_html__('Basic Security Headers', 'abdal-security-headers'); ?></h2>
                        <p class="ash-description"><?php echo esc_html__('Configure basic security headers for your website.', 'abdal-security-headers'); ?></p>
                        <?php do_settings_fields('abdal-security-headers', 'ash_basic_headers'); ?>
                    </div>

                    <div class="ash-section">
                        <h2><?php echo esc_html__('Additional Security Features', 'abdal-security-headers'); ?></h2>
                        <p class="ash-description"><?php echo esc_html__('Enable additional security features to enhance your website protection.', 'abdal-security-headers'); ?></p>
                        <?php do_settings_fields('abdal-security-headers', 'ash_additional_security'); ?>
                    </div>

                    <div class="ash-section">
                        <h2><?php echo esc_html__('Content Security Policy', 'abdal-security-headers'); ?></h2>
                        <div class="ash-field">
                            <span class="ash-field-label"><?php echo esc_html__('Enable Content Security Policy', 'abdal-security-headers'); ?></span>
                            <div class="ash-field-control">
                                <label class="ios-switch">
                                    <input type="checkbox" id="content_security_policy" 
                                           name="ash_options[content_security_policy]" value="1" 
                                           <?php checked('1', isset($this->options['content_security_policy']) ? $this->options['content_security_policy'] : '0'); ?>>
                                    <span class="ios-slider"></span>
                                </label>
                            </div>
                        </div>
                        
                        <div class="csp-directives" id="csp-directives" style="display: <?php echo isset($this->options['content_security_policy']) && $this->options['content_security_policy'] === '1' ? 'block' : 'none'; ?>;">
                            <p class="ash-description"><?php echo esc_html__('Configure Content Security Policy (CSP) directives', 'abdal-security-headers'); ?></p>
                            <?php do_settings_fields('abdal-security-headers', 'ash_csp_section'); ?>
                            
                            <div class="csp-accordion">
                                <div class="csp-accordion-header" id="csp-preview-header">
                                    <span><?php echo esc_html__('CSP Header Preview', 'abdal-security-headers'); ?></span>
                                    <div class="accordion-arrow"></div>
                                </div>
                                <div class="csp-accordion-content">
                                    <pre id="csp-preview-content"></pre>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="ash-submit-container">
                        <?php submit_button(null, 'primary', 'submit', true, array('id' => 'ash-submit-button')); ?>
                        <div class="ash-spinner"></div>
                    </div>
                </form>
            </div>
        </div>
        <?php
    }

    public function page_init() {
        register_setting(
            'ash_options_group',
            'ash_options',
            array($this, 'sanitize')
        );

        // Basic Security Headers Section
        add_settings_section(
            'ash_basic_headers',
            esc_html__('Basic Security Headers', 'abdal-security-headers'),
            array($this, 'print_section_info'),
            'abdal-security-headers'
        );

        // Original Headers
        $this->add_checkbox_field('x_xss_protection', esc_html__('X-XSS-Protection', 'abdal-security-headers'), 'ash_basic_headers');
        $this->add_checkbox_field('x_content_type_options', esc_html__('X-Content-Type-Options', 'abdal-security-headers'), 'ash_basic_headers');
        $this->add_checkbox_field('strict_transport_security', esc_html__('Strict-Transport-Security', 'abdal-security-headers'), 'ash_basic_headers');
        $this->add_checkbox_field('permissions_policy', esc_html__('Permissions-Policy', 'abdal-security-headers'), 'ash_basic_headers');
        $this->add_checkbox_field('x_frame_options', esc_html__('X-Frame-Options', 'abdal-security-headers'), 'ash_basic_headers');
        $this->add_checkbox_field('referrer_policy', esc_html__('Referrer-Policy', 'abdal-security-headers'), 'ash_basic_headers');

        // Additional Security Section
        add_settings_section(
            'ash_additional_security',
            esc_html__('Additional Security Features', 'abdal-security-headers'),
            array($this, 'print_additional_section_info'),
            'abdal-security-headers'
        );

        // New Security Options
        $this->add_checkbox_field('remove_x_powered_by', esc_html__('Remove X-Powered-By Header', 'abdal-security-headers'), 'ash_additional_security');
        $this->add_checkbox_field('hide_wp_version', esc_html__('Hide WordPress Version', 'abdal-security-headers'), 'ash_additional_security');
        $this->add_checkbox_field('remove_login_errors', esc_html__('Remove Login Error Messages', 'abdal-security-headers'), 'ash_additional_security');
        $this->add_checkbox_field('disable_xmlrpc', esc_html__('Disable XML-RPC', 'abdal-security-headers'), 'ash_additional_security');
        $this->add_checkbox_field('remove_x_pingback', esc_html__('Remove X-Pingback Header', 'abdal-security-headers'), 'ash_additional_security');
        $this->add_checkbox_field('restrict_rest_api', esc_html__('Restrict REST API Access', 'abdal-security-headers'), 'ash_additional_security');

        // CSP Section
        add_settings_section(
            'ash_csp_section',
            esc_html__('Content Security Policy', 'abdal-security-headers'),
            array($this, 'print_csp_section_info'),
            'abdal-security-headers'
        );

        // CSP Fields
        $csp_fields = array(
            'default-src' => esc_html__('Default Source', 'abdal-security-headers'),
            'script-src' => esc_html__('Script Source', 'abdal-security-headers'),
            'style-src' => esc_html__('Style Source', 'abdal-security-headers'),
            'img-src' => esc_html__('Image Source', 'abdal-security-headers'),
            'connect-src' => esc_html__('Connect Source', 'abdal-security-headers'),
            'font-src' => esc_html__('Font Source', 'abdal-security-headers'),
            'object-src' => esc_html__('Object Source', 'abdal-security-headers'),
            'media-src' => esc_html__('Media Source', 'abdal-security-headers'),
            'frame-src' => esc_html__('Frame Source', 'abdal-security-headers'),
            'worker-src' => esc_html__('Worker Source', 'abdal-security-headers'),
            'form-action' => esc_html__('Form Action', 'abdal-security-headers'),
            'base-uri' => esc_html__('Base URI', 'abdal-security-headers'),
            'sandbox' => esc_html__('Sandbox', 'abdal-security-headers'),
            'report-uri' => esc_html__('Report URI', 'abdal-security-headers'),
            'report-to' => esc_html__('Report To', 'abdal-security-headers')
        );

        foreach ($csp_fields as $key => $label) {
            $this->add_text_field('csp_' . str_replace('-', '_', $key), $label, 'ash_csp_section');
        }
    }

    private function add_checkbox_field($id, $title, $section) {
        add_settings_field(
            $id,
            $title,
            array($this, 'checkbox_callback'),
            'abdal-security-headers',
            $section,
            array('id' => $id)
        );
    }

    private function add_text_field($id, $title, $section) {
        add_settings_field(
            $id,
            $title,
            array($this, 'text_callback'),
            'abdal-security-headers',
            $section,
            array('id' => $id)
        );
    }

    public function checkbox_callback($args) {
        $id = $args['id'];
        $checked = isset($this->options[$id]) ? $this->options[$id] : '0';
        ?>
        <div class="ash-field">
            <span class="ash-field-label"><?php echo esc_html($args['label']); ?></span>
            <div class="ash-field-control">
                <label class="ios-switch">
                    <input type="checkbox" id="<?php echo esc_attr($id); ?>" 
                           name="ash_options[<?php echo esc_attr($id); ?>]" value="1" 
                           <?php checked('1', $checked); ?>>
                    <span class="ios-slider"></span>
                </label>
            </div>
        </div>
        <?php
    }

    public function text_callback($args) {
        $id = $args['id'];
        $value = isset($this->options[$id]) ? $this->options[$id] : '';
        ?>
        <div class="csp-field">
            <label for="<?php echo esc_attr($id); ?>"><?php echo esc_html($args['label']); ?></label>
            <input type="text" class="form-control" id="<?php echo esc_attr($id); ?>" 
                   name="ash_options[<?php echo esc_attr($id); ?>]" 
                   value="<?php echo esc_attr($value); ?>" 
                   data-csp-directive="<?php echo esc_attr(str_replace('csp_', '', $id)); ?>">
        </div>
        <?php
    }

    public function print_section_info() {
        esc_html_e('Configure basic security headers for your website.', 'abdal-security-headers');
    }

    public function print_additional_section_info() {
        esc_html_e('Enable additional security features to enhance your website protection.', 'abdal-security-headers');
    }

    public function print_csp_section_info() {
        esc_html_e('Configure Content Security Policy (CSP) directives', 'abdal-security-headers');
    }

    public function sanitize($input) {
        $new_input = array();
        
        // Get existing options
        $existing_options = get_option('ash_options', array());
        
        // Sanitize checkboxes
        $checkbox_fields = array(
            'x_xss_protection', 'x_content_type_options', 'strict_transport_security',
            'permissions_policy', 'x_frame_options', 'referrer_policy', 'content_security_policy',
            'remove_x_powered_by', 'hide_wp_version', 'remove_login_errors',
            'disable_xmlrpc', 'remove_x_pingback', 'restrict_rest_api'
        );

        foreach ($checkbox_fields as $field) {
            $new_input[$field] = isset($input[$field]) ? '1' : '0';
        }

        // Preserve CSP fields even when CSP is disabled
        $csp_fields = array(
            'csp_default_src', 'csp_script_src', 'csp_style_src', 'csp_img_src',
            'csp_connect_src', 'csp_font_src', 'csp_object_src', 'csp_media_src',
            'csp_frame_src', 'csp_worker_src', 'csp_form_action', 'csp_base_uri',
            'csp_sandbox', 'csp_report_uri', 'csp_report_to'
        );

        foreach ($csp_fields as $field) {
            // If the field exists in input, use it
            if (isset($input[$field])) {
                $new_input[$field] = sanitize_text_field($input[$field]);
            }
            // If not in input but exists in current options, preserve it
            elseif (isset($existing_options[$field])) {
                $new_input[$field] = $existing_options[$field];
            }
        }

        return $new_input;
    }
} 