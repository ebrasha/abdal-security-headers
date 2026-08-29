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
    private $page_hook = '';

    public function __construct() {
        add_action('admin_menu', array($this, 'add_plugin_page'));
        add_action('admin_init', array($this, 'page_init'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        $this->options = get_option('ash_options', array());
        if (!is_array($this->options)) {
            $this->options = array();
        }
    }

    public function enqueue_admin_assets($hook) {
        if (empty($this->page_hook) || $hook !== $this->page_hook) {
            return;
        }

        $css_path = ASH_PLUGIN_DIR . 'assets/css/admin.css';
        $js_path = ASH_PLUGIN_DIR . 'assets/js/admin.js';
        $css_version = file_exists($css_path) ? (string) filemtime($css_path) : ASH_VERSION;
        $js_version = file_exists($js_path) ? (string) filemtime($js_path) : ASH_VERSION;

        wp_enqueue_style(
            'ash-admin-styles',
            ASH_PLUGIN_URL . 'assets/css/admin.css',
            array('dashicons'),
            $css_version
        );

        wp_enqueue_script(
            'ash-admin-scripts',
            ASH_PLUGIN_URL . 'assets/js/admin.js',
            array(),
            $js_version,
            true
        );

        $assistant_js_path = ASH_PLUGIN_DIR . 'assets/js/csp-assistant.js';
        $assistant_js_version = file_exists($assistant_js_path) ? (string) filemtime($assistant_js_path) : ASH_VERSION;
        wp_enqueue_script(
            'ash-csp-assistant',
            ASH_PLUGIN_URL . 'assets/js/csp-assistant.js',
            array('ash-admin-scripts'),
            $assistant_js_version,
            true
        );

        wp_localize_script('ash-csp-assistant', 'ashCspAssistant', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ash_csp_assistant'),
            'siteHost' => strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST)),
            'optionMap' => class_exists('ASH_CSP_Assistant') ? ASH_CSP_Assistant::OPTION_MAP : array(),
            'strings' => class_exists('ASH_CSP_Assistant') ? ASH_CSP_Assistant::ui_strings() : array(),
            'initial' => class_exists('ASH_CSP_Assistant') ? ASH_CSP_Assistant::instance()->payload() : array(),
        ));

        wp_localize_script('ash-admin-scripts', 'ashAdmin', array(
            'headerFields' => array(
                'x_xss_protection',
                'x_content_type_options',
                'strict_transport_security',
                'permissions_policy',
                'x_frame_options',
                'referrer_policy',
            ),
            'featureFields' => array(
                'remove_x_powered_by',
                'hide_wp_version',
                'remove_login_errors',
                'disable_xmlrpc',
                'remove_x_pingback',
                'restrict_rest_api',
            ),
            'strings' => array(
                'confirmSave' => __('Are you sure you want to save these settings?', 'abdal-security-headers'),
                'confirmReset' => __('Reset unsaved changes and restore the last saved values?', 'abdal-security-headers'),
                'saveChanges' => __('Save Changes', 'abdal-security-headers'),
                'reset' => __('Reset', 'abdal-security-headers'),
                'yes' => __('Yes', 'abdal-security-headers'),
                'no' => __('No', 'abdal-security-headers'),
                'success' => __('Settings saved successfully', 'abdal-security-headers'),
                'ok' => __('OK', 'abdal-security-headers'),
                'cancel' => __('Cancel', 'abdal-security-headers'),
                'editorOk' => _x('OK', 'csp editor confirm', 'abdal-security-headers'),
                /* translators: %s: CSP directive name such as script-src */
                'editDirective' => __('Edit %s', 'abdal-security-headers'),
                'error' => __('Error', 'abdal-security-headers'),
                'errorMessage' => __('An error occurred while saving the settings. Please try again.', 'abdal-security-headers'),
                'copied' => __('Copied', 'abdal-security-headers'),
                'copyCsp' => __('Copy CSP header', 'abdal-security-headers'),
                'copyFailed' => __('Unable to copy the CSP header.', 'abdal-security-headers'),
                'cspEmpty' => __('Content-Security-Policy header is enabled but no directives are set.', 'abdal-security-headers'),
                'cspDisabled' => __('Content Security Policy is disabled. Enable it to send this header.', 'abdal-security-headers'),
                'statusGood' => _x('Good', 'security status', 'abdal-security-headers'),
                'statusFair' => _x('Fair', 'security status', 'abdal-security-headers'),
                'statusNeedsAttention' => _x('Needs attention', 'security status', 'abdal-security-headers'),
                'statusGoodHint' => __('Most security controls are enabled.', 'abdal-security-headers'),
                'statusFairHint' => __('Some recommended security controls are still disabled.', 'abdal-security-headers'),
                'statusNeedsHint' => __('Enable more security headers and hardening options.', 'abdal-security-headers'),
                'cspOn' => _x('Enabled', 'CSP status', 'abdal-security-headers'),
                'cspOff' => _x('Disabled', 'CSP status', 'abdal-security-headers'),
                'cspOnHint' => __('Content Security Policy is being sent with responses.', 'abdal-security-headers'),
                'cspOffHint' => __('Content Security Policy is currently turned off.', 'abdal-security-headers'),
                /* translators: 1: number of enabled headers, 2: total headers */
                'headersHint' => __('%1$d of %2$d security headers are enabled', 'abdal-security-headers'),
                /* translators: 1: number of enabled features, 2: total features */
                'featuresHint' => __('%1$d of %2$d additional features are enabled', 'abdal-security-headers'),
            ),
        ));
    }

    public function add_plugin_page() {
        $this->page_hook = add_menu_page(
            esc_html__('Abdal Security Headers', 'abdal-security-headers'),
            esc_html__('Security Headers', 'abdal-security-headers'),
            'manage_options',
            'abdal-security-headers',
            array($this, 'create_admin_page'),
            'dashicons-shield',
            58
        );
    }

    public function create_admin_page() {
        require_once ASH_PLUGIN_DIR . 'includes/class-ash-admin-ui.php';
        $ui = new ASH_Admin_UI($this->options);
        $ui->render();
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
            array(
                'id' => $id,
                'label' => $title,
                'class' => 'ash-settings-row'
            )
        );
    }

    private function add_text_field($id, $title, $section) {
        add_settings_field(
            $id,
            $title,
            array($this, 'text_callback'),
            'abdal-security-headers',
            $section,
            array(
                'id' => $id,
                'label' => $title,
                'class' => 'ash-settings-row'
            )
        );
    }

    public function checkbox_callback($args) {
        $id = isset($args['id']) ? $args['id'] : '';
        $label = isset($args['label']) ? $args['label'] : '';
        $checked = isset($this->options[$id]) ? $this->options[$id] : '0';
        ?>
        <label>
            <input type="checkbox" id="<?php echo esc_attr($id); ?>"
                   name="ash_options[<?php echo esc_attr($id); ?>]" value="1"
                   <?php checked('1', $checked); ?>>
            <?php echo esc_html($label); ?>
        </label>
        <?php
    }

    public function text_callback($args) {
        $id = isset($args['id']) ? $args['id'] : '';
        $label = isset($args['label']) ? $args['label'] : '';
        $value = isset($this->options[$id]) ? $this->options[$id] : '';
        ?>
        <label for="<?php echo esc_attr($id); ?>"><?php echo esc_html($label); ?></label>
        <input type="text" id="<?php echo esc_attr($id); ?>"
               name="ash_options[<?php echo esc_attr($id); ?>]"
               value="<?php echo esc_attr($value); ?>">
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
