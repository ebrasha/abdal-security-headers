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
    private $headers_hook = '';
    private $csp_hook = '';
    private $features_hook = '';
    private $settings_hook = '';

    public function __construct() {
        add_action('admin_menu', array($this, 'add_plugin_page'));
        add_action('admin_init', array($this, 'page_init'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        add_action('wp_ajax_ash_security_center', array($this, 'ajax_security_center'));
        add_action('wp_ajax_ash_settings_transfer', array($this, 'ajax_settings_transfer'));
        add_filter('admin_body_class', array($this, 'filter_admin_body_class'));
        $this->options = get_option('ash_options', array());
        if (!is_array($this->options)) {
            $this->options = array();
        }
    }

    /**
     * Mark plugin admin screens so CSS can hide the WordPress footer and pad the canvas.
     *
     * @param string $classes Existing admin body classes.
     * @return string
     */
    public function filter_admin_body_class($classes) {
        $screen_id = '';
        if (function_exists('get_current_screen')) {
            $screen = get_current_screen();
            if (is_object($screen) && isset($screen->id)) {
                $screen_id = (string) $screen->id;
            }
        }

        $hooks = $this->plugin_admin_hooks();
        if (!in_array($screen_id, $hooks, true)) {
            return $classes;
        }

        return $classes . ' ash-admin-screen';
    }

    /**
     * Hook suffixes for every plugin admin screen.
     *
     * @return array
     */
    private function plugin_admin_hooks() {
        return array_values(
            array_filter(
                array(
                    $this->page_hook,
                    $this->headers_hook,
                    $this->csp_hook,
                    $this->features_hook,
                    $this->settings_hook,
                )
            )
        );
    }

    public function enqueue_admin_assets($hook) {
        if (!in_array($hook, $this->plugin_admin_hooks(), true)) {
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

        wp_localize_script('ash-admin-scripts', 'ashAdmin', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('ash_security_center'),
            'settingsNonce' => wp_create_nonce('ash_settings_transfer'),
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
                'confirmRemoveDirective' => __('Remove this custom Permissions-Policy directive?', 'abdal-security-headers'),
                'removeDirective' => __('Remove directive', 'abdal-security-headers'),
                'invalidDirectiveName' => __('Enter a valid directive name using lowercase letters, numbers, and hyphens.', 'abdal-security-headers'),
                'duplicateDirectiveName' => __('That directive name is already in the list.', 'abdal-security-headers'),
                'confirmApplyProfile' => __('Apply this Security Profile? Security Headers and Security Features will be updated. Content Security Policy will not change.', 'abdal-security-headers'),
                'confirmApplyHardened' => __('Hardened can affect compatibility with themes, plugins, XML-RPC clients, and some WordPress tools. Apply anyway? Content Security Policy will not change.', 'abdal-security-headers'),
                'confirmApplyManual' => __('Switch to Manual? Current Security Headers and Security Features will stay as they are.', 'abdal-security-headers'),
                'confirmResetProfile' => __('Reset Security Headers and Security Features to the Recommended profile? Content Security Policy will not change.', 'abdal-security-headers'),
                'confirmApplyTitle' => __('Apply Security Profile', 'abdal-security-headers'),
                'resetProfileTitle' => __('Reset Profile to Defaults', 'abdal-security-headers'),
                'selectProfile' => __('Select a Security Profile before applying.', 'abdal-security-headers'),
                'successApply' => __('Security Profile applied. Content Security Policy was not changed.', 'abdal-security-headers'),
                'successReset' => __('Security Headers and Security Features were reset to Recommended. Content Security Policy was not changed.', 'abdal-security-headers'),
                'successRecalculate' => __('Security status was recalculated from the current configuration.', 'abdal-security-headers'),
                'centerError' => __('The security center request could not be completed. Please try again.', 'abdal-security-headers'),
                'confirmImportTitle' => __('Import settings', 'abdal-security-headers'),
                'confirmImport' => __('Import will replace current plugin settings, including Security Headers, Security Features, Content Security Policy, Security Profile, and Settings. This cannot be undone from this screen.', 'abdal-security-headers'),
                'successExport' => __('Settings file downloaded.', 'abdal-security-headers'),
                'successImport' => __('Settings were imported. The page will reload.', 'abdal-security-headers'),
                'importNoFile' => __('Choose a settings JSON file before importing.', 'abdal-security-headers'),
                'chooseFile' => __('Choose file', 'abdal-security-headers'),
                'noFileSelected' => __('No file selected', 'abdal-security-headers'),
                'transferError' => __('The settings transfer could not be completed. Please try again.', 'abdal-security-headers'),
            ),
        ));

        if ($hook !== $this->csp_hook) {
            return;
        }

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
    }

    /**
     * Apply, reset, or recalculate Security Control Center state.
     *
     * @return void
     */
    public function ajax_security_center() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(
                array(
                    'message' => __('You are not allowed to manage these settings.', 'abdal-security-headers'),
                ),
                403
            );
        }

        check_ajax_referer('ash_security_center', 'nonce');

        if (!class_exists('ASH_Security_Profile') || !class_exists('ASH_Security_Status')) {
            wp_send_json_error(
                array(
                    'message' => __('Security Profile cannot be applied because required settings classes are missing.', 'abdal-security-headers'),
                ),
                500
            );
        }

        $task = isset($_POST['task']) ? sanitize_key(wp_unslash($_POST['task'])) : '';
        $allowed = array('apply', 'reset', 'recalculate');
        if (!in_array($task, $allowed, true)) {
            wp_send_json_error(
                array(
                    'message' => __('The requested security center action is not valid.', 'abdal-security-headers'),
                ),
                400
            );
        }

        if ($task === 'recalculate') {
            delete_transient(ASH_Security_Status::PROBE_TRANSIENT);
            $options = get_option('ash_options', array());
            if (!is_array($options)) {
                $options = array();
            }
            $options = ASH_Security_Status::persist_drift($options);
            $payload = ASH_Security_Status::payload($options, true, true);
            $payload['message'] = __('Security status was recalculated from the current configuration.', 'abdal-security-headers');
            wp_send_json_success($payload);
        }

        $profile = 'recommended';
        if ($task === 'apply') {
            $raw_profile = isset($_POST['profile']) ? sanitize_key(wp_unslash($_POST['profile'])) : '';
            if (!in_array($raw_profile, ASH_Security_Profile::ids(), true)) {
                wp_send_json_error(
                    array(
                        'message' => __('Select a Security Profile before applying.', 'abdal-security-headers'),
                    ),
                    400
                );
            }
            $profile = $raw_profile;
        }

        $result = ASH_Security_Profile::apply($profile);
        if (is_wp_error($result)) {
            wp_send_json_error(
                array(
                    'message' => $result->get_error_message(),
                ),
                400
            );
        }

        $payload = ASH_Security_Status::payload($result, true, true);
        if ($task === 'reset') {
            $payload['message'] = __('Security Headers and Security Features were reset to Recommended. Content Security Policy was not changed.', 'abdal-security-headers');
        } else {
            $payload['message'] = __('Security Profile applied. Content Security Policy was not changed.', 'abdal-security-headers');
        }
        wp_send_json_success($payload);
    }

    /**
     * Export or import plugin configuration from the Settings screen.
     *
     * @return void
     */
    public function ajax_settings_transfer() {
        if (!class_exists('ASH_Settings_Transfer')) {
            wp_send_json_error(
                array(
                    'message' => __('The settings transfer could not be completed. Please try again.', 'abdal-security-headers'),
                ),
                500
            );
        }

        ASH_Settings_Transfer::handle_ajax();
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

        add_submenu_page(
            'abdal-security-headers',
            esc_html__('Dashboard', 'abdal-security-headers'),
            esc_html__('Dashboard', 'abdal-security-headers'),
            'manage_options',
            'abdal-security-headers'
        );

        $this->headers_hook = add_submenu_page(
            'abdal-security-headers',
            esc_html__('Security Headers', 'abdal-security-headers'),
            esc_html__('Security Headers', 'abdal-security-headers'),
            'manage_options',
            'abdal-security-headers-headers',
            array($this, 'create_headers_page')
        );

        $this->csp_hook = add_submenu_page(
            'abdal-security-headers',
            esc_html__('Content Security Policy', 'abdal-security-headers'),
            esc_html__('Content Security Policy', 'abdal-security-headers'),
            'manage_options',
            'abdal-security-headers-csp',
            array($this, 'create_csp_page')
        );

        $this->features_hook = add_submenu_page(
            'abdal-security-headers',
            esc_html__('Security Features', 'abdal-security-headers'),
            esc_html__('Security Features', 'abdal-security-headers'),
            'manage_options',
            'abdal-security-headers-features',
            array($this, 'create_features_page')
        );

        $this->settings_hook = add_submenu_page(
            'abdal-security-headers',
            esc_html__('Settings', 'abdal-security-headers'),
            esc_html__('Settings', 'abdal-security-headers'),
            'manage_options',
            'abdal-security-headers-settings',
            array($this, 'create_plugin_settings_page')
        );
    }

    public function create_admin_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to manage these settings.', 'abdal-security-headers'));
        }

        require_once ASH_PLUGIN_DIR . 'includes/class-ash-admin-ui.php';
        $ui = new ASH_Admin_UI($this->options);
        $ui->render();
    }

    /**
     * Render the Security Headers screen.
     *
     * @return void
     */
    public function create_headers_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to manage these settings.', 'abdal-security-headers'));
        }

        require_once ASH_PLUGIN_DIR . 'includes/class-ash-admin-ui.php';
        $ui = new ASH_Admin_UI($this->options);
        $ui->render_security_headers();
    }

    /**
     * Render the Content Security Policy screen.
     *
     * @return void
     */
    public function create_csp_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to manage these settings.', 'abdal-security-headers'));
        }

        require_once ASH_PLUGIN_DIR . 'includes/class-ash-admin-ui.php';
        $ui = new ASH_Admin_UI($this->options);
        $ui->render_content_security_policy();
    }

    /**
     * Render the Security Features screen.
     *
     * @return void
     */
    public function create_features_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to manage these settings.', 'abdal-security-headers'));
        }

        require_once ASH_PLUGIN_DIR . 'includes/class-ash-admin-ui.php';
        $ui = new ASH_Admin_UI($this->options);
        $ui->render_security_features();
    }

    /**
     * Render the plugin Settings screen (plugin-owned options, not HTTP headers).
     *
     * @return void
     */
    public function create_plugin_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to manage these settings.', 'abdal-security-headers'));
        }

        $plugin_settings = get_option('ash_plugin_settings', array());
        if (!is_array($plugin_settings)) {
            $plugin_settings = array();
        }

        require_once ASH_PLUGIN_DIR . 'includes/class-ash-admin-ui.php';
        $ui = new ASH_Admin_UI($this->options);
        $ui->render_plugin_settings($plugin_settings);
    }

    public function page_init() {
        register_setting(
            'ash_options_group',
            'ash_options',
            array($this, 'sanitize')
        );

        register_setting(
            'ash_plugin_settings_group',
            'ash_plugin_settings',
            array(
                'type' => 'array',
                'sanitize_callback' => array($this, 'sanitize_plugin_settings'),
                'default' => array(
                    'remove_data_on_uninstall' => '0',
                ),
                'show_in_rest' => false,
                'capability' => 'manage_options',
            )
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
        $existing_options = get_option('ash_options', array());
        if (!is_array($existing_options)) {
            $existing_options = array();
        }

        if (!is_array($input)) {
            return $existing_options;
        }

        $screen = isset($input['_ash_screen']) ? sanitize_key((string) $input['_ash_screen']) : '';
        $allowed_screens = array('headers', 'features', 'csp');
        if (!in_array($screen, $allowed_screens, true)) {
            // Settings forms always send _ash_screen. Programmatic writes (Security Profile,
            // CSP Assistant, drift sync) call update_option without that token; the registered
            // sanitize_option filter must not replace them with the previous stored array.
            $option_page = isset($_POST['option_page']) ? sanitize_key(wp_unslash($_POST['option_page'])) : '';
            if ($option_page === 'ash_options_group') {
                return $existing_options;
            }
            unset($input['_ash_screen']);
            return $input;
        }

        $sanitized = $existing_options;

        $header_fields = array(
            'x_xss_protection',
            'x_content_type_options',
            'strict_transport_security',
            'permissions_policy',
            'x_frame_options',
            'referrer_policy',
        );
        $feature_fields = array(
            'remove_x_powered_by',
            'hide_wp_version',
            'remove_login_errors',
            'disable_xmlrpc',
            'remove_x_pingback',
            'restrict_rest_api',
        );
        $csp_fields = array(
            'csp_default_src', 'csp_script_src', 'csp_style_src', 'csp_img_src',
            'csp_connect_src', 'csp_font_src', 'csp_object_src', 'csp_media_src',
            'csp_frame_src', 'csp_worker_src', 'csp_form_action', 'csp_base_uri',
            'csp_sandbox', 'csp_report_uri', 'csp_report_to',
        );

        if ($screen === 'headers') {
            foreach ($header_fields as $field) {
                $sanitized[$field] = (isset($input[$field]) && (string) $input[$field] === '1') ? '1' : '0';
            }
            if (class_exists('ASH_Header_Settings')) {
                $sanitized = ASH_Header_Settings::sanitize_headers_input($input, $sanitized);
            }
        }

        if ($screen === 'features') {
            foreach ($feature_fields as $field) {
                $sanitized[$field] = (isset($input[$field]) && (string) $input[$field] === '1') ? '1' : '0';
            }
            if (class_exists('ASH_Feature_Settings')) {
                $sanitized = ASH_Feature_Settings::sanitize_features_input($input, $sanitized);
            }
        }

        if ($screen === 'csp') {
            $sanitized['content_security_policy'] = (isset($input['content_security_policy']) && (string) $input['content_security_policy'] === '1') ? '1' : '0';
            foreach ($csp_fields as $field) {
                if (isset($input[$field])) {
                    $sanitized[$field] = sanitize_text_field($input[$field]);
                }
            }
        }

        unset($sanitized['_ash_screen']);

        if (($screen === 'headers' || $screen === 'features') && class_exists('ASH_Security_Profile')) {
            $sanitized = ASH_Security_Profile::sync_after_save($sanitized);
        }

        return $sanitized;
    }

    /**
     * Sanitize plugin-owned settings. Unknown keys are kept; invalid fields are repaired.
     *
     * @param mixed $input Raw submitted settings.
     * @return array
     */
    public function sanitize_plugin_settings($input) {
        $existing = get_option('ash_plugin_settings', array());
        if (!is_array($existing)) {
            $existing = array();
        }

        if (!is_array($input)) {
            $input = array();
        }

        $sanitized = $existing;
        $sanitized['remove_data_on_uninstall'] = (isset($input['remove_data_on_uninstall']) && (string) $input['remove_data_on_uninstall'] === '1') ? '1' : '0';

        return $sanitized;
    }
}
