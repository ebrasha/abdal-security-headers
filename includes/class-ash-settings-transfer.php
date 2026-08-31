<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-settings-transfer.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-31 22:23:33
 * Description : Export and import plugin configuration as a JSON snapshot
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

class ASH_Settings_Transfer {
    const PLUGIN_SLUG = 'abdal-security-headers';
    const FORMAT = 1;
    const MAX_BYTES = 1048576;
    const MAX_JSON_DEPTH = 24;
    const NONCE_ACTION = 'ash_settings_transfer';

    /**
     * Privileged AJAX entry for export and import.
     *
     * @return void
     */
    public static function handle_ajax() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(
                array(
                    'message' => __('You are not allowed to manage these settings.', 'abdal-security-headers'),
                ),
                403
            );
        }

        check_ajax_referer(self::NONCE_ACTION, 'nonce');

        $task = isset($_POST['task']) ? sanitize_key(wp_unslash($_POST['task'])) : '';
        if ($task === 'export') {
            $payload = self::export_payload();
            wp_send_json_success(
                array(
                    'filename' => self::export_filename(),
                    'payload' => $payload,
                    'message' => __('Settings file downloaded.', 'abdal-security-headers'),
                )
            );
        }

        if ($task === 'import') {
            $result = self::import_from_upload();
            if (is_wp_error($result)) {
                wp_send_json_error(
                    array(
                        'message' => $result->get_error_message(),
                    ),
                    400
                );
            }

            wp_send_json_success(
                array(
                    'message' => __('Settings were imported. The page will reload.', 'abdal-security-headers'),
                )
            );
        }

        wp_send_json_error(
            array(
                'message' => __('The requested settings transfer action is not valid.', 'abdal-security-headers'),
            ),
            400
        );
    }

    /**
     * Build a JSON-safe snapshot of plugin configuration.
     *
     * @return array
     */
    public static function export_payload() {
        $options = get_option('ash_options', array());
        if (!is_array($options)) {
            $options = array();
        }
        unset($options['_ash_screen']);

        $plugin_settings = get_option('ash_plugin_settings', array());
        if (!is_array($plugin_settings)) {
            $plugin_settings = array();
        }

        $data = array(
            'ash_options' => $options,
            'ash_plugin_settings' => $plugin_settings,
        );

        $exclusions = get_option('ash_csp_disk_exclusions', false);
        if ($exclusions !== false) {
            $data['ash_csp_disk_exclusions'] = is_array($exclusions) ? $exclusions : array();
        }

        $scope = get_option('ash_csp_disk_scope', false);
        if (is_array($scope)) {
            $data['ash_csp_disk_scope'] = $scope;
        }

        return array(
            'plugin' => self::PLUGIN_SLUG,
            'format' => self::FORMAT,
            'plugin_version' => defined('ASH_VERSION') ? ASH_VERSION : '',
            'exported_at' => gmdate('c'),
            'data' => $data,
        );
    }

    /**
     * @return string
     */
    public static function export_filename() {
        $day = function_exists('current_time') ? current_time('Y-m-d') : gmdate('Y-m-d');
        return 'abdal-security-headers-settings-' . $day . '.json';
    }

    /**
     * @return true|\WP_Error
     */
    private static function import_from_upload() {
        if (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
            return new WP_Error(
                'ash_import_nofile',
                __('Choose a settings JSON file before importing.', 'abdal-security-headers')
            );
        }

        $error = isset($_FILES['file']['error']) ? (int) $_FILES['file']['error'] : UPLOAD_ERR_NO_FILE;
        if ($error !== UPLOAD_ERR_OK) {
            return new WP_Error(
                'ash_import_upload',
                __('The settings file could not be uploaded. Please try again.', 'abdal-security-headers')
            );
        }

        $size = isset($_FILES['file']['size']) ? (int) $_FILES['file']['size'] : 0;
        if ($size <= 0 || $size > self::MAX_BYTES) {
            return new WP_Error(
                'ash_import_size',
                __('The settings file is empty or larger than the allowed size.', 'abdal-security-headers')
            );
        }

        $tmp = isset($_FILES['file']['tmp_name']) ? (string) $_FILES['file']['tmp_name'] : '';
        if ($tmp === '' || !is_uploaded_file($tmp)) {
            return new WP_Error(
                'ash_import_tmp',
                __('The settings file could not be read.', 'abdal-security-headers')
            );
        }

        $name = isset($_FILES['file']['name']) ? sanitize_file_name((string) $_FILES['file']['name']) : '';
        $ext = strtolower((string) pathinfo($name, PATHINFO_EXTENSION));
        if ($ext !== 'json') {
            return new WP_Error(
                'ash_import_type',
                __('The settings file must be a JSON export from this plugin.', 'abdal-security-headers')
            );
        }

        $type = isset($_FILES['file']['type']) ? strtolower((string) $_FILES['file']['type']) : '';
        $type = trim((string) strtok($type, ';'));
        $allowed_types = array(
            '',
            'application/json',
            'text/json',
            'text/plain',
            'application/octet-stream',
        );
        if (!in_array($type, $allowed_types, true)) {
            return new WP_Error(
                'ash_import_type',
                __('The settings file must be a JSON export from this plugin.', 'abdal-security-headers')
            );
        }

        $raw = file_get_contents($tmp);
        if (!is_string($raw) || $raw === '') {
            return new WP_Error(
                'ash_import_empty',
                __('The settings file could not be read.', 'abdal-security-headers')
            );
        }

        if (substr($raw, 0, 3) === "\xEF\xBB\xBF") {
            $raw = substr($raw, 3);
        }

        $decoded = json_decode($raw, true, self::MAX_JSON_DEPTH);
        if (!is_array($decoded) || json_last_error() !== JSON_ERROR_NONE) {
            return new WP_Error(
                'ash_import_json',
                __('The settings file is not valid JSON.', 'abdal-security-headers')
            );
        }

        return self::import_payload($decoded);
    }

    /**
     * Validate, sanitize, and atomically store an export payload.
     *
     * @param array $payload Decoded JSON.
     * @return true|\WP_Error
     */
    private static function import_payload($payload) {
        if (!is_array($payload)) {
            return new WP_Error(
                'ash_import_shape',
                __('The settings file is not a valid Abdal Security Headers export.', 'abdal-security-headers')
            );
        }

        $plugin = isset($payload['plugin']) ? sanitize_key((string) $payload['plugin']) : '';
        $format = isset($payload['format']) ? absint($payload['format']) : 0;
        if ($plugin !== self::PLUGIN_SLUG || $format !== self::FORMAT) {
            return new WP_Error(
                'ash_import_plugin',
                __('The settings file is not a valid Abdal Security Headers export.', 'abdal-security-headers')
            );
        }

        $data = isset($payload['data']) && is_array($payload['data']) ? $payload['data'] : array();
        if ($data === array()) {
            return new WP_Error(
                'ash_import_empty_data',
                __('The settings file does not contain any configuration.', 'abdal-security-headers')
            );
        }

        $plan = array();

        if (array_key_exists('ash_options', $data)) {
            if (!is_array($data['ash_options'])) {
                return new WP_Error(
                    'ash_import_options',
                    __('The exported Security Headers configuration is not valid.', 'abdal-security-headers')
                );
            }
            if ($data['ash_options'] !== array()) {
                $plan['ash_options'] = self::sanitize_imported_options($data['ash_options']);
            }
        }

        if (array_key_exists('ash_plugin_settings', $data)) {
            if (!is_array($data['ash_plugin_settings'])) {
                return new WP_Error(
                    'ash_import_plugin_settings',
                    __('The exported plugin settings are not valid.', 'abdal-security-headers')
                );
            }
            $plan['ash_plugin_settings'] = self::sanitize_imported_plugin_settings($data['ash_plugin_settings']);
        }

        if (array_key_exists('ash_csp_disk_exclusions', $data) && class_exists('ASH_CSP_Disk_Scanner')) {
            $plan['ash_csp_disk_exclusions'] = ASH_CSP_Disk_Scanner::sanitize_exclusions($data['ash_csp_disk_exclusions']);
        }

        if (array_key_exists('ash_csp_disk_scope', $data) && class_exists('ASH_CSP_Disk_Scanner')) {
            $scope = is_array($data['ash_csp_disk_scope']) ? $data['ash_csp_disk_scope'] : array();
            $plan['ash_csp_disk_scope'] = array(
                'enabled' => (!empty($scope['enabled']) && (string) $scope['enabled'] !== '0') ? 1 : 0,
                'targets' => ASH_CSP_Disk_Scanner::sanitize_scope_targets(isset($scope['targets']) ? $scope['targets'] : array()),
            );
        }

        if ($plan === array()) {
            return new WP_Error(
                'ash_import_empty_data',
                __('The settings file does not contain any configuration.', 'abdal-security-headers')
            );
        }

        return self::commit_plan($plan);
    }

    /**
     * Overlay imported header, feature, CSP, and profile values onto current options.
     *
     * @param array $imported Imported ash_options.
     * @return array
     */
    private static function sanitize_imported_options($imported) {
        $existing = get_option('ash_options', array());
        if (!is_array($existing)) {
            $existing = array();
        }
        if (!is_array($imported)) {
            $imported = array();
        }
        unset($imported['_ash_screen']);

        $merged = array_merge($existing, $imported);
        $merged = self::adapt_hsts_input($merged);
        $sanitized = $existing;

        $header_flags = class_exists('ASH_Security_Profile')
            ? ASH_Security_Profile::header_flags()
            : array(
                'x_xss_protection',
                'x_content_type_options',
                'strict_transport_security',
                'permissions_policy',
                'x_frame_options',
                'referrer_policy',
            );
        foreach ($header_flags as $field) {
            if (array_key_exists($field, $imported)) {
                $sanitized[$field] = ((string) $imported[$field] === '1') ? '1' : '0';
            }
        }
        if (class_exists('ASH_Header_Settings')) {
            $sanitized = ASH_Header_Settings::sanitize_headers_input($merged, $sanitized);
        }

        $feature_flags = class_exists('ASH_Security_Profile')
            ? ASH_Security_Profile::feature_flags()
            : array(
                'remove_x_powered_by',
                'hide_wp_version',
                'remove_login_errors',
                'disable_xmlrpc',
                'remove_x_pingback',
                'restrict_rest_api',
            );
        foreach ($feature_flags as $field) {
            if (array_key_exists($field, $imported)) {
                $sanitized[$field] = ((string) $imported[$field] === '1') ? '1' : '0';
            }
        }
        if (class_exists('ASH_Feature_Settings')) {
            $sanitized = ASH_Feature_Settings::sanitize_features_input($merged, $sanitized);
        }

        if (array_key_exists('content_security_policy', $imported)) {
            $sanitized['content_security_policy'] = ((string) $imported['content_security_policy'] === '1') ? '1' : '0';
        }
        foreach (self::csp_fields() as $field) {
            if (array_key_exists($field, $imported)) {
                $sanitized[$field] = sanitize_text_field((string) $imported[$field]);
            }
        }

        if (array_key_exists('security_profile', $imported) && class_exists('ASH_Security_Profile')) {
            $sanitized['security_profile'] = ASH_Security_Profile::sanitize_id($imported['security_profile']);
            $sanitized = ASH_Security_Profile::sync_after_save($sanitized);
        }

        unset($sanitized['_ash_screen']);
        return $sanitized;
    }

    /**
     * Stored options keep hsts_max_age. The header sanitizer reads the form preset field.
     *
     * @param array $imported Imported options.
     * @return array
     */
    private static function adapt_hsts_input($imported) {
        if (!is_array($imported) || isset($imported['hsts_max_age_preset'])) {
            return $imported;
        }
        if (!isset($imported['hsts_max_age']) || !class_exists('ASH_Header_Settings')) {
            return $imported;
        }

        $age = (string) absint($imported['hsts_max_age']);
        $presets = ASH_Header_Settings::max_age_preset_values();
        if (in_array($age, $presets, true)) {
            $imported['hsts_max_age_preset'] = $age;
        } else {
            $imported['hsts_max_age_preset'] = 'custom';
            $imported['hsts_max_age_custom'] = $age;
        }

        return $imported;
    }

    /**
     * @param array $imported Imported plugin settings.
     * @return array
     */
    private static function sanitize_imported_plugin_settings($imported) {
        $existing = get_option('ash_plugin_settings', array());
        if (!is_array($existing)) {
            $existing = array();
        }
        if (!is_array($imported)) {
            $imported = array();
        }

        $sanitized = $existing;
        if (array_key_exists('remove_data_on_uninstall', $imported)) {
            $sanitized['remove_data_on_uninstall'] = ((string) $imported['remove_data_on_uninstall'] === '1') ? '1' : '0';
        }

        return $sanitized;
    }

    /**
     * @return array
     */
    private static function csp_fields() {
        return array(
            'csp_default_src',
            'csp_script_src',
            'csp_style_src',
            'csp_img_src',
            'csp_connect_src',
            'csp_font_src',
            'csp_object_src',
            'csp_media_src',
            'csp_frame_src',
            'csp_worker_src',
            'csp_form_action',
            'csp_base_uri',
            'csp_sandbox',
            'csp_report_uri',
            'csp_report_to',
        );
    }

    /**
     * Write the import plan. Restore previous values if a later write cannot be verified.
     *
     * @param array $plan Sanitized option map.
     * @return true|\WP_Error
     */
    private static function commit_plan($plan) {
        $snapshots = array();
        foreach ($plan as $name => $unused) {
            $snapshots[$name] = get_option($name, false);
        }
        unset($unused);

        foreach ($plan as $name => $value) {
            update_option($name, $value);
            $stored = get_option($name, false);
            if (!self::option_matches($name, $value, $stored)) {
                self::restore_snapshots($snapshots);
                return new WP_Error(
                    'ash_import_commit',
                    __('The settings could not be imported completely. Previous settings were kept.', 'abdal-security-headers')
                );
            }
        }

        if (class_exists('ASH_Security_Status')) {
            delete_transient(ASH_Security_Status::PROBE_TRANSIENT);
        }

        return true;
    }

    /**
     * @param string $name Option name.
     * @param mixed  $wanted Written value.
     * @param mixed  $stored Stored value.
     * @return bool
     */
    private static function option_matches($name, $wanted, $stored) {
        if ($name === 'ash_plugin_settings') {
            $wanted_flag = isset($wanted['remove_data_on_uninstall']) ? (string) $wanted['remove_data_on_uninstall'] : '0';
            $stored_flag = (is_array($stored) && isset($stored['remove_data_on_uninstall'])) ? (string) $stored['remove_data_on_uninstall'] : '0';
            return $wanted_flag === $stored_flag;
        }

        if ($name === 'ash_csp_disk_exclusions') {
            if (!is_array($wanted) || !is_array($stored)) {
                return false;
            }
            return array_values($wanted) === array_values($stored);
        }

        if ($name === 'ash_csp_disk_scope') {
            if (!is_array($wanted) || !is_array($stored)) {
                return false;
            }
            $wanted_enabled = (!empty($wanted['enabled']) && (string) $wanted['enabled'] !== '0') ? 1 : 0;
            $stored_enabled = (!empty($stored['enabled']) && (string) $stored['enabled'] !== '0') ? 1 : 0;
            $wanted_targets = isset($wanted['targets']) && is_array($wanted['targets']) ? array_values($wanted['targets']) : array();
            $stored_targets = isset($stored['targets']) && is_array($stored['targets']) ? array_values($stored['targets']) : array();
            return $wanted_enabled === $stored_enabled && $wanted_targets === $stored_targets;
        }

        if ($name === 'ash_options') {
            if (!is_array($stored) || !is_array($wanted)) {
                return false;
            }
            $check = array(
                'security_profile',
                'content_security_policy',
                'x_xss_protection',
                'restrict_rest_api',
            );
            foreach ($check as $key) {
                if (!array_key_exists($key, $wanted)) {
                    continue;
                }
                $wanted_value = (string) $wanted[$key];
                $stored_value = array_key_exists($key, $stored) ? (string) $stored[$key] : '';
                if ($wanted_value !== $stored_value) {
                    return false;
                }
            }
            return true;
        }

        return is_array($stored);
    }

    /**
     * @param array $snapshots Option name => previous value or false.
     * @return void
     */
    private static function restore_snapshots($snapshots) {
        foreach ($snapshots as $name => $value) {
            if ($value === false) {
                delete_option($name);
                continue;
            }
            update_option($name, $value);
        }
    }
}
