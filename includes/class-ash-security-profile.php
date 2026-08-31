<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-security-profile.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-31 21:55:09
 * Description : Security Profile values, fingerprinting, and atomic apply for headers and features
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

class ASH_Security_Profile {
    const OPTION_KEY = 'security_profile';

    /**
     * Named profiles plus Manual.
     *
     * @return array
     */
    public static function ids() {
        return array(
            'compatibility',
            'recommended',
            'hardened',
            'manual',
        );
    }

    /**
     * Profiles that write header and feature values.
     *
     * @return array
     */
    public static function named_ids() {
        return array(
            'compatibility',
            'recommended',
            'hardened',
        );
    }

    /**
     * UI catalog. Manual never changes configuration by itself.
     *
     * @return array
     */
    public static function catalog() {
        return array(
            'compatibility' => array(
                'label' => __('Compatibility', 'abdal-security-headers'),
                'description' => __('Conservative settings with the lowest risk of breaking WordPress, themes, and plugins.', 'abdal-security-headers'),
                'hint' => __('REST API and XML-RPC stay available. Strict headers such as HSTS Preload are left off.', 'abdal-security-headers'),
            ),
            'recommended' => array(
                'label' => __('Recommended', 'abdal-security-headers'),
                'description' => __('Balanced security for most WordPress sites. Gutenberg and Site Health keep REST access for signed-in users.', 'abdal-security-headers'),
                'hint' => __('This is the suggested profile for typical WordPress sites.', 'abdal-security-headers'),
            ),
            'hardened' => array(
                'label' => __('Hardened', 'abdal-security-headers'),
                'description' => __('Strict security settings. Some integrations, embeds, or WordPress tools may need extra review.', 'abdal-security-headers'),
                'hint' => __('Applying this profile can affect compatibility with themes, plugins, and XML-RPC clients.', 'abdal-security-headers'),
            ),
            'manual' => array(
                'label' => __('Manual', 'abdal-security-headers'),
                'description' => __('Do not change any Security Headers or Security Features automatically. You manage every setting.', 'abdal-security-headers'),
                'hint' => __('Manual never overwrites configuration. It is also used when saved settings no longer match a profile.', 'abdal-security-headers'),
            ),
        );
    }

    /**
     * @param mixed $value Candidate profile id.
     * @return string
     */
    public static function sanitize_id($value) {
        $id = sanitize_key((string) $value);
        return in_array($id, self::ids(), true) ? $id : 'manual';
    }

    /**
     * Hydrate options used by profiles without writing the database.
     *
     * @param mixed $options Stored ash_options.
     * @return array
     */
    public static function hydrate($options) {
        if (!is_array($options)) {
            $options = array();
        }
        if (class_exists('ASH_Header_Settings')) {
            $options = ASH_Header_Settings::hydrate($options);
        }
        if (class_exists('ASH_Feature_Settings')) {
            $options = ASH_Feature_Settings::hydrate($options);
        }

        $options[self::OPTION_KEY] = self::sanitize_id(isset($options[self::OPTION_KEY]) ? $options[self::OPTION_KEY] : 'manual');

        return $options;
    }

    /**
     * Stored profile id after hydrate.
     *
     * @param array $options Hydrated options.
     * @return string
     */
    public static function stored_id($options) {
        $options = self::hydrate($options);
        return $options[self::OPTION_KEY];
    }

    /**
     * Effective profile: Manual when a named profile no longer matches.
     *
     * @param array $options Hydrated or raw options.
     * @return string
     */
    public static function effective_id($options) {
        $options = self::hydrate($options);
        $stored = $options[self::OPTION_KEY];
        if ($stored === 'manual') {
            return 'manual';
        }
        if (!self::matches($stored, $options)) {
            return 'manual';
        }
        return $stored;
    }

    /**
     * Whether current header/feature values match a named profile.
     *
     * @param string $id      Profile id.
     * @param array  $options Options.
     * @return bool
     */
    public static function matches($id, $options) {
        $id = self::sanitize_id($id);
        if ($id === 'manual' || !in_array($id, self::named_ids(), true)) {
            return false;
        }

        $current = self::fingerprint($options);
        $expected = self::fingerprint(self::materialize($id));
        return $current !== '' && $expected !== '' && hash_equals($expected, $current);
    }

    /**
     * Apply a profile atomically. CSP keys are never written.
     *
     * @param string $id Profile id.
     * @return array|\WP_Error
     */
    public static function apply($id) {
        $id = self::sanitize_id($id);
        $existing = get_option('ash_options', array());
        if (!is_array($existing)) {
            $existing = array();
        }

        if ($id === 'manual') {
            $next = $existing;
            $next[self::OPTION_KEY] = 'manual';
            return self::commit($existing, $next);
        }

        if (!class_exists('ASH_Header_Settings') || !class_exists('ASH_Feature_Settings')) {
            return new WP_Error(
                'ash_profile_unavailable',
                __('Security Profile cannot be applied because required settings classes are missing.', 'abdal-security-headers')
            );
        }

        $values = self::values($id);
        if (empty($values)) {
            return new WP_Error(
                'ash_profile_invalid',
                __('The selected Security Profile is not valid.', 'abdal-security-headers')
            );
        }

        $sanitized = self::merge_profile_values($existing, $values);
        $sanitized[self::OPTION_KEY] = $id;

        foreach ($existing as $key => $value) {
            if ($key === 'content_security_policy' || strpos((string) $key, 'csp_') === 0) {
                $sanitized[$key] = $value;
            }
        }

        if (!self::matches($id, $sanitized)) {
            return new WP_Error(
                'ash_profile_validate',
                __('The Security Profile could not be validated. No settings were saved.', 'abdal-security-headers')
            );
        }

        return self::commit($existing, $sanitized);
    }

    /**
     * After a headers/features save, drop a named profile to Manual on drift.
     *
     * @param array $options Options being stored.
     * @return array
     */
    public static function sync_after_save($options) {
        if (!is_array($options)) {
            return array();
        }

        $stored = self::sanitize_id(isset($options[self::OPTION_KEY]) ? $options[self::OPTION_KEY] : 'manual');
        $options[self::OPTION_KEY] = $stored;
        if ($stored === 'manual') {
            return $options;
        }
        if (!self::matches($stored, $options)) {
            $options[self::OPTION_KEY] = 'manual';
        }

        return $options;
    }

    /**
     * Header enable flags owned by profiles.
     *
     * @return array
     */
    public static function header_flags() {
        return array(
            'x_xss_protection',
            'x_content_type_options',
            'strict_transport_security',
            'permissions_policy',
            'x_frame_options',
            'referrer_policy',
        );
    }

    /**
     * Feature enable flags owned by profiles.
     *
     * @return array
     */
    public static function feature_flags() {
        return array(
            'remove_x_powered_by',
            'hide_wp_version',
            'remove_login_errors',
            'disable_xmlrpc',
            'remove_x_pingback',
            'restrict_rest_api',
        );
    }

    /**
     * Fingerprint of profile-controlled keys only.
     *
     * @param array $options Options.
     * @return string
     */
    public static function fingerprint($options) {
        $canonical = self::canonical($options);
        $json = wp_json_encode($canonical);
        if (!is_string($json) || $json === '') {
            return '';
        }
        return md5($json);
    }

    /**
     * Sanitize profile values onto a base options array. CSP keys on the base are kept.
     *
     * @param array $base   Existing options.
     * @param array $values Profile input for sanitizers.
     * @return array
     */
    private static function merge_profile_values($base, $values) {
        if (!is_array($base)) {
            $base = array();
        }
        if (!is_array($values)) {
            $values = array();
        }

        $sanitized = $base;
        foreach (self::header_flags() as $field) {
            $sanitized[$field] = (isset($values[$field]) && (string) $values[$field] === '1') ? '1' : '0';
        }
        $sanitized = ASH_Header_Settings::sanitize_headers_input($values, $sanitized);

        foreach (self::feature_flags() as $field) {
            $sanitized[$field] = (isset($values[$field]) && (string) $values[$field] === '1') ? '1' : '0';
        }
        $sanitized = ASH_Feature_Settings::sanitize_features_input($values, $sanitized);

        return $sanitized;
    }

    /**
     * Fully sanitized snapshot of a named profile.
     *
     * @param string $id Named profile id.
     * @return array
     */
    private static function materialize($id) {
        return self::merge_profile_values(array(), self::values($id));
    }

    /**
     * Profile-controlled values ready for sanitizers.
     *
     * @param string $id Named profile id.
     * @return array
     */
    public static function values($id) {
        $id = self::sanitize_id($id);
        if ($id === 'compatibility') {
            return self::compatibility_values();
        }
        if ($id === 'recommended') {
            return self::recommended_values();
        }
        if ($id === 'hardened') {
            return self::hardened_values();
        }
        return array();
    }

    /**
     * @param array $before Previous option array.
     * @param array $after  Candidate option array.
     * @return array|\WP_Error
     */
    private static function commit($before, $after) {
        $updated = update_option('ash_options', $after);
        $stored = get_option('ash_options', array());
        if (!is_array($stored)) {
            $stored = array();
        }

        $stored_profile = self::sanitize_id(isset($stored[self::OPTION_KEY]) ? $stored[self::OPTION_KEY] : '');
        $wanted_profile = self::sanitize_id(isset($after[self::OPTION_KEY]) ? $after[self::OPTION_KEY] : '');
        $profile_ok = $stored_profile === $wanted_profile;
        $values_ok = ($wanted_profile === 'manual') || self::matches($wanted_profile, $stored);

        if (!$profile_ok || !$values_ok) {
            if (is_array($before)) {
                update_option('ash_options', $before);
            }
            return new WP_Error(
                'ash_profile_commit',
                __('The Security Profile could not be saved completely. Previous settings were kept.', 'abdal-security-headers')
            );
        }

        unset($updated);
        if (class_exists('ASH_Security_Status')) {
            delete_transient(ASH_Security_Status::PROBE_TRANSIENT);
        }
        return $stored;
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function canonical($options) {
        $options = self::hydrate($options);
        $slice = array();
        foreach (self::controlled_keys() as $key) {
            $slice[$key] = isset($options[$key]) ? $options[$key] : null;
        }
        return self::normalize($slice);
    }

    /**
     * @return array
     */
    private static function controlled_keys() {
        return array(
            'x_xss_protection',
            'xss_policy',
            'xss_report_url',
            'x_content_type_options',
            'strict_transport_security',
            'hsts_max_age',
            'hsts_include_subdomains',
            'hsts_preload',
            'permissions_policy',
            'pp_directives',
            'pp_custom',
            'x_frame_options',
            'x_frame_options_policy',
            'referrer_policy',
            'referrer_policy_value',
            'remove_x_powered_by',
            'hide_wp_version',
            'hide_generator_meta',
            'hide_version_feeds',
            'remove_login_errors',
            'login_error_mode',
            'login_error_custom',
            'disable_xmlrpc',
            'xmlrpc_mode',
            'xmlrpc_allow_methods',
            'xmlrpc_block_methods',
            'remove_x_pingback',
            'restrict_rest_api',
            'rest_access_policy',
            'rest_roles',
            'rest_capability',
            'rest_allow_namespaces',
            'rest_allow_routes',
            'rest_deny_namespaces',
            'rest_deny_routes',
            'rest_users_restrict',
            'rest_users_policy',
            'rest_users_capability',
        );
    }

    /**
     * @param mixed $value Canonical value.
     * @return mixed
     */
    private static function normalize($value) {
        if (is_array($value)) {
            $is_list = self::is_list($value);
            $out = array();
            foreach ($value as $key => $item) {
                $out[$key] = self::normalize($item);
            }
            if (!$is_list) {
                ksort($out);
            }
            return $out;
        }
        if (is_bool($value)) {
            return $value ? '1' : '0';
        }
        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }
        if ($value === null) {
            return '';
        }
        return (string) $value;
    }

    /**
     * @param array $value Array.
     * @return bool
     */
    private static function is_list($value) {
        if ($value === array()) {
            return true;
        }
        return array_keys($value) === range(0, count($value) - 1);
    }

    /**
     * @return array
     */
    private static function compatibility_values() {
        return array_merge(
            self::shared_feature_lists(),
            array(
                'x_xss_protection' => '0',
                'xss_policy' => '0',
                'xss_report_url' => '',
                'x_content_type_options' => '1',
                'strict_transport_security' => '0',
                'hsts_max_age_preset' => '31536000',
                'hsts_include_subdomains' => '0',
                'hsts_preload' => '0',
                'permissions_policy' => '0',
                'pp_directives' => self::pp_unset(),
                'pp_custom' => array(),
                'x_frame_options' => '1',
                'x_frame_options_policy' => 'SAMEORIGIN',
                'referrer_policy' => '1',
                'referrer_policy_value' => 'strict-origin-when-cross-origin',
                'remove_x_powered_by' => '1',
                'hide_wp_version' => '1',
                'hide_generator_meta' => '1',
                'hide_version_feeds' => '1',
                'remove_login_errors' => '1',
                'login_error_mode' => 'generic',
                'login_error_custom' => '',
                'disable_xmlrpc' => '0',
                'xmlrpc_mode' => 'auth',
                'remove_x_pingback' => '1',
                'restrict_rest_api' => '0',
                'rest_access_policy' => 'authenticated',
                'rest_users_restrict' => '0',
                'rest_users_policy' => 'authenticated',
            )
        );
    }

    /**
     * @return array
     */
    private static function recommended_values() {
        $pp = class_exists('ASH_Header_Settings')
            ? ASH_Header_Settings::default_pp_directives(true)
            : self::pp_unset();

        return array_merge(
            self::shared_feature_lists(),
            array(
                'x_xss_protection' => '0',
                'xss_policy' => '0',
                'xss_report_url' => '',
                'x_content_type_options' => '1',
                'strict_transport_security' => '1',
                'hsts_max_age_preset' => '31536000',
                'hsts_include_subdomains' => '0',
                'hsts_preload' => '0',
                'permissions_policy' => '1',
                'pp_directives' => $pp,
                'pp_custom' => array(),
                'x_frame_options' => '1',
                'x_frame_options_policy' => 'SAMEORIGIN',
                'referrer_policy' => '1',
                'referrer_policy_value' => 'strict-origin-when-cross-origin',
                'remove_x_powered_by' => '1',
                'hide_wp_version' => '1',
                'hide_generator_meta' => '1',
                'hide_version_feeds' => '1',
                'remove_login_errors' => '1',
                'login_error_mode' => 'generic',
                'login_error_custom' => '',
                'disable_xmlrpc' => '1',
                'xmlrpc_mode' => 'auth',
                'remove_x_pingback' => '1',
                'restrict_rest_api' => '0',
                'rest_access_policy' => 'authenticated',
                'rest_users_restrict' => '1',
                'rest_users_policy' => 'authenticated',
            )
        );
    }

    /**
     * @return array
     */
    private static function hardened_values() {
        return array_merge(
            self::shared_feature_lists(),
            array(
                'x_xss_protection' => '0',
                'xss_policy' => '0',
                'xss_report_url' => '',
                'x_content_type_options' => '1',
                'strict_transport_security' => '1',
                'hsts_max_age_preset' => '63072000',
                'hsts_include_subdomains' => '1',
                'hsts_preload' => '1',
                'permissions_policy' => '1',
                'pp_directives' => self::pp_all_deny(),
                'pp_custom' => array(),
                'x_frame_options' => '1',
                'x_frame_options_policy' => 'DENY',
                'referrer_policy' => '1',
                'referrer_policy_value' => 'strict-origin',
                'remove_x_powered_by' => '1',
                'hide_wp_version' => '1',
                'hide_generator_meta' => '1',
                'hide_version_feeds' => '1',
                'remove_login_errors' => '1',
                'login_error_mode' => 'generic',
                'login_error_custom' => '',
                'disable_xmlrpc' => '1',
                'xmlrpc_mode' => 'all',
                'remove_x_pingback' => '1',
                'restrict_rest_api' => '1',
                'rest_access_policy' => 'authenticated',
                'rest_users_restrict' => '1',
                'rest_users_policy' => 'administrators',
            )
        );
    }

    /**
     * Lists shared by every named profile. REST is never Block All.
     *
     * @return array
     */
    private static function shared_feature_lists() {
        return array(
            'xmlrpc_allow_methods' => array(),
            'xmlrpc_block_methods' => array(),
            'rest_roles' => array(),
            'rest_capability' => 'edit_posts',
            'rest_allow_namespaces' => array(),
            'rest_allow_routes' => array(),
            'rest_deny_namespaces' => array(),
            'rest_deny_routes' => array(),
            'rest_users_capability' => 'list_users',
        );
    }

    /**
     * @return array
     */
    private static function pp_unset() {
        $directives = array();
        $names = class_exists('ASH_Header_Settings') ? ASH_Header_Settings::directive_names() : array();
        foreach ($names as $name) {
            $directives[$name] = array(
                'enabled' => '0',
                'policy' => 'not_set',
                'origins' => array(),
            );
        }
        return $directives;
    }

    /**
     * @return array
     */
    private static function pp_all_deny() {
        $directives = array();
        $names = class_exists('ASH_Header_Settings') ? ASH_Header_Settings::directive_names() : array();
        foreach ($names as $name) {
            $directives[$name] = array(
                'enabled' => '1',
                'policy' => 'deny',
                'origins' => array(),
            );
        }
        return $directives;
    }
}
