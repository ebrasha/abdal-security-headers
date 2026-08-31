<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-feature-settings.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-31 21:15:30
 * Description : Shared allowlists, sanitization, and defaults for WordPress hardening features
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

class ASH_Feature_Settings {
    const MAX_LIST_ITEMS = 40;
    const MAX_METHOD_LENGTH = 80;
    const MAX_NAMESPACE_LENGTH = 80;
    const MAX_ROUTE_LENGTH = 200;
    const MAX_LOGIN_MESSAGE = 200;
    const MAX_CAPABILITY_LENGTH = 64;

    /**
     * XML-RPC pingback methods blocked in pingback mode.
     *
     * @return array
     */
    public static function pingback_methods() {
        return array(
            'pingback.ping',
            'pingback.extensions.getPingbacks',
        );
    }

    /**
     * Login error modes.
     *
     * @return array
     */
    public static function login_error_modes() {
        return array(
            'generic',
            'hide',
            'custom',
        );
    }

    /**
     * XML-RPC protection modes.
     *
     * @return array
     */
    public static function xmlrpc_modes() {
        return array(
            'auth',
            'pingback',
            'all',
            'custom',
        );
    }

    /**
     * REST access policies for the main controller.
     *
     * @return array
     */
    public static function rest_access_policies() {
        return array(
            'wordpress',
            'authenticated',
            'roles',
            'capability',
            'administrators',
            'block_all',
        );
    }

    /**
     * REST access policies for user endpoints.
     *
     * @return array
     */
    public static function rest_users_policies() {
        return array(
            'wordpress',
            'authenticated',
            'capability',
            'administrators',
        );
    }

    /**
     * Defaults merged on activation for missing feature-config keys only.
     *
     * @param mixed $existing Current ash_options value.
     * @return array
     */
    public static function activation_defaults($existing) {
        $existing = is_array($existing) ? $existing : array();
        $is_existing = array_key_exists('hide_wp_version', $existing);
        $hide_version = $is_existing && isset($existing['hide_wp_version']) && (string) $existing['hide_wp_version'] === '1';
        $xmlrpc_on = $is_existing && isset($existing['disable_xmlrpc']) && (string) $existing['disable_xmlrpc'] === '1';
        $rest_on = $is_existing && isset($existing['restrict_rest_api']) && (string) $existing['restrict_rest_api'] === '1';

        return array(
            'hide_generator_meta' => $hide_version || !$is_existing ? '1' : '0',
            'hide_version_feeds' => $hide_version || !$is_existing ? '1' : '0',
            'login_error_mode' => 'generic',
            'login_error_custom' => '',
            'xmlrpc_mode' => $xmlrpc_on ? 'all' : 'auth',
            'xmlrpc_allow_methods' => array(),
            'xmlrpc_block_methods' => array(),
            'rest_access_policy' => $rest_on ? 'block_all' : 'authenticated',
            'rest_roles' => array(),
            'rest_capability' => 'edit_posts',
            'rest_allow_namespaces' => array(),
            'rest_allow_routes' => array(),
            'rest_deny_namespaces' => array(),
            'rest_deny_routes' => array(),
            'rest_users_restrict' => '0',
            'rest_users_policy' => 'authenticated',
            'rest_users_capability' => 'list_users',
        );
    }

    /**
     * Fill missing feature-config keys in memory without writing the database.
     *
     * @param mixed $options Stored ash_options.
     * @return array
     */
    public static function hydrate($options) {
        if (!is_array($options)) {
            $options = array();
        }

        $hide_version = isset($options['hide_wp_version']) && (string) $options['hide_wp_version'] === '1';
        $xmlrpc_on = isset($options['disable_xmlrpc']) && (string) $options['disable_xmlrpc'] === '1';
        $rest_on = isset($options['restrict_rest_api']) && (string) $options['restrict_rest_api'] === '1';
        $legacy_xmlrpc = $xmlrpc_on && !array_key_exists('xmlrpc_mode', $options);
        $legacy_rest = $rest_on && !array_key_exists('rest_access_policy', $options);

        if (!isset($options['hide_generator_meta'])) {
            $options['hide_generator_meta'] = $hide_version ? '1' : '0';
        } else {
            $options['hide_generator_meta'] = ((string) $options['hide_generator_meta'] === '1') ? '1' : '0';
        }

        if (!isset($options['hide_version_feeds'])) {
            $options['hide_version_feeds'] = $hide_version ? '1' : '0';
        } else {
            $options['hide_version_feeds'] = ((string) $options['hide_version_feeds'] === '1') ? '1' : '0';
        }

        $login_mode = isset($options['login_error_mode']) ? (string) $options['login_error_mode'] : 'generic';
        $options['login_error_mode'] = in_array($login_mode, self::login_error_modes(), true) ? $login_mode : 'generic';
        $options['login_error_custom'] = isset($options['login_error_custom'])
            ? self::sanitize_login_message($options['login_error_custom'])
            : '';

        $xmlrpc_mode = isset($options['xmlrpc_mode']) ? (string) $options['xmlrpc_mode'] : '';
        if (!in_array($xmlrpc_mode, self::xmlrpc_modes(), true)) {
            $options['xmlrpc_mode'] = $legacy_xmlrpc ? 'all' : 'auth';
        }

        $options['xmlrpc_allow_methods'] = self::sanitize_method_list(isset($options['xmlrpc_allow_methods']) ? $options['xmlrpc_allow_methods'] : array());
        $options['xmlrpc_block_methods'] = self::sanitize_method_list(isset($options['xmlrpc_block_methods']) ? $options['xmlrpc_block_methods'] : array());

        $rest_policy = isset($options['rest_access_policy']) ? (string) $options['rest_access_policy'] : '';
        if (!in_array($rest_policy, self::rest_access_policies(), true)) {
            $options['rest_access_policy'] = $legacy_rest ? 'block_all' : 'authenticated';
        }

        $options['rest_roles'] = self::sanitize_role_list(isset($options['rest_roles']) ? $options['rest_roles'] : array());
        $options['rest_capability'] = self::sanitize_capability(isset($options['rest_capability']) ? $options['rest_capability'] : 'edit_posts', 'edit_posts');
        $options['rest_allow_namespaces'] = self::sanitize_namespace_list(isset($options['rest_allow_namespaces']) ? $options['rest_allow_namespaces'] : array());
        $options['rest_allow_routes'] = self::sanitize_route_list(isset($options['rest_allow_routes']) ? $options['rest_allow_routes'] : array());
        $options['rest_deny_namespaces'] = self::sanitize_namespace_list(isset($options['rest_deny_namespaces']) ? $options['rest_deny_namespaces'] : array());
        $options['rest_deny_routes'] = self::sanitize_route_list(isset($options['rest_deny_routes']) ? $options['rest_deny_routes'] : array());
        $options['rest_users_restrict'] = (isset($options['rest_users_restrict']) && (string) $options['rest_users_restrict'] === '1') ? '1' : '0';

        $users_policy = isset($options['rest_users_policy']) ? (string) $options['rest_users_policy'] : 'authenticated';
        $options['rest_users_policy'] = in_array($users_policy, self::rest_users_policies(), true) ? $users_policy : 'authenticated';
        $options['rest_users_capability'] = self::sanitize_capability(isset($options['rest_users_capability']) ? $options['rest_users_capability'] : 'list_users', 'list_users');

        return $options;
    }

    /**
     * Sanitize feature-screen fields. Enable flags are already merged.
     *
     * @param array $input Submitted ash_options slice.
     * @param array $sanitized Options being saved.
     * @return array
     */
    public static function sanitize_features_input($input, $sanitized) {
        if (!is_array($input)) {
            $input = array();
        }
        if (!is_array($sanitized)) {
            $sanitized = array();
        }

        $sanitized['hide_generator_meta'] = (isset($input['hide_generator_meta']) && (string) $input['hide_generator_meta'] === '1') ? '1' : '0';
        $sanitized['hide_version_feeds'] = (isset($input['hide_version_feeds']) && (string) $input['hide_version_feeds'] === '1') ? '1' : '0';

        $login_mode = isset($input['login_error_mode']) ? (string) $input['login_error_mode'] : 'generic';
        $sanitized['login_error_mode'] = in_array($login_mode, self::login_error_modes(), true) ? $login_mode : 'generic';
        $sanitized['login_error_custom'] = isset($input['login_error_custom'])
            ? self::sanitize_login_message($input['login_error_custom'])
            : '';

        $xmlrpc_mode = isset($input['xmlrpc_mode']) ? (string) $input['xmlrpc_mode'] : 'auth';
        $sanitized['xmlrpc_mode'] = in_array($xmlrpc_mode, self::xmlrpc_modes(), true) ? $xmlrpc_mode : 'auth';
        $sanitized['xmlrpc_allow_methods'] = self::sanitize_method_list(isset($input['xmlrpc_allow_methods']) ? $input['xmlrpc_allow_methods'] : array());
        $sanitized['xmlrpc_block_methods'] = self::sanitize_method_list(isset($input['xmlrpc_block_methods']) ? $input['xmlrpc_block_methods'] : array());

        $rest_policy = isset($input['rest_access_policy']) ? (string) $input['rest_access_policy'] : 'authenticated';
        $sanitized['rest_access_policy'] = in_array($rest_policy, self::rest_access_policies(), true) ? $rest_policy : 'authenticated';
        $sanitized['rest_roles'] = self::sanitize_role_list(isset($input['rest_roles']) ? $input['rest_roles'] : array());
        $sanitized['rest_capability'] = self::sanitize_capability(isset($input['rest_capability']) ? $input['rest_capability'] : 'edit_posts', 'edit_posts');
        $sanitized['rest_allow_namespaces'] = self::sanitize_namespace_list(isset($input['rest_allow_namespaces']) ? $input['rest_allow_namespaces'] : array());
        $sanitized['rest_allow_routes'] = self::sanitize_route_list(isset($input['rest_allow_routes']) ? $input['rest_allow_routes'] : array());
        $sanitized['rest_deny_namespaces'] = self::sanitize_namespace_list(isset($input['rest_deny_namespaces']) ? $input['rest_deny_namespaces'] : array());
        $sanitized['rest_deny_routes'] = self::sanitize_route_list(isset($input['rest_deny_routes']) ? $input['rest_deny_routes'] : array());
        $sanitized['rest_users_restrict'] = (isset($input['rest_users_restrict']) && (string) $input['rest_users_restrict'] === '1') ? '1' : '0';

        $users_policy = isset($input['rest_users_policy']) ? (string) $input['rest_users_policy'] : 'authenticated';
        $sanitized['rest_users_policy'] = in_array($users_policy, self::rest_users_policies(), true) ? $users_policy : 'authenticated';
        $sanitized['rest_users_capability'] = self::sanitize_capability(isset($input['rest_users_capability']) ? $input['rest_users_capability'] : 'list_users', 'list_users');

        return $sanitized;
    }

    /**
     * Default generic login failure message (plain text, translated at output).
     *
     * @return string
     */
    public static function default_login_error_message() {
        return __('Invalid username or password.', 'abdal-security-headers');
    }

    /**
     * @param mixed $value Raw message.
     * @return string
     */
    public static function sanitize_login_message($value) {
        $value = sanitize_text_field((string) $value);
        if (strlen($value) > self::MAX_LOGIN_MESSAGE) {
            $value = substr($value, 0, self::MAX_LOGIN_MESSAGE);
        }
        return $value;
    }

    /**
     * @param mixed  $value    Raw capability.
     * @param string $fallback Fallback capability.
     * @return string
     */
    public static function sanitize_capability($value, $fallback = 'read') {
        $cap = sanitize_key((string) $value);
        if ($cap === '' || strlen($cap) > self::MAX_CAPABILITY_LENGTH) {
            $fallback = sanitize_key($fallback);
            return $fallback !== '' ? $fallback : 'read';
        }
        return $cap;
    }

    /**
     * @param mixed $raw Role slugs.
     * @return array
     */
    public static function sanitize_role_list($raw) {
        $lines = self::as_lines($raw);
        $known = array();
        if (function_exists('wp_roles')) {
            $roles = wp_roles();
            if (is_object($roles) && isset($roles->roles) && is_array($roles->roles)) {
                $known = $roles->roles;
            }
        }

        $out = array();
        foreach ($lines as $line) {
            if (count($out) >= self::MAX_LIST_ITEMS) {
                break;
            }
            $slug = sanitize_key($line);
            if ($slug === '' || isset($out[$slug])) {
                continue;
            }
            if (!empty($known) && !isset($known[$slug])) {
                continue;
            }
            $out[$slug] = $slug;
        }

        return array_values($out);
    }

    /**
     * @param mixed $raw Method names.
     * @return array
     */
    public static function sanitize_method_list($raw) {
        $lines = self::as_lines($raw);
        $out = array();
        foreach ($lines as $line) {
            if (count($out) >= self::MAX_LIST_ITEMS) {
                break;
            }
            $method = self::sanitize_xmlrpc_method($line);
            if ($method === '' || in_array($method, $out, true)) {
                continue;
            }
            $out[] = $method;
        }
        return $out;
    }

    /**
     * @param mixed $raw Namespace list.
     * @return array
     */
    public static function sanitize_namespace_list($raw) {
        $lines = self::as_lines($raw);
        $out = array();
        foreach ($lines as $line) {
            if (count($out) >= self::MAX_LIST_ITEMS) {
                break;
            }
            $namespace = self::sanitize_rest_namespace($line);
            if ($namespace === '' || in_array($namespace, $out, true)) {
                continue;
            }
            $out[] = $namespace;
        }
        return $out;
    }

    /**
     * @param mixed $raw Route list.
     * @return array
     */
    public static function sanitize_route_list($raw) {
        $lines = self::as_lines($raw);
        $out = array();
        foreach ($lines as $line) {
            if (count($out) >= self::MAX_LIST_ITEMS) {
                break;
            }
            $route = self::sanitize_rest_route($line);
            if ($route === '' || in_array($route, $out, true)) {
                continue;
            }
            $out[] = $route;
        }
        return $out;
    }

    /**
     * @param string $method Candidate XML-RPC method name.
     * @return string
     */
    public static function sanitize_xmlrpc_method($method) {
        $method = trim((string) $method);
        if ($method === '' || strlen($method) > self::MAX_METHOD_LENGTH) {
            return '';
        }
        if (!preg_match('/^[A-Za-z][A-Za-z0-9._]*$/', $method)) {
            return '';
        }
        return $method;
    }

    /**
     * @param string $namespace Candidate REST namespace.
     * @return string
     */
    public static function sanitize_rest_namespace($namespace) {
        $namespace = trim((string) $namespace);
        $namespace = trim($namespace, '/');
        if ($namespace === '' || strlen($namespace) > self::MAX_NAMESPACE_LENGTH) {
            return '';
        }
        if (!preg_match('/^[A-Za-z0-9_]+(?:\/[A-Za-z0-9._-]+)*$/', $namespace)) {
            return '';
        }
        return $namespace;
    }

    /**
     * @param string $route Candidate REST route.
     * @return string
     */
    public static function sanitize_rest_route($route) {
        $route = trim((string) $route);
        if ($route === '') {
            return '';
        }
        $route = '/' . ltrim($route, '/');
        $route = rtrim($route, '/');
        if ($route === '/' || strlen($route) > self::MAX_ROUTE_LENGTH) {
            return $route === '/' ? '' : '';
        }
        if (!preg_match('/^\/[A-Za-z0-9\/_\-{}.,]+$/', $route)) {
            return '';
        }
        return $route;
    }

    /**
     * Whether a REST route belongs to a namespace.
     *
     * @param string $route     Request route.
     * @param string $namespace Namespace such as wp/v2.
     * @return bool
     */
    public static function route_in_namespace($route, $namespace) {
        $route = '/' . ltrim((string) $route, '/');
        $namespace = trim((string) $namespace, '/');
        if ($namespace === '') {
            return false;
        }
        $prefix = '/' . $namespace;
        return $route === $prefix || strpos($route, $prefix . '/') === 0;
    }

    /**
     * Whether a REST route matches an allowed/blocked route pattern.
     *
     * @param string $route   Request route.
     * @param string $pattern Stored route.
     * @return bool
     */
    public static function route_matches($route, $pattern) {
        $route = '/' . ltrim((string) $route, '/');
        $pattern = '/' . ltrim((string) $pattern, '/');
        $pattern = rtrim($pattern, '/');
        if ($pattern === '' || $pattern === '/') {
            return false;
        }
        return $route === $pattern || strpos($route, $pattern . '/') === 0;
    }

    /**
     * Whether a REST route is a core users endpoint.
     *
     * @param string $route Request route.
     * @return bool
     */
    public static function is_users_rest_route($route) {
        $route = '/' . ltrim((string) $route, '/');
        return $route === '/wp/v2/users' || strpos($route, '/wp/v2/users/') === 0;
    }

    /**
     * @param mixed $raw Textarea string or array.
     * @return array
     */
    private static function as_lines($raw) {
        if (is_string($raw)) {
            $parts = preg_split('/\r\n|\r|\n/', $raw);
            return is_array($parts) ? $parts : array();
        }
        if (is_array($raw)) {
            return $raw;
        }
        return array();
    }
}
