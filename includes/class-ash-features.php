<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-features.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-31 21:15:30
 * Description : Applies WordPress hardening features for version disclosure, XML-RPC, REST, and login errors
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

class ASH_Features {
    private $options;

    public function __construct() {
        $this->options = get_option('ash_options', array());
        if (!is_array($this->options)) {
            $this->options = array();
        }
        if (class_exists('ASH_Feature_Settings')) {
            $this->options = ASH_Feature_Settings::hydrate($this->options);
        }

        if ($this->flag('remove_x_powered_by')) {
            add_action('init', array($this, 'remove_x_powered_by'));
            add_action('send_headers', array($this, 'remove_x_powered_by_header'), 2);
        }

        if ($this->flag('hide_wp_version')) {
            add_action('init', array($this, 'hide_wp_version'));
        }

        if ($this->flag('remove_login_errors')) {
            add_filter('wp_login_errors', array($this, 'filter_login_errors'), 10, 2);
        }

        if ($this->flag('disable_xmlrpc')) {
            $mode = $this->xmlrpc_mode();
            if ($mode === 'auth' || $mode === 'all') {
                add_filter('xmlrpc_enabled', '__return_false');
            }
            add_filter('xmlrpc_methods', array($this, 'filter_xmlrpc_methods'), 999);
            if ($mode === 'all') {
                add_action('init', array($this, 'block_xmlrpc_file'), 0);
            }
        }

        if ($this->flag('remove_x_pingback')) {
            add_filter('wp_headers', array($this, 'remove_x_pingback'));
        }

        if ($this->flag('restrict_rest_api') || $this->flag('rest_users_restrict')) {
            add_filter('rest_pre_dispatch', array($this, 'filter_rest_pre_dispatch'), 10, 3);
        }

        if ($this->flag('restrict_rest_api') && $this->rest_policy() !== 'wordpress') {
            add_action('after_setup_theme', array($this, 'remove_rest_discovery'));
        }
    }

    /**
     * Turn off PHP expose_php when possible.
     *
     * @return void
     */
    public function remove_x_powered_by() {
        if (function_exists('ini_set')) {
            ini_set('expose_php', 'Off');
        }
        $this->remove_x_powered_by_header();
    }

    /**
     * Strip the X-Powered-By response header.
     *
     * @return void
     */
    public function remove_x_powered_by_header() {
        if (function_exists('header_remove') && !headers_sent()) {
            header_remove('X-Powered-By');
        }
    }

    /**
     * Hide generator output according to the selected switches.
     *
     * Version query arguments on scripts and styles are left intact for cache busting.
     *
     * @return void
     */
    public function hide_wp_version() {
        if ($this->flag('hide_generator_meta')) {
            remove_action('wp_head', 'wp_generator');
        }
        add_filter('the_generator', array($this, 'filter_the_generator'), 10, 2);
    }

    /**
     * Filter generator markup by output type.
     *
     * @param string $generator Current generator markup.
     * @param string $type      Generator type.
     * @return string
     */
    public function filter_the_generator($generator, $type = '') {
        $type = (string) $type;
        if ($this->flag('hide_generator_meta') && in_array($type, array('html', 'xhtml', 'comment', 'export'), true)) {
            return '';
        }
        if ($this->flag('hide_version_feeds') && in_array($type, array('rss', 'rss2', 'atom', 'rdf'), true)) {
            return '';
        }
        return $generator;
    }

    /**
     * Replace or remove authentication failure messages only.
     *
     * @param WP_Error $errors       Login errors.
     * @param string   $redirect_to  Unused redirect target.
     * @return WP_Error
     */
    public function filter_login_errors($errors, $redirect_to = '') {
        unset($redirect_to);
        if (!$errors instanceof WP_Error) {
            return $errors;
        }

        $codes = array(
            'incorrect_password',
            'invalid_username',
            'invalid_email',
            'invalidcombo',
            'authentication_failed',
        );
        $replacement = $this->login_error_replacement();

        foreach ($codes as $code) {
            if ($errors->get_error_message($code) === '') {
                continue;
            }
            $errors->remove($code);
            if ($replacement !== '') {
                $errors->add($code, $replacement);
            }
        }

        return $errors;
    }

    /**
     * Filter the XML-RPC method map.
     *
     * @param array $methods Registered methods.
     * @return array
     */
    public function filter_xmlrpc_methods($methods) {
        if (!is_array($methods)) {
            return array();
        }

        $mode = $this->xmlrpc_mode();
        if ($mode === 'all') {
            return array();
        }

        if ($mode === 'pingback') {
            foreach (ASH_Feature_Settings::pingback_methods() as $method) {
                unset($methods[$method]);
            }
            return $methods;
        }

        if ($mode === 'custom') {
            $allowed = isset($this->options['xmlrpc_allow_methods']) && is_array($this->options['xmlrpc_allow_methods'])
                ? $this->options['xmlrpc_allow_methods']
                : array();
            $blocked = isset($this->options['xmlrpc_block_methods']) && is_array($this->options['xmlrpc_block_methods'])
                ? $this->options['xmlrpc_block_methods']
                : array();

            if (!empty($allowed)) {
                $keep = array();
                foreach ($allowed as $name) {
                    if (isset($methods[$name])) {
                        $keep[$name] = $methods[$name];
                    }
                }
                $methods = $keep;
            }

            foreach ($blocked as $name) {
                unset($methods[$name]);
            }
        }

        return $methods;
    }

    /**
     * Block direct execution of xmlrpc.php in Disable All mode.
     *
     * @return void
     */
    public function block_xmlrpc_file() {
        $script = '';
        if (isset($_SERVER['SCRIPT_FILENAME'])) {
            $script = basename(str_replace('\\', '/', wp_unslash((string) $_SERVER['SCRIPT_FILENAME'])));
        } elseif (isset($_SERVER['SCRIPT_NAME'])) {
            $script = basename(str_replace('\\', '/', wp_unslash((string) $_SERVER['SCRIPT_NAME'])));
        }
        if ($script !== 'xmlrpc.php') {
            return;
        }

        status_header(403);
        nocache_headers();
        wp_die(
            esc_html__('XML-RPC is disabled.', 'abdal-security-headers'),
            '',
            array(
                'response' => 403,
            )
        );
    }

    /**
     * Remove the X-Pingback header from the WordPress header map.
     *
     * @param array $headers Header map.
     * @return array
     */
    public function remove_x_pingback($headers) {
        if (!is_array($headers)) {
            return array();
        }
        unset($headers['X-Pingback']);
        return $headers;
    }

    /**
     * Enforce REST access policy before a request is dispatched.
     *
     * @param mixed           $result Dispatch result.
     * @param WP_REST_Server  $server REST server.
     * @param WP_REST_Request $request Request.
     * @return mixed
     */
    public function filter_rest_pre_dispatch($result, $server, $request) {
        unset($server);
        if ($result !== null) {
            return $result;
        }
        if (!$request instanceof WP_REST_Request) {
            return $result;
        }

        $denied = $this->rest_denial($request);
        if ($denied instanceof WP_Error) {
            return $denied;
        }

        return $result;
    }

    /**
     * Remove REST discovery links from the front end when a restriction is active.
     *
     * @return void
     */
    public function remove_rest_discovery() {
        remove_action('wp_head', 'rest_output_link_wp_head');
        remove_action('template_redirect', 'rest_output_link_header', 11);
    }

    /**
     * @param WP_REST_Request $request Request.
     * @return WP_Error|null
     */
    private function rest_denial($request) {
        $route = (string) $request->get_route();
        $is_users = class_exists('ASH_Feature_Settings') && ASH_Feature_Settings::is_users_rest_route($route);
        $main_enabled = $this->flag('restrict_rest_api');
        $users_enabled = $this->flag('rest_users_restrict');

        if ($main_enabled) {
            if ($this->rest_list_match($route, 'rest_deny_routes', 'route') || $this->rest_list_match($route, 'rest_deny_namespaces', 'namespace')) {
                return $this->rest_error(true);
            }

            $allowed = $this->rest_list_match($route, 'rest_allow_routes', 'route')
                || $this->rest_list_match($route, 'rest_allow_namespaces', 'namespace');

            if (!$allowed) {
                $main = $this->evaluate_rest_policy($this->rest_policy(), 'rest_capability', 'rest_roles');
                if ($main instanceof WP_Error) {
                    return $main;
                }
            }
        }

        if ($users_enabled && $is_users) {
            $users = $this->evaluate_rest_policy($this->users_policy(), 'rest_users_capability', '');
            if ($users instanceof WP_Error) {
                return $users;
            }
        }

        return null;
    }

    /**
     * @param string $policy          Policy key.
     * @param string $capability_key  Options key for the capability.
     * @param string $roles_key       Options key for selected roles, or empty.
     * @return true|WP_Error
     */
    private function evaluate_rest_policy($policy, $capability_key, $roles_key) {
        if ($policy === 'wordpress') {
            return true;
        }

        if ($policy === 'block_all') {
            return $this->rest_error(true);
        }

        $logged_in = is_user_logged_in();

        if ($policy === 'authenticated') {
            return $logged_in ? true : $this->rest_error(false);
        }

        if ($policy === 'administrators') {
            if (!$logged_in) {
                return $this->rest_error(false);
            }
            return current_user_can('manage_options') ? true : $this->rest_error(true);
        }

        if ($policy === 'capability') {
            if (!$logged_in) {
                return $this->rest_error(false);
            }
            $cap = isset($this->options[$capability_key]) ? (string) $this->options[$capability_key] : '';
            $cap = class_exists('ASH_Feature_Settings')
                ? ASH_Feature_Settings::sanitize_capability($cap, 'read')
                : 'read';
            return current_user_can($cap) ? true : $this->rest_error(true);
        }

        if ($policy === 'roles') {
            if (!$logged_in) {
                return $this->rest_error(false);
            }
            if (function_exists('is_super_admin') && is_super_admin()) {
                return true;
            }
            $allowed_roles = ($roles_key !== '' && isset($this->options[$roles_key]) && is_array($this->options[$roles_key]))
                ? $this->options[$roles_key]
                : array();
            $user = wp_get_current_user();
            $user_roles = (is_object($user) && isset($user->roles) && is_array($user->roles)) ? $user->roles : array();
            foreach ($user_roles as $role) {
                if (in_array($role, $allowed_roles, true)) {
                    return true;
                }
            }
            return $this->rest_error(true);
        }

        return true;
    }

    /**
     * @param string $route Request route.
     * @param string $key   Options list key.
     * @param string $kind  namespace or route.
     * @return bool
     */
    private function rest_list_match($route, $key, $kind) {
        $items = isset($this->options[$key]) && is_array($this->options[$key]) ? $this->options[$key] : array();
        foreach ($items as $item) {
            if ($kind === 'namespace' && ASH_Feature_Settings::route_in_namespace($route, $item)) {
                return true;
            }
            if ($kind === 'route' && ASH_Feature_Settings::route_matches($route, $item)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param bool $forbidden True for 403, false for 401.
     * @return WP_Error
     */
    private function rest_error($forbidden) {
        if ($forbidden) {
            return new WP_Error(
                'ash_rest_forbidden',
                __('REST API access is not allowed.', 'abdal-security-headers'),
                array('status' => 403)
            );
        }

        return new WP_Error(
            'ash_rest_unauthorized',
            __('Authentication is required to access the REST API.', 'abdal-security-headers'),
            array('status' => 401)
        );
    }

    /**
     * @return string
     */
    private function login_error_replacement() {
        $mode = isset($this->options['login_error_mode']) ? (string) $this->options['login_error_mode'] : 'generic';
        if ($mode === 'hide') {
            return '';
        }
        if ($mode === 'custom') {
            $custom = isset($this->options['login_error_custom']) ? (string) $this->options['login_error_custom'] : '';
            $custom = class_exists('ASH_Feature_Settings')
                ? ASH_Feature_Settings::sanitize_login_message($custom)
                : sanitize_text_field($custom);
            if ($custom !== '') {
                return esc_html($custom);
            }
        }

        $message = class_exists('ASH_Feature_Settings')
            ? ASH_Feature_Settings::default_login_error_message()
            : __('Invalid username or password.', 'abdal-security-headers');
        return esc_html($message);
    }

    /**
     * @param string $key Option flag.
     * @return bool
     */
    private function flag($key) {
        return isset($this->options[$key]) && (string) $this->options[$key] === '1';
    }

    /**
     * @return string
     */
    private function xmlrpc_mode() {
        $mode = isset($this->options['xmlrpc_mode']) ? (string) $this->options['xmlrpc_mode'] : 'auth';
        return in_array($mode, ASH_Feature_Settings::xmlrpc_modes(), true) ? $mode : 'auth';
    }

    /**
     * @return string
     */
    private function rest_policy() {
        $policy = isset($this->options['rest_access_policy']) ? (string) $this->options['rest_access_policy'] : 'authenticated';
        return in_array($policy, ASH_Feature_Settings::rest_access_policies(), true) ? $policy : 'authenticated';
    }

    /**
     * @return string
     */
    private function users_policy() {
        $policy = isset($this->options['rest_users_policy']) ? (string) $this->options['rest_users_policy'] : 'authenticated';
        return in_array($policy, ASH_Feature_Settings::rest_users_policies(), true) ? $policy : 'authenticated';
    }
}
