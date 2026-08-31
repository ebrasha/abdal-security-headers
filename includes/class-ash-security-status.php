<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-security-status.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-31 21:55:09
 * Description : Calculates live security score, attention items, CSP status, and header conflicts
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

class ASH_Security_Status {
    const PROBE_TRANSIENT = 'ash_header_probe';
    const PROBE_TTL = 300;

    /**
     * Build the dashboard payload from the current site configuration.
     *
     * @param array $raw         Stored ash_options, before or after hydrate.
     * @param bool  $force_probe Bypass the cached public-header probe.
     * @param bool  $allow_probe Whether to probe public response headers.
     * @return array
     */
    public static function payload($raw = null, $force_probe = false, $allow_probe = true) {
        if (!is_array($raw)) {
            $raw = get_option('ash_options', array());
        }
        if (!is_array($raw)) {
            $raw = array();
        }

        $options = class_exists('ASH_Security_Profile')
            ? ASH_Security_Profile::hydrate($raw)
            : $raw;

        $headers = self::header_health($options, $raw);
        $features = self::feature_health($options);
        $csp = self::csp_status($options);
        $conflicts = $allow_probe
            ? self::conflicts($options, $force_probe)
            : array(
                'count' => 0,
                'items' => array(),
            );
        $attention = self::attention_items($options, $raw, $headers, $features, $csp, $conflicts);
        $score = self::security_score($options, $raw, $headers, $features, $conflicts);
        $stored = class_exists('ASH_Security_Profile')
            ? ASH_Security_Profile::stored_id($options)
            : 'manual';
        $effective = class_exists('ASH_Security_Profile')
            ? ASH_Security_Profile::effective_id($options)
            : 'manual';
        $matches = ($stored !== 'manual' && $effective === $stored);
        $catalog = class_exists('ASH_Security_Profile') ? ASH_Security_Profile::catalog() : array();
        $effective_meta = isset($catalog[$effective]) ? $catalog[$effective] : array();
        $stored_meta = isset($catalog[$stored]) ? $catalog[$stored] : array();

        $warning_count = 0;
        foreach ($attention as $item) {
            if (isset($item['tone']) && $item['tone'] === 'warning') {
                $warning_count++;
            }
        }

        $profile_hint = $matches
            ? __('Current settings match the saved Security Profile.', 'abdal-security-headers')
            : __('Current settings do not match the saved profile, so the effective profile is Manual.', 'abdal-security-headers');
        if ($stored === 'manual' && $effective === 'manual') {
            $profile_hint = __('Security Headers and Security Features are managed manually.', 'abdal-security-headers');
        }

        return array(
            'score' => $score['value'],
            'score_tone' => $score['tone'],
            'score_hint' => $score['hint'],
            'csp_score' => $csp['score'],
            'profile' => array(
                'stored' => $stored,
                'stored_label' => isset($stored_meta['label']) ? $stored_meta['label'] : $stored,
                'effective' => $effective,
                'effective_label' => isset($effective_meta['label']) ? $effective_meta['label'] : $effective,
                'matches' => $matches,
                'hint' => $profile_hint,
                'status_text' => trim(
                    sprintf(
                        /* translators: 1: saved profile label, 2: effective profile label */
                        __('Saved profile: %1$s. Effective profile: %2$s.', 'abdal-security-headers'),
                        isset($stored_meta['label']) ? $stored_meta['label'] : $stored,
                        isset($effective_meta['label']) ? $effective_meta['label'] : $effective
                    ) . ' ' . $profile_hint
                ),
            ),
            'headers' => $headers['summary'],
            'features' => $features['summary'],
            'csp' => $csp,
            'attention' => $attention,
            'attention_empty' => __('No configuration issues detected.', 'abdal-security-headers'),
            'conflicts' => $conflicts,
            'summary' => array(
                array(
                    'label' => __('Current Security Profile', 'abdal-security-headers'),
                    'value' => isset($effective_meta['label']) ? $effective_meta['label'] : $effective,
                ),
                array(
                    'label' => __('Security Score', 'abdal-security-headers'),
                    'value' => (string) $score['value'],
                ),
                array(
                    'label' => __('Active Security Headers', 'abdal-security-headers'),
                    'value' => $headers['summary']['active'] . ' / ' . $headers['summary']['total'],
                ),
                array(
                    'label' => __('Active Security Features', 'abdal-security-headers'),
                    'value' => $features['summary']['active'] . ' / ' . $features['summary']['total'],
                ),
                array(
                    'label' => __('CSP Status', 'abdal-security-headers'),
                    'value' => $csp['label'],
                ),
                array(
                    'label' => __('Configuration Warnings', 'abdal-security-headers'),
                    'value' => (string) $warning_count,
                ),
                array(
                    'label' => __('Detected Conflicts', 'abdal-security-headers'),
                    'value' => (string) $conflicts['count'],
                ),
            ),
        );
    }

    /**
     * Persist Manual when a named profile has drifted.
     *
     * @param array $options Options.
     * @return array
     */
    public static function persist_drift($options) {
        if (!class_exists('ASH_Security_Profile')) {
            return is_array($options) ? $options : array();
        }
        $synced = ASH_Security_Profile::sync_after_save($options);
        $before = isset($options['security_profile']) ? (string) $options['security_profile'] : '';
        $after = isset($synced['security_profile']) ? (string) $synced['security_profile'] : '';
        if ($before !== $after) {
            update_option('ash_options', $synced);
        }
        return $synced;
    }

    /**
     * @param array $options Hydrated options.
     * @param array $raw     Raw stored options.
     * @return array
     */
    private static function header_health($options, $raw) {
        $items = array(
            'x_xss_protection' => self::xss_state($options),
            'x_content_type_options' => self::simple_header_state($options, 'x_content_type_options'),
            'strict_transport_security' => self::hsts_state($options, $raw),
            'permissions_policy' => self::pp_state($options),
            'x_frame_options' => self::xfo_state($options),
            'referrer_policy' => self::referrer_state($options),
        );

        $total = count($items);
        $active = 0;
        $attention = 0;
        foreach ($items as $item) {
            if ($item['healthy']) {
                $active++;
            }
            if ($item['attention']) {
                $attention++;
            }
        }

        return array(
            'items' => $items,
            'summary' => array(
                'active' => $active,
                'total' => $total,
                'attention' => $attention,
                'label' => $active . ' / ' . $total,
                'hint' => sprintf(
                    /* translators: 1: healthy headers, 2: total headers, 3: headers needing attention */
                    __('%1$d of %2$d headers are healthy. %3$d require attention.', 'abdal-security-headers'),
                    $active,
                    $total,
                    $attention
                ),
            ),
        );
    }

    /**
     * @param array $options Hydrated options.
     * @return array
     */
    private static function feature_health($options) {
        $items = array(
            'remove_x_powered_by' => self::simple_feature_state($options, 'remove_x_powered_by'),
            'hide_wp_version' => self::hide_version_state($options),
            'remove_login_errors' => self::login_state($options),
            'disable_xmlrpc' => self::xmlrpc_state($options),
            'remove_x_pingback' => self::simple_feature_state($options, 'remove_x_pingback'),
            'restrict_rest_api' => self::rest_state($options),
        );

        $total = count($items);
        $active = 0;
        $attention = 0;
        foreach ($items as $item) {
            if ($item['healthy']) {
                $active++;
            }
            if ($item['attention']) {
                $attention++;
            }
        }

        return array(
            'items' => $items,
            'summary' => array(
                'active' => $active,
                'total' => $total,
                'attention' => $attention,
                'label' => $active . ' / ' . $total,
                'hint' => sprintf(
                    /* translators: 1: healthy features, 2: total features, 3: features needing attention */
                    __('%1$d of %2$d features are healthy. %3$d require attention.', 'abdal-security-headers'),
                    $active,
                    $total,
                    $attention
                ),
            ),
        );
    }

    /**
     * Weighted 0-100 score. CSP is excluded.
     *
     * @param array $options  Hydrated options.
     * @param array $raw      Raw stored options.
     * @param array $headers  Header health.
     * @param array $features Feature health.
     * @param array $conflicts Conflict payload.
     * @return array
     */
    private static function security_score($options, $raw, $headers, $features, $conflicts) {
        $points = 0;

        if (!empty($headers['items']['x_content_type_options']['healthy'])) {
            $points += 10;
        }
        if (!empty($headers['items']['strict_transport_security']['healthy'])) {
            $points += 12;
            if (self::flag($options, 'hsts_include_subdomains')) {
                $points += 1;
            }
            if (self::flag($options, 'hsts_preload')) {
                $points += 1;
            }
        }
        if (!empty($headers['items']['x_frame_options']['healthy'])) {
            $points += 10;
        }
        if (!empty($headers['items']['referrer_policy']['healthy'])) {
            $points += 8;
        }
        if (!empty($headers['items']['permissions_policy']['healthy'])) {
            $points += 8;
        }

        if (!empty($features['items']['hide_wp_version']['healthy'])) {
            $points += 8;
        } elseif (self::flag($options, 'hide_wp_version')) {
            $points += 3;
        }
        if (!empty($features['items']['remove_login_errors']['healthy'])) {
            $points += 7;
        }
        if (self::flag($options, 'disable_xmlrpc')) {
            $mode = isset($options['xmlrpc_mode']) ? (string) $options['xmlrpc_mode'] : 'auth';
            if ($mode === 'all') {
                $points += 8;
            } elseif ($mode === 'custom') {
                $points += empty($features['items']['disable_xmlrpc']['healthy']) ? 1 : 6;
            } else {
                $points += 6;
            }
        }
        if (self::flag($options, 'restrict_rest_api')) {
            $policy = isset($options['rest_access_policy']) ? (string) $options['rest_access_policy'] : 'authenticated';
            if ($policy === 'block_all') {
                $points += 4;
            } elseif ($policy === 'wordpress') {
                $points += 1;
            } elseif ($policy === 'authenticated' || $policy === 'roles' || $policy === 'capability' || $policy === 'administrators') {
                $points += 10;
            }
        }
        if (self::flag($options, 'rest_users_restrict')) {
            $users_policy = isset($options['rest_users_policy']) ? (string) $options['rest_users_policy'] : 'authenticated';
            if ($users_policy !== 'wordpress') {
                $points += 5;
            }
        }
        if (!empty($features['items']['remove_x_powered_by']['healthy'])) {
            $points += 5;
        }
        if (!empty($features['items']['remove_x_pingback']['healthy'])) {
            $points += 5;
        }

        if (self::flag($options, 'x_xss_protection')) {
            $points -= 4;
        }
        if (self::flag($options, 'referrer_policy') && self::option_string($options, 'referrer_policy_value') === 'unsafe-url') {
            $points -= 10;
        }
        if (self::flag($options, 'strict_transport_security') && !self::site_is_https()) {
            $points -= 6;
        }
        if (self::hsts_preload_incomplete_raw($raw)) {
            $points -= 5;
        }
        if (self::flag($options, 'permissions_policy') && empty($headers['items']['permissions_policy']['healthy'])) {
            $points -= 5;
        }
        if (self::flag($options, 'restrict_rest_api') && self::option_string($options, 'rest_access_policy') === 'block_all') {
            $points -= 8;
        }

        $mismatch = 0;
        if (isset($conflicts['items']) && is_array($conflicts['items'])) {
            foreach ($conflicts['items'] as $item) {
                if (!empty($item['mismatch'])) {
                    $mismatch++;
                }
            }
        }
        if ($mismatch > 0) {
            $points -= min(8, $mismatch * 2);
        }

        $points = (int) round($points);
        if ($points < 0) {
            $points = 0;
        }
        if ($points > 100) {
            $points = 100;
        }

        if ($points >= 80) {
            $tone = 'green';
            $hint = __('Strong header and feature coverage for the current configuration.', 'abdal-security-headers');
        } elseif ($points >= 50) {
            $tone = 'warning';
            $hint = __('Useful controls are on, but higher-impact settings still need review.', 'abdal-security-headers');
        } else {
            $tone = 'muted';
            $hint = __('The current configuration leaves important protections off or invalid.', 'abdal-security-headers');
        }

        return array(
            'value' => $points,
            'tone' => $tone,
            'hint' => $hint,
        );
    }

    /**
     * Independent CSP score, 0-100.
     *
     * @param array $options Hydrated options.
     * @return array
     */
    private static function csp_status($options) {
        $learning = class_exists('ASH_CSP_Assistant') && ASH_CSP_Assistant::is_learning();
        $enabled = self::flag($options, 'content_security_policy');
        $directives = self::csp_directive_count($options);
        $score = 0;
        $status = 'disabled';
        $tone = 'muted';
        $label = _x('Disabled', 'CSP status', 'abdal-security-headers');
        $hint = __('Content Security Policy is currently turned off.', 'abdal-security-headers');

        if ($learning) {
            $status = 'report_only';
            $tone = 'warning';
            $label = _x('Report Only', 'CSP status', 'abdal-security-headers');
            $hint = __('Smart CSP Assistant is sending Content-Security-Policy-Report-Only while it learns.', 'abdal-security-headers');
            $score = 35;
        } elseif ($enabled && $directives === 0) {
            $status = 'invalid';
            $tone = 'warning';
            $label = _x('Invalid Configuration', 'CSP status', 'abdal-security-headers');
            $hint = __('Content Security Policy is enabled but no directives are set.', 'abdal-security-headers');
            $score = 5;
        } elseif ($enabled) {
            $status = 'enabled';
            $tone = 'green';
            $label = _x('Enabled', 'CSP status', 'abdal-security-headers');
            $hint = __('Content Security Policy is being sent with responses.', 'abdal-security-headers');
            $score = 40;
            if (self::csp_has($options, 'csp_default_src')) {
                $score += 10;
            }
            if (self::csp_has($options, 'csp_script_src')) {
                $score += 15;
            }
            if (self::csp_has($options, 'csp_style_src')) {
                $score += 8;
            }
            if (self::csp_has($options, 'csp_object_src')) {
                $score += 7;
            }
            if (self::csp_has($options, 'csp_base_uri')) {
                $score += 5;
            }
            $script = isset($options['csp_script_src']) ? (string) $options['csp_script_src'] : '';
            if ($script !== '' && strpos($script, 'unsafe-eval') !== false) {
                $score -= 10;
            } elseif ($script !== '') {
                $score += 5;
            }
        }

        if ($score < 0) {
            $score = 0;
        }
        if ($score > 100) {
            $score = 100;
        }

        return array(
            'status' => $status,
            'score' => $score,
            'tone' => $tone,
            'label' => $label,
            'hint' => $hint,
        );
    }

    /**
     * @param array $options Hydrated.
     * @param array $raw Raw.
     * @param array $headers Header health.
     * @param array $features Feature health.
     * @param array $csp CSP status.
     * @param array $conflicts Conflicts.
     * @return array
     */
    private static function attention_items($options, $raw, $headers, $features, $csp, $conflicts) {
        $items = array();

        if (self::flag($options, 'strict_transport_security') && !self::site_is_https()) {
            $items[] = self::attention(
                'hsts_no_https',
                __('HSTS is enabled while the site URL is not HTTPS.', 'abdal-security-headers'),
                __('Strict-Transport-Security is only sent over HTTPS. Serve the site over HTTPS before relying on HSTS.', 'abdal-security-headers')
            );
        }
        if (self::hsts_preload_incomplete_raw($raw)) {
            $items[] = self::attention(
                'hsts_preload_incomplete',
                __('HSTS Preload is incomplete.', 'abdal-security-headers'),
                __('Preload requires includeSubDomains and a max-age of at least one year.', 'abdal-security-headers')
            );
        }
        if (self::flag($options, 'x_xss_protection')) {
            $items[] = self::attention(
                'xss_deprecated',
                __('X-XSS-Protection is a deprecated header.', 'abdal-security-headers'),
                __('Modern browsers ignore this header. Prefer Content-Security-Policy instead.', 'abdal-security-headers')
            );
        }
        if (self::flag($options, 'restrict_rest_api') && self::option_string($options, 'rest_access_policy') === 'block_all') {
            $items[] = self::attention(
                'rest_block_all',
                __('REST API is set to Block All REST Access.', 'abdal-security-headers'),
                __('Gutenberg, Site Health, plugins, themes, and integrations may stop working.', 'abdal-security-headers')
            );
        }
        if (self::flag($options, 'disable_xmlrpc') && self::option_string($options, 'xmlrpc_mode') === 'all') {
            $items[] = self::attention(
                'xmlrpc_all',
                __('XML-RPC is fully disabled.', 'abdal-security-headers'),
                __('Some applications and integrations that depend on XML-RPC may stop working.', 'abdal-security-headers')
            );
        }
        if (self::flag($options, 'permissions_policy') && empty($headers['items']['permissions_policy']['healthy'])) {
            $items[] = self::attention(
                'pp_invalid',
                __('Permissions-Policy has an invalid or empty configuration.', 'abdal-security-headers'),
                __('The header is enabled but no valid directive is generated.', 'abdal-security-headers')
            );
        }
        if (!empty($conflicts['count'])) {
            $items[] = self::attention(
                'header_conflict',
                __('A security header conflict was detected.', 'abdal-security-headers'),
                __('Another server, CDN, or plugin appears to send a security header that does not match this plugin.', 'abdal-security-headers')
            );
        }
        if ($csp['status'] === 'disabled') {
            $items[] = self::attention(
                'csp_disabled',
                __('Content Security Policy is disabled.', 'abdal-security-headers'),
                __('CSP is independent of Security Profiles. Enable it from the Content Security Policy screen when you are ready.', 'abdal-security-headers'),
                'muted'
            );
        }
        if ($csp['status'] === 'report_only') {
            $items[] = self::attention(
                'csp_report_only',
                __('Content Security Policy is in Report Only mode.', 'abdal-security-headers'),
                __('Learning uses Content-Security-Policy-Report-Only and does not block resources.', 'abdal-security-headers')
            );
        }
        if ($csp['status'] === 'invalid') {
            $items[] = self::attention(
                'csp_invalid',
                __('Content Security Policy configuration is invalid.', 'abdal-security-headers'),
                __('Enable at least one CSP directive before sending the header.', 'abdal-security-headers')
            );
        }
        if (self::flag($options, 'hide_wp_version') && empty($features['items']['hide_wp_version']['healthy'])) {
            $items[] = self::attention(
                'hide_version_incomplete',
                __('WordPress version hiding is enabled without generator outputs.', 'abdal-security-headers'),
                __('Turn on Hide Generator Meta Version or Hide Version from Feeds.', 'abdal-security-headers')
            );
        }
        if (self::flag($options, 'referrer_policy') && self::option_string($options, 'referrer_policy_value') === 'unsafe-url') {
            $items[] = self::attention(
                'referrer_unsafe',
                __('Referrer-Policy is set to unsafe-url.', 'abdal-security-headers'),
                __('unsafe-url sends the full URL across origins and is privacy-sensitive.', 'abdal-security-headers')
            );
        }
        if (self::flag($options, 'disable_xmlrpc') && self::option_string($options, 'xmlrpc_mode') === 'custom') {
            $allow = isset($options['xmlrpc_allow_methods']) && is_array($options['xmlrpc_allow_methods']) ? $options['xmlrpc_allow_methods'] : array();
            $block = isset($options['xmlrpc_block_methods']) && is_array($options['xmlrpc_block_methods']) ? $options['xmlrpc_block_methods'] : array();
            if (empty($allow) && empty($block)) {
                $items[] = self::attention(
                    'xmlrpc_custom_empty',
                    __('XML-RPC custom policy has no methods configured.', 'abdal-security-headers'),
                    __('Add allowed or blocked method names, or choose another protection mode.', 'abdal-security-headers')
                );
            }
        }
        if (self::flag($options, 'restrict_rest_api') && self::option_string($options, 'rest_access_policy') === 'roles') {
            $roles = isset($options['rest_roles']) && is_array($options['rest_roles']) ? $options['rest_roles'] : array();
            if (empty($roles)) {
                $items[] = self::attention(
                    'rest_roles_empty',
                    __('REST Selected Roles has no roles chosen.', 'abdal-security-headers'),
                    __('Select at least one WordPress role or choose another access policy.', 'abdal-security-headers')
                );
            }
        }
        if (self::flag($options, 'x_xss_protection') && self::option_string($options, 'xss_policy') === '1_report') {
            $url = self::option_string($options, 'xss_report_url');
            if ($url === '') {
                $items[] = self::attention(
                    'xss_report_missing',
                    __('X-XSS-Protection report policy is missing a reporting URL.', 'abdal-security-headers'),
                    __('Add a reporting URL or choose another X-XSS-Protection policy.', 'abdal-security-headers')
                );
            }
        }

        return $items;
    }

    /**
     * Detect public response headers that do not match this plugin.
     *
     * @param array $options Hydrated options.
     * @param bool  $force_probe Bypass cache.
     * @return array
     */
    private static function conflicts($options, $force_probe) {
        $remote = self::probe_public_headers($force_probe);
        $ours = self::expected_public_headers($options);
        $items = array();

        if (!is_array($remote) || empty($remote)) {
            return array(
                'count' => 0,
                'items' => array(),
            );
        }

        foreach ($ours as $name => $expected) {
            $found = self::remote_header($remote, $name);
            if ($expected === null) {
                if ($found !== '') {
                    $items[] = array(
                        'name' => $name,
                        'mismatch' => false,
                        'label' => sprintf(
                            /* translators: %s: HTTP header name */
                            __('Another layer sends %s while this plugin does not.', 'abdal-security-headers'),
                            $name
                        ),
                    );
                }
                continue;
            }
            if ($found === '') {
                continue;
            }
            if (!self::header_values_match($expected, $found)) {
                $items[] = array(
                    'name' => $name,
                    'mismatch' => true,
                    'label' => sprintf(
                        /* translators: %s: HTTP header name */
                        __('The public %s value does not match this plugin.', 'abdal-security-headers'),
                        $name
                    ),
                );
            }
        }

        return array(
            'count' => count($items),
            'items' => $items,
        );
    }

    /**
     * @param array $options Hydrated options.
     * @return array Header name => expected value or null when we would not send it.
     */
    private static function expected_public_headers($options) {
        $map = array(
            'X-XSS-Protection' => null,
            'X-Content-Type-Options' => null,
            'Strict-Transport-Security' => null,
            'Permissions-Policy' => null,
            'X-Frame-Options' => null,
            'Referrer-Policy' => null,
            'X-Powered-By' => null,
            'X-Pingback' => null,
            'Content-Security-Policy' => null,
        );

        if (self::flag($options, 'content_security_policy')) {
            unset($map['Content-Security-Policy']);
        }

        if (self::flag($options, 'x_xss_protection') && class_exists('ASH_Header_Settings')) {
            $map['X-XSS-Protection'] = ASH_Header_Settings::build_xss_protection($options);
        }
        if (self::flag($options, 'x_content_type_options')) {
            $map['X-Content-Type-Options'] = 'nosniff';
        }
        if (self::flag($options, 'strict_transport_security') && self::site_is_https() && class_exists('ASH_Header_Settings')) {
            $map['Strict-Transport-Security'] = ASH_Header_Settings::build_hsts($options);
        }
        if (self::flag($options, 'permissions_policy') && class_exists('ASH_Header_Settings')) {
            $value = ASH_Header_Settings::build_permissions_policy($options);
            $map['Permissions-Policy'] = $value !== '' ? $value : null;
        }
        if (self::flag($options, 'x_frame_options') && class_exists('ASH_Header_Settings')) {
            $map['X-Frame-Options'] = ASH_Header_Settings::build_x_frame_options($options);
        }
        if (self::flag($options, 'referrer_policy') && class_exists('ASH_Header_Settings')) {
            $map['Referrer-Policy'] = ASH_Header_Settings::build_referrer_policy($options);
        }
        if (self::flag($options, 'remove_x_powered_by')) {
            $map['X-Powered-By'] = '';
        }
        if (self::flag($options, 'remove_x_pingback')) {
            $map['X-Pingback'] = '';
        }

        return $map;
    }

    /**
     * @param bool $force_probe Bypass cache.
     * @return array
     */
    private static function probe_public_headers($force_probe) {
        if (!$force_probe) {
            $cached = get_transient(self::PROBE_TRANSIENT);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $url = home_url('/');
        $parts = wp_parse_url($url);
        if (!is_array($parts) || empty($parts['host'])) {
            return array();
        }

        $response = wp_remote_get(
            $url,
            array(
                'timeout' => 4,
                'redirection' => 0,
                'sslverify' => true,
                'headers' => array(
                    'Cache-Control' => 'no-cache',
                ),
            )
        );
        if (is_wp_error($response)) {
            set_transient(self::PROBE_TRANSIENT, array(), self::PROBE_TTL);
            return array();
        }

        $headers = wp_remote_retrieve_headers($response);
        $map = array();
        if (is_array($headers) || $headers instanceof \Traversable) {
            foreach ($headers as $name => $value) {
                if (is_array($value)) {
                    $value = implode(', ', $value);
                }
                $map[strtolower((string) $name)] = (string) $value;
            }
        }

        set_transient(self::PROBE_TRANSIENT, $map, self::PROBE_TTL);
        return $map;
    }

    /**
     * @param array  $remote Remote header map, lowercase keys.
     * @param string $name   Header name.
     * @return string
     */
    private static function remote_header($remote, $name) {
        $key = strtolower($name);
        return isset($remote[$key]) ? trim((string) $remote[$key]) : '';
    }

    /**
     * @param string $expected Expected value. Empty string means we intend to remove it.
     * @param string $found    Public value.
     * @return bool
     */
    private static function header_values_match($expected, $found) {
        $expected = strtolower(trim((string) $expected));
        $found = strtolower(trim((string) $found));
        if ($expected === '') {
            return $found === '';
        }
        return $expected === $found;
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function xss_state($options) {
        if (!self::flag($options, 'x_xss_protection')) {
            return self::state(false, false);
        }
        $policy = self::option_string($options, 'xss_policy', '0');
        if ($policy === '1_report' && self::option_string($options, 'xss_report_url') === '') {
            return self::state(false, true);
        }
        return self::state(false, true);
    }

    /**
     * @param array  $options Options.
     * @param string $key     Flag.
     * @return array
     */
    private static function simple_header_state($options, $key) {
        $on = self::flag($options, $key);
        return self::state($on, false);
    }

    /**
     * @param array $options Hydrated.
     * @param array $raw Raw.
     * @return array
     */
    private static function hsts_state($options, $raw) {
        if (!self::flag($options, 'strict_transport_security')) {
            return self::state(false, false);
        }
        $attention = !self::site_is_https() || self::hsts_preload_incomplete_raw($raw);
        $healthy = self::site_is_https() && absint(self::option_string($options, 'hsts_max_age', '0')) > 0 && !$attention;
        return self::state($healthy, $attention);
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function pp_state($options) {
        if (!self::flag($options, 'permissions_policy')) {
            return self::state(false, false);
        }
        $value = class_exists('ASH_Header_Settings') ? ASH_Header_Settings::build_permissions_policy($options) : '';
        $ok = is_string($value) && $value !== '';
        return self::state($ok, !$ok);
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function xfo_state($options) {
        if (!self::flag($options, 'x_frame_options')) {
            return self::state(false, false);
        }
        $policy = self::option_string($options, 'x_frame_options_policy', 'SAMEORIGIN');
        $ok = class_exists('ASH_Header_Settings') && ASH_Header_Settings::is_x_frame_options_policy($policy);
        return self::state($ok, !$ok);
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function referrer_state($options) {
        if (!self::flag($options, 'referrer_policy')) {
            return self::state(false, false);
        }
        $policy = self::option_string($options, 'referrer_policy_value');
        $ok = class_exists('ASH_Header_Settings') && ASH_Header_Settings::is_referrer_policy($policy);
        $weak = $policy === 'unsafe-url';
        return self::state($ok && !$weak, $weak || !$ok);
    }

    /**
     * @param array  $options Options.
     * @param string $key Flag.
     * @return array
     */
    private static function simple_feature_state($options, $key) {
        $on = self::flag($options, $key);
        return self::state($on, false);
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function hide_version_state($options) {
        if (!self::flag($options, 'hide_wp_version')) {
            return self::state(false, false);
        }
        $ok = self::flag($options, 'hide_generator_meta') || self::flag($options, 'hide_version_feeds');
        return self::state($ok, !$ok);
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function login_state($options) {
        if (!self::flag($options, 'remove_login_errors')) {
            return self::state(false, false);
        }
        $mode = self::option_string($options, 'login_error_mode', 'generic');
        if ($mode === 'custom' && self::option_string($options, 'login_error_custom') === '') {
            return self::state(true, false);
        }
        return self::state(true, false);
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function xmlrpc_state($options) {
        if (!self::flag($options, 'disable_xmlrpc')) {
            return self::state(false, false);
        }
        $mode = self::option_string($options, 'xmlrpc_mode', 'auth');
        if ($mode === 'all') {
            return self::state(true, true);
        }
        if ($mode === 'custom') {
            $allow = isset($options['xmlrpc_allow_methods']) && is_array($options['xmlrpc_allow_methods']) ? $options['xmlrpc_allow_methods'] : array();
            $block = isset($options['xmlrpc_block_methods']) && is_array($options['xmlrpc_block_methods']) ? $options['xmlrpc_block_methods'] : array();
            $ok = !empty($allow) || !empty($block);
            return self::state($ok, !$ok);
        }
        return self::state(true, false);
    }

    /**
     * @param array $options Options.
     * @return array
     */
    private static function rest_state($options) {
        if (!self::flag($options, 'restrict_rest_api')) {
            return self::state(false, false);
        }
        $policy = self::option_string($options, 'rest_access_policy', 'authenticated');
        if ($policy === 'block_all') {
            return self::state(true, true);
        }
        if ($policy === 'roles') {
            $roles = isset($options['rest_roles']) && is_array($options['rest_roles']) ? $options['rest_roles'] : array();
            $ok = !empty($roles);
            return self::state($ok, !$ok);
        }
        if ($policy === 'capability') {
            $cap = self::option_string($options, 'rest_capability');
            $ok = $cap !== '';
            return self::state($ok, !$ok);
        }
        return self::state(true, false);
    }

    /**
     * @param bool $healthy Healthy.
     * @param bool $attention Attention.
     * @return array
     */
    private static function state($healthy, $attention) {
        return array(
            'healthy' => (bool) $healthy,
            'attention' => (bool) $attention,
        );
    }

    /**
     * @param array  $options Options.
     * @param string $key Key.
     * @return bool
     */
    private static function flag($options, $key) {
        return isset($options[$key]) && (string) $options[$key] === '1';
    }

    /**
     * @param array  $options Options.
     * @param string $key Key.
     * @param string $default Default.
     * @return string
     */
    private static function option_string($options, $key, $default = '') {
        return isset($options[$key]) ? (string) $options[$key] : $default;
    }

    /**
     * @return bool
     */
    private static function site_is_https() {
        $scheme = wp_parse_url(home_url(), PHP_URL_SCHEME);
        if (is_string($scheme) && strtolower($scheme) === 'https') {
            return true;
        }
        return is_ssl();
    }

    /**
     * @param array $raw Raw options.
     * @return bool
     */
    private static function hsts_preload_incomplete_raw($raw) {
        if (!is_array($raw) || !self::flag($raw, 'strict_transport_security')) {
            return false;
        }
        if (!self::flag($raw, 'hsts_preload')) {
            return false;
        }
        $max_age = isset($raw['hsts_max_age']) ? absint($raw['hsts_max_age']) : 0;
        $include = self::flag($raw, 'hsts_include_subdomains');
        return !$include || $max_age < 31536000;
    }

    /**
     * @param array $options Options.
     * @return int
     */
    private static function csp_directive_count($options) {
        $count = 0;
        foreach (self::csp_keys() as $key) {
            if (self::csp_has($options, $key)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * @param array  $options Options.
     * @param string $key Key.
     * @return bool
     */
    private static function csp_has($options, $key) {
        return isset($options[$key]) && trim((string) $options[$key]) !== '';
    }

    /**
     * @return array
     */
    private static function csp_keys() {
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
     * @param string $id Id.
     * @param string $title Title.
     * @param string $description Description.
     * @param string $tone Tone.
     * @return array
     */
    private static function attention($id, $title, $description, $tone = 'warning') {
        return array(
            'id' => $id,
            'title' => $title,
            'description' => $description,
            'tone' => $tone,
        );
    }
}
