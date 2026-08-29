<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-csp-repository.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 05:17:35
 * Description : Stores and merges Smart CSP Assistant discovery records
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

class ASH_CSP_Repository {
    const DB_VERSION = '1';
    const EXPIRE_NEW_DAYS = 30;
    const EXPIRE_REVIEWED_DAYS = 90;

    /**
     * @return string
     */
    public static function table_name() {
        global $wpdb;
        return $wpdb->prefix . 'ash_csp_sources';
    }

    /**
     * Create or upgrade the discovery table.
     *
     * @return void
     */
    public static function install() {
        global $wpdb;

        $table = self::table_name();
        $charset = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            origin_key varchar(32) NOT NULL,
            origin varchar(191) NOT NULL,
            scheme varchar(10) NOT NULL DEFAULT '',
            directive varchar(32) NOT NULL,
            resource_type varchar(32) NOT NULL DEFAULT '',
            first_seen datetime NOT NULL,
            last_seen datetime NOT NULL,
            detection_count int(10) unsigned NOT NULL DEFAULT 1,
            detection_methods varchar(64) NOT NULL DEFAULT '',
            pages_detected longtext NULL,
            detected_from varchar(191) NOT NULL DEFAULT '',
            confidence varchar(32) NOT NULL DEFAULT 'unknown',
            status varchar(20) NOT NULL DEFAULT 'new',
            is_new tinyint(1) NOT NULL DEFAULT 1,
            PRIMARY KEY  (id),
            UNIQUE KEY origin_key (origin_key),
            KEY last_seen (last_seen),
            KEY status (status),
            KEY directive (directive)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
        update_option('ash_csp_db_version', self::DB_VERSION, false);
    }

    /**
     * Install the table when missing after a plugin update.
     *
     * @return void
     */
    public static function maybe_install() {
        if (get_option('ash_csp_db_version') !== self::DB_VERSION) {
            self::install();
        }
    }

    /**
     * Insert or merge a discovered source. Never auto-trusts third parties.
     *
     * @param array $item Discovery payload.
     * @return bool
     */
    public static function upsert($item) {
        global $wpdb;

        $origin = isset($item['origin']) ? $item['origin'] : '';
        $directive = isset($item['directive']) ? $item['directive'] : 'unknown';
        $method = isset($item['method']) ? $item['method'] : 'runtime';
        if ($origin === '' || !in_array($method, array('static', 'report-only', 'runtime', 'disk'), true)) {
            return false;
        }

        $table = self::table_name();
        $now = current_time('mysql');
        $key = ASH_CSP_Normalizer::origin_key($origin, $directive);
        $scheme = (string) wp_parse_url($origin, PHP_URL_SCHEME);
        $page = isset($item['page']) ? ASH_CSP_Normalizer::page_path($item['page']) : '';
        $detected_from = isset($item['detected_from']) ? sanitize_text_field($item['detected_from']) : '';
        $resource_type = isset($item['resource_type']) ? sanitize_key($item['resource_type']) : '';
        $is_dangerous = ASH_CSP_Normalizer::is_dangerous($origin);

        $existing = $wpdb->get_row(
            $wpdb->prepare("SELECT * FROM {$table} WHERE origin_key = %s", $key),
            ARRAY_A
        );

        if (!$existing) {
            $pages = ($page !== '') ? array($page) : array();
            $status = $is_dangerous ? 'warning' : 'new';
            $row = array(
                'origin_key' => $key,
                'origin' => substr($origin, 0, 191),
                'scheme' => substr($scheme, 0, 10),
                'directive' => substr($directive, 0, 32),
                'resource_type' => substr($resource_type, 0, 32),
                'first_seen' => $now,
                'last_seen' => $now,
                'detection_count' => 1,
                'detection_methods' => $method,
                'pages_detected' => wp_json_encode($pages),
                'detected_from' => substr($detected_from, 0, 191),
                'confidence' => 'unknown',
                'status' => $status,
                'is_new' => 1,
            );
            $row['confidence'] = self::score($row);
            $wpdb->insert($table, $row);
            return true;
        }

        $methods = array_filter(explode(',', (string) $existing['detection_methods']));
        $methods[] = $method;
        $methods = array_values(array_unique($methods));
        sort($methods);

        $pages = json_decode((string) $existing['pages_detected'], true);
        if (!is_array($pages)) {
            $pages = array();
        }
        if ($page !== '' && !in_array($page, $pages, true) && count($pages) < 25) {
            $pages[] = $page;
        }

        $status = $existing['status'];
        if ($is_dangerous) {
            $status = 'warning';
        }

        $detected_from_value = $existing['detected_from'];
        if ($detected_from_value === '' && $detected_from !== '') {
            $detected_from_value = $detected_from;
        }

        $resource_type_value = $existing['resource_type'] !== '' ? $existing['resource_type'] : $resource_type;

        $row = array(
            'origin' => $existing['origin'],
            'scheme' => $existing['scheme'],
            'directive' => $existing['directive'],
            'resource_type' => $resource_type_value,
            'first_seen' => $existing['first_seen'],
            'last_seen' => $now,
            'detection_count' => (int) $existing['detection_count'] + 1,
            'detection_methods' => implode(',', $methods),
            'pages_detected' => wp_json_encode($pages),
            'detected_from' => $detected_from_value,
            'status' => $status,
            'is_new' => in_array($status, array('applied', 'ignored'), true) ? 0 : 1,
        );
        $row['confidence'] = self::score($row);

        $wpdb->update($table, $row, array('origin_key' => $key));
        return true;
    }

    /**
     * @param array $args Query args.
     * @return array
     */
    public static function get_sources($args = array()) {
        global $wpdb;
        $table = self::table_name();
        $sql = "SELECT * FROM {$table} ORDER BY is_new DESC, last_seen DESC, origin ASC LIMIT 500";
        $rows = $wpdb->get_results($sql, ARRAY_A);
        return is_array($rows) ? $rows : array();
    }

    /**
     * @param int $id Row ID.
     * @return array|null
     */
    public static function get_source($id) {
        global $wpdb;
        $table = self::table_name();
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE id = %d", (int) $id), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    /**
     * @param array $ids Source IDs.
     * @return array
     */
    public static function get_sources_by_ids($ids) {
        global $wpdb;
        $ids = array_map('intval', (array) $ids);
        $ids = array_values(array_filter($ids));
        if (empty($ids)) {
            return array();
        }
        $table = self::table_name();
        $placeholders = implode(',', array_fill(0, count($ids), '%d'));
        $sql = $wpdb->prepare("SELECT * FROM {$table} WHERE id IN ({$placeholders})", $ids);
        $rows = $wpdb->get_results($sql, ARRAY_A);
        return is_array($rows) ? $rows : array();
    }

    /**
     * @param int    $id Source ID.
     * @param string $status Status key.
     * @return bool
     */
    public static function set_status($id, $status) {
        global $wpdb;
        if (!in_array($status, array('new', 'ignored', 'applied', 'warning'), true)) {
            return false;
        }
        $table = self::table_name();
        $is_new = ($status === 'new' || $status === 'warning') ? 1 : 0;
        return false !== $wpdb->update(
            $table,
            array(
                'status' => $status,
                'is_new' => $is_new,
            ),
            array('id' => (int) $id)
        );
    }

    /**
     * @return int
     */
    public static function count_sources() {
        global $wpdb;
        $table = self::table_name();
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
    }

    /**
     * @return array
     */
    public static function summary() {
        global $wpdb;
        $table = self::table_name();
        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        $new_count = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table} WHERE is_new = 1 AND status = 'new'");
        $rows = $wpdb->get_results("SELECT directive, COUNT(*) AS total FROM {$table} GROUP BY directive", ARRAY_A);
        $by_directive = array();
        if (is_array($rows)) {
            foreach ($rows as $row) {
                $by_directive[$row['directive']] = (int) $row['total'];
            }
        }
        return array(
            'total' => $total,
            'new' => $new_count,
            'by_directive' => $by_directive,
        );
    }

    /**
     * @return void
     */
    public static function clear_all() {
        global $wpdb;
        $wpdb->query('DELETE FROM ' . self::table_name());
    }

    /**
     * Drop stale discovery rows so the table cannot grow without bound.
     *
     * @return void
     */
    public static function expire_old() {
        global $wpdb;
        $table = self::table_name();
        $new_before = gmdate('Y-m-d H:i:s', time() - (self::EXPIRE_NEW_DAYS * DAY_IN_SECONDS));
        $reviewed_before = gmdate('Y-m-d H:i:s', time() - (self::EXPIRE_REVIEWED_DAYS * DAY_IN_SECONDS));
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE last_seen < %s AND status IN ('new', 'warning')",
            $new_before
        ));
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table} WHERE last_seen < %s AND status IN ('ignored', 'applied')",
            $reviewed_before
        ));
    }

    /**
     * Confidence is a suggestion signal only and never auto-whitelists.
     *
     * @param array $row Source row.
     * @return string
     */
    public static function score($row) {
        $origin = isset($row['origin']) ? $row['origin'] : '';
        if (ASH_CSP_Normalizer::is_dangerous($origin) || $origin === 'data:' || $origin === 'blob:') {
            return 'potentially_risky';
        }

        $methods = array_filter(explode(',', isset($row['detection_methods']) ? $row['detection_methods'] : ''));
        $count = isset($row['detection_count']) ? (int) $row['detection_count'] : 1;
        $has_static = in_array('static', $methods, true);
        $has_runtime = in_array('runtime', $methods, true);
        $has_report = in_array('report-only', $methods, true);

        if (ASH_CSP_Normalizer::is_site_origin($origin)) {
            return 'trusted';
        }

        if ($has_static && $has_runtime) {
            return 'trusted';
        }
        if ($has_static) {
            return 'likely_safe';
        }
        if ($has_runtime && $has_report && $count >= 3) {
            return 'likely_safe';
        }
        if ($has_runtime && $count >= 5) {
            return 'likely_safe';
        }
        if ($has_report && !$has_runtime && !$has_static) {
            return $count <= 1 ? 'potentially_risky' : 'unknown';
        }
        if ($count <= 1) {
            return 'unknown';
        }

        return 'unknown';
    }
}
