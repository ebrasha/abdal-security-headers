<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : uninstall.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-31 05:31:51
 * Description : Removes plugin-owned data on uninstall only when the site owner enabled it
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Read the plugin-owned settings array for the current site.
 *
 * @return array
 */
function ash_uninstall_plugin_settings() {
    $settings = get_option('ash_plugin_settings', array());
    return is_array($settings) ? $settings : array();
}

/**
 * Whether the current site asked to purge plugin data on uninstall.
 *
 * @return bool
 */
function ash_uninstall_should_remove_data() {
    $settings = ash_uninstall_plugin_settings();
    return isset($settings['remove_data_on_uninstall']) && (string) $settings['remove_data_on_uninstall'] === '1';
}

/**
 * Delete plugin-owned transients from the current site options table.
 *
 * @return void
 */
function ash_uninstall_delete_rate_limit_transients() {
    global $wpdb;

    $like_transient = $wpdb->esc_like('_transient_ash_csp_rl_') . '%';
    $like_timeout = $wpdb->esc_like('_transient_timeout_ash_csp_rl_') . '%';

    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
            $like_transient,
            $like_timeout
        )
    );
}

/**
 * Delete the plugin-owned disk-scan directory inside uploads.
 *
 * @return void
 */
function ash_uninstall_delete_disk_scan_dir() {
    $upload = wp_upload_dir(null, false);
    if (!is_array($upload) || !empty($upload['error']) || empty($upload['basedir'])) {
        return;
    }

    $base = wp_normalize_path((string) $upload['basedir']);
    $real_base = realpath($base);
    if ($real_base === false) {
        return;
    }
    $real_base = wp_normalize_path($real_base);
    $base_prefix = trailingslashit($real_base);

    $dir = wp_normalize_path($base . '/ash-csp-disk-scan');
    $real_dir = realpath($dir);
    if ($real_dir === false) {
        return;
    }
    $real_dir = wp_normalize_path($real_dir);

    if (!str_starts_with(trailingslashit($real_dir), $base_prefix)) {
        return;
    }

    if (substr($real_dir, -strlen('ash-csp-disk-scan')) !== 'ash-csp-disk-scan') {
        return;
    }

    foreach (array('files.txt', 'index.php') as $name) {
        $path = $real_dir . '/' . $name;
        if (is_file($path)) {
            unlink($path);
        }
    }

    if (is_dir($real_dir)) {
        rmdir($real_dir);
    }
}

/**
 * Drop the plugin CSP sources table for the current site.
 *
 * @return void
 */
function ash_uninstall_drop_csp_table() {
    global $wpdb;

    $table = $wpdb->prefix . 'ash_csp_sources';
    if (!preg_match('/^[A-Za-z0-9_]+$/', $table)) {
        return;
    }

    $wpdb->query('DROP TABLE IF EXISTS `' . $table . '`');
}

/**
 * Purge plugin-owned data for the current site when the uninstall switch is on.
 *
 * @return void
 */
function ash_uninstall_purge_current_site() {
    if (!ash_uninstall_should_remove_data()) {
        return;
    }

    delete_option('ash_options');
    delete_option('ash_plugin_settings');
    delete_option('ash_csp_assistant_state');
    delete_option('ash_csp_db_version');
    delete_option('ash_csp_disk_scan');
    delete_option('ash_csp_disk_exclusions');
    delete_option('ash_csp_disk_scope');

    wp_clear_scheduled_hook('ash_scheduled_tasks');
    wp_clear_scheduled_hook('ash_csp_assistant_cron');

    ash_uninstall_delete_rate_limit_transients();
    ash_uninstall_delete_disk_scan_dir();
    ash_uninstall_drop_csp_table();
}

if (is_multisite()) {
    $offset = 0;
    $chunk = 100;

    do {
        $site_ids = get_sites(
            array(
                'fields' => 'ids',
                'number' => $chunk,
                'offset' => $offset,
            )
        );

        if (!is_array($site_ids) || $site_ids === array()) {
            break;
        }

        foreach ($site_ids as $site_id) {
            switch_to_blog((int) $site_id);
            ash_uninstall_purge_current_site();
            restore_current_blog();
        }

        $count = count($site_ids);
        $offset += $chunk;
    } while ($count === $chunk);
} else {
    ash_uninstall_purge_current_site();
}
