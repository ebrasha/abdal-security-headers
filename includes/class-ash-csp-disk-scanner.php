<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-csp-disk-scanner.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 10:30:09
 * Description : Chunked on-disk scan of plugin and theme files for CSP origins
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

class ASH_CSP_Disk_Scanner {
    const OPTION = 'ash_csp_disk_scan';
    const EXCLUSIONS_OPTION = 'ash_csp_disk_exclusions';
    const SCOPE_OPTION = 'ash_csp_disk_scope';
    const BATCH_SIZE = 18;
    const MAX_FILE_BYTES = 1572864;
    const MAX_FILES = 150000;
    const MAX_EXCLUSIONS = 80;

    /**
     * Folder names and relative paths skipped for the current scan.
     *
     * @var array|null
     */
    private static $exclusion_rules = null;

    /**
     * @return array
     */
    public static function default_job() {
        return array(
            'status' => 'idle',
            'total' => 0,
            'processed' => 0,
            'found' => 0,
            'byte_offset' => 0,
            'list_file' => '',
            'cancel' => 0,
            'error' => '',
            'exclusions' => array(),
            'scope_enabled' => 0,
            'scope_targets' => array(),
            'updated_at' => 0,
        );
    }

    /**
     * Built-in skip list shown in the editor until the site owner changes it.
     *
     * @return array
     */
    public static function default_exclusions() {
        return array(
            'node_modules',
            '.git',
            '.svn',
            '.hg',
            '.idea',
            '.vscode',
        );
    }

    /**
     * Sanitize exclusion names and relative paths.
     *
     * @param mixed $items Raw list.
     * @return array
     */
    public static function sanitize_exclusions($items) {
        if (!is_array($items)) {
            return array();
        }

        $clean = array();
        foreach ($items as $item) {
            if (count($clean) >= self::MAX_EXCLUSIONS) {
                break;
            }
            $item = wp_normalize_path(trim((string) $item));
            $item = trim($item, "/\\");
            if ($item === '' || strpos($item, '..') !== false) {
                continue;
            }
            $item = sanitize_text_field($item);
            $item = trim($item, "/\\");
            if ($item === '' || strlen($item) > 180) {
                continue;
            }
            $key = strtolower($item);
            $clean[$key] = $item;
        }

        return array_values($clean);
    }

    /**
     * Saved skip list, or the built-in defaults when the option was never stored.
     *
     * @return array
     */
    public static function get_exclusions() {
        $saved = get_option(self::EXCLUSIONS_OPTION, false);
        if ($saved === false) {
            return self::default_exclusions();
        }
        return self::sanitize_exclusions($saved);
    }

    /**
     * @param mixed $items Raw list.
     * @return array
     */
    public static function save_exclusions($items) {
        $clean = self::sanitize_exclusions($items);
        update_option(self::EXCLUSIONS_OPTION, $clean, false);
        self::$exclusion_rules = null;
        return $clean;
    }

    /**
     * Restore the built-in skip list.
     *
     * @return array
     */
    public static function restore_default_exclusions() {
        return self::save_exclusions(self::default_exclusions());
    }

    /**
     * @return array
     */
    public static function default_scope() {
        return array(
            'enabled' => 0,
            'targets' => array(),
        );
    }

    /**
     * @param mixed $ids Raw target ids.
     * @return array
     */
    public static function sanitize_scope_targets($ids) {
        if (!is_array($ids)) {
            return array();
        }

        $allowed = array();
        foreach (self::list_installed_items() as $item) {
            $allowed[$item['id']] = true;
        }

        $clean = array();
        foreach ($ids as $id) {
            $id = sanitize_text_field((string) $id);
            if ($id === '' || empty($allowed[$id])) {
                continue;
            }
            $clean[$id] = $id;
        }

        return array_values($clean);
    }

    /**
     * @return array
     */
    public static function get_scope() {
        $saved = get_option(self::SCOPE_OPTION, false);
        if (!is_array($saved)) {
            return self::default_scope();
        }

        return array(
            'enabled' => !empty($saved['enabled']) ? 1 : 0,
            'targets' => self::sanitize_scope_targets(isset($saved['targets']) ? $saved['targets'] : array()),
        );
    }

    /**
     * @param bool  $enabled Whether the allow-list is active.
     * @param mixed $targets Selected plugin/theme ids.
     * @return array
     */
    public static function save_scope($enabled, $targets) {
        $scope = array(
            'enabled' => $enabled ? 1 : 0,
            'targets' => self::sanitize_scope_targets($targets),
        );
        update_option(self::SCOPE_OPTION, $scope, false);
        return $scope;
    }

    /**
     * Installed plugins and themes available as scan targets.
     *
     * @return array
     */
    public static function list_installed_items() {
        $items = array();

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        foreach (get_plugins() as $file => $data) {
            $slug = dirname((string) $file);
            if ($slug === '.' || $slug === '') {
                $slug = (string) $file;
            }
            $name = isset($data['Name']) ? (string) $data['Name'] : $slug;
            $items[] = array(
                'id' => 'plugin:' . $slug,
                'type' => 'plugin',
                'slug' => $slug,
                'name' => $name,
            );
        }

        foreach (wp_get_themes() as $stylesheet => $theme) {
            $name = $theme instanceof WP_Theme ? (string) $theme->get('Name') : (string) $stylesheet;
            if ($name === '') {
                $name = (string) $stylesheet;
            }
            $items[] = array(
                'id' => 'theme:' . $stylesheet,
                'type' => 'theme',
                'slug' => (string) $stylesheet,
                'name' => $name,
            );
        }

        return $items;
    }

    /**
     * Payload for the selected-items editor.
     *
     * @return array
     */
    public static function scope_payload() {
        $scope = self::get_scope();
        $selected = array();
        foreach ($scope['targets'] as $id) {
            $selected[$id] = true;
        }

        $plugins = array();
        $themes = array();
        foreach (self::list_installed_items() as $item) {
            $item['selected'] = !empty($selected[$item['id']]);
            if ($item['type'] === 'theme') {
                $themes[] = $item;
            } else {
                $plugins[] = $item;
            }
        }

        usort($plugins, array(__CLASS__, 'sort_items_by_name'));
        usort($themes, array(__CLASS__, 'sort_items_by_name'));

        return array(
            'enabled' => (int) $scope['enabled'],
            'targets' => $scope['targets'],
            'plugins' => $plugins,
            'themes' => $themes,
        );
    }

    /**
     * @param array $a First item.
     * @param array $b Second item.
     * @return int
     */
    private static function sort_items_by_name($a, $b) {
        return strcasecmp(isset($a['name']) ? $a['name'] : '', isset($b['name']) ? $b['name'] : '');
    }

    /**
     * @return array
     */
    public static function get_job() {
        $job = get_option(self::OPTION, array());
        if (!is_array($job)) {
            $job = array();
        }
        return array_merge(self::default_job(), $job);
    }

    /**
     * @param array $job Job values.
     * @return array
     */
    public static function save_job($job) {
        $job = array_merge(self::get_job(), $job);
        $job['updated_at'] = time();
        update_option(self::OPTION, $job, false);
        return $job;
    }

    /**
     * @return bool
     */
    public static function is_active() {
        $status = self::get_job()['status'];
        return in_array($status, array('counting', 'running'), true);
    }

    /**
     * Public snapshot for the assistant payload.
     *
     * @return array
     */
    public static function snapshot() {
        $job = self::get_job();
        $total = (int) $job['total'];
        $processed = (int) $job['processed'];
        $percent = 0;
        if ($total > 0) {
            $percent = (int) min(100, floor(($processed / $total) * 100));
        }
        if ($job['status'] === 'complete') {
            $percent = 100;
        }

        return array(
            'status' => $job['status'],
            'total' => $total,
            'processed' => $processed,
            'found' => (int) $job['found'],
            'percent' => $percent,
            'error' => (string) $job['error'],
        );
    }

    /**
     * Count eligible plugin and theme files, then persist the path list.
     *
     * @return array
     */
    public static function prepare() {
        @set_time_limit(60);
        self::$exclusion_rules = null;
        self::cleanup_list_file();

        $list_file = self::list_file_path();
        $dir = dirname($list_file);
        if (!is_dir($dir) && !wp_mkdir_p($dir)) {
            return self::save_job(array(
                'status' => 'error',
                'error' => 'list_dir',
            ));
        }
        $index = $dir . '/index.php';
        if (!is_file($index)) {
            file_put_contents($index, "<?php\n// Silence is golden.\n");
        }

        $handle = fopen($list_file, 'wb');
        if (!$handle) {
            return self::save_job(array(
                'status' => 'error',
                'error' => 'list_file',
            ));
        }

        $scope = self::get_scope();
        self::save_job(array(
            'status' => 'counting',
            'total' => 0,
            'processed' => 0,
            'found' => 0,
            'byte_offset' => 0,
            'list_file' => $list_file,
            'cancel' => 0,
            'error' => '',
            'exclusions' => self::get_exclusions(),
            'scope_enabled' => !empty($scope['enabled']) ? 1 : 0,
            'scope_targets' => isset($scope['targets']) ? $scope['targets'] : array(),
        ));

        if (self::was_cancelled()) {
            fclose($handle);
            return self::mark_cancelled();
        }

        $total = 0;
        foreach (self::scan_roots() as $root) {
            if (self::was_cancelled()) {
                fclose($handle);
                self::cleanup_list_file();
                return self::mark_cancelled();
            }
            $total += self::write_root_files($handle, $root, $total);
            if ($total >= self::MAX_FILES) {
                break;
            }
        }
        fclose($handle);

        if (self::was_cancelled()) {
            self::cleanup_list_file();
            return self::mark_cancelled();
        }

        return self::save_job(array(
            'status' => $total > 0 ? 'running' : 'complete',
            'total' => $total,
            'processed' => 0,
            'found' => 0,
            'byte_offset' => 0,
            'list_file' => $list_file,
            'cancel' => 0,
            'error' => '',
        ));
    }

    /**
     * Scan the next batch of listed files.
     *
     * @return array
     */
    public static function tick() {
        @set_time_limit(25);

        if (self::was_cancelled()) {
            return self::mark_cancelled();
        }

        $job = self::get_job();
        if ($job['status'] === 'cancelled' || $job['status'] === 'complete' || $job['status'] === 'idle') {
            return $job;
        }
        if ($job['status'] === 'error') {
            return $job;
        }
        if ($job['status'] !== 'running' || $job['list_file'] === '' || !is_readable($job['list_file'])) {
            return self::save_job(array(
                'status' => 'error',
                'error' => 'missing_list',
            ));
        }

        $handle = fopen($job['list_file'], 'rb');
        if (!$handle) {
            return self::save_job(array(
                'status' => 'error',
                'error' => 'read_list',
            ));
        }

        $offset = (int) $job['byte_offset'];
        if ($offset > 0) {
            fseek($handle, $offset);
        }

        $processed = (int) $job['processed'];
        $found = (int) $job['found'];
        $batch = 0;

        while ($batch < self::BATCH_SIZE && ($line = fgets($handle)) !== false) {
            if (self::was_cancelled()) {
                fclose($handle);
                return self::mark_cancelled();
            }

            $path = trim($line);
            $processed++;
            $batch++;
            if ($path !== '') {
                $found += self::scan_file($path);
            }
        }

        $byte_offset = ftell($handle);
        $eof = feof($handle);
        fclose($handle);

        if ($eof || $processed >= (int) $job['total']) {
            self::cleanup_list_file();
            return self::save_job(array(
                'status' => 'complete',
                'processed' => max($processed, (int) $job['total']),
                'found' => $found,
                'byte_offset' => 0,
                'list_file' => '',
                'cancel' => 0,
            ));
        }

        return self::save_job(array(
            'status' => 'running',
            'processed' => $processed,
            'found' => $found,
            'byte_offset' => (int) $byte_offset,
        ));
    }

    /**
     * Request cancellation of an in-progress disk scan.
     *
     * @return array
     */
    public static function cancel() {
        self::save_job(array('cancel' => 1));
        return self::mark_cancelled();
    }

    /**
     * Drop job state and any leftover list file.
     *
     * @return void
     */
    public static function reset() {
        self::cleanup_list_file();
        delete_option(self::OPTION);
    }

    /**
     * @return bool
     */
    private static function was_cancelled() {
        $job = get_option(self::OPTION, array());
        return is_array($job) && !empty($job['cancel']);
    }

    /**
     * @return array
     */
    private static function mark_cancelled() {
        self::cleanup_list_file();
        return self::save_job(array(
            'status' => 'cancelled',
            'list_file' => '',
            'byte_offset' => 0,
            'cancel' => 0,
            'error' => '',
        ));
    }

    /**
     * @return void
     */
    private static function cleanup_list_file() {
        $job = get_option(self::OPTION, array());
        if (!is_array($job) || empty($job['list_file']) || !is_string($job['list_file'])) {
            return;
        }
        if (is_file($job['list_file'])) {
            @unlink($job['list_file']);
        }
        $dir = dirname($job['list_file']);
        if (is_dir($dir) && self::is_scan_dir($dir)) {
            $index = $dir . '/index.php';
            if (is_file($index)) {
                @unlink($index);
            }
            @rmdir($dir);
        }
    }

    /**
     * @param string $dir Directory path.
     * @return bool
     */
    private static function is_scan_dir($dir) {
        $dir = wp_normalize_path($dir);
        return substr($dir, -strlen('/ash-csp-disk-scan')) === '/ash-csp-disk-scan'
            || substr($dir, -strlen('\\ash-csp-disk-scan')) === '\\ash-csp-disk-scan';
    }

    /**
     * @return string
     */
    private static function list_file_path() {
        $upload = wp_upload_dir(null, false);
        $base = isset($upload['basedir']) ? $upload['basedir'] : WP_CONTENT_DIR;
        return wp_normalize_path($base . '/ash-csp-disk-scan/files.txt');
    }

    /**
     * @return array
     */
    private static function scan_roots() {
        $scope = self::scope_for_scan();
        if (!empty($scope['enabled'])) {
            $roots = array();
            $targets = isset($scope['targets']) && is_array($scope['targets']) ? $scope['targets'] : array();
            foreach ($targets as $id) {
                $path = self::path_for_target($id);
                if ($path !== '') {
                    $roots[] = $path;
                }
            }
            return array_values(array_unique($roots));
        }

        $roots = array();
        if (defined('WP_PLUGIN_DIR') && is_dir(WP_PLUGIN_DIR)) {
            $roots[] = wp_normalize_path(WP_PLUGIN_DIR);
        }
        $theme_root = get_theme_root();
        if (is_string($theme_root) && is_dir($theme_root)) {
            $roots[] = wp_normalize_path($theme_root);
        }
        return array_values(array_unique($roots));
    }

    /**
     * Scope frozen for the active job, otherwise the saved allow-list.
     *
     * @return array
     */
    private static function scope_for_scan() {
        $job = self::get_job();
        $raw = get_option(self::OPTION, array());
        $frozen = is_array($raw) && array_key_exists('scope_enabled', $raw);
        if ($frozen && in_array($job['status'], array('counting', 'running'), true)) {
            return array(
                'enabled' => !empty($job['scope_enabled']) ? 1 : 0,
                'targets' => is_array($job['scope_targets']) ? $job['scope_targets'] : array(),
            );
        }
        return self::get_scope();
    }

    /**
     * Absolute plugin or theme path for a target id.
     *
     * @param string $id Target id such as plugin:woocommerce.
     * @return string
     */
    private static function path_for_target($id) {
        $id = (string) $id;
        if (strpos($id, 'plugin:') === 0) {
            $slug = substr($id, 7);
            $base = defined('WP_PLUGIN_DIR') ? WP_PLUGIN_DIR : '';
        } elseif (strpos($id, 'theme:') === 0) {
            $slug = substr($id, 6);
            $base = get_theme_root();
        } else {
            return '';
        }

        $slug = wp_normalize_path($slug);
        $slug = ltrim($slug, '/');
        if ($slug === '' || strpos($slug, '..') !== false || $base === '' || !is_string($base)) {
            return '';
        }

        $base = wp_normalize_path($base);
        $path = wp_normalize_path($base . '/' . $slug);
        if (!self::is_under_root($path, trailingslashit($base))) {
            return '';
        }
        if (is_dir($path) || is_file($path)) {
            return $path;
        }

        return '';
    }

    /**
     * @param resource $handle List file handle.
     * @param string   $root   Absolute root directory.
     * @param int      $already Number of files already written.
     * @return int
     */
    private static function write_root_files($handle, $root, $already) {
        $written = 0;
        $root = wp_normalize_path($root);

        if (is_file($root)) {
            if (self::is_scan_extension($root) && !self::path_is_excluded($root)) {
                fwrite($handle, $root . "\n");
                return 1;
            }
            return 0;
        }

        if (!is_dir($root)) {
            return 0;
        }

        $root = trailingslashit($root);

        try {
            $directory = new RecursiveDirectoryIterator(
                $root,
                FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO
            );
            $filtered = new RecursiveCallbackFilterIterator(
                $directory,
                array(__CLASS__, 'filter_node')
            );
            $iterator = new RecursiveIteratorIterator($filtered, RecursiveIteratorIterator::LEAVES_ONLY);
        } catch (Exception $e) {
            return 0;
        }

        foreach ($iterator as $fileinfo) {
            if (self::was_cancelled()) {
                break;
            }
            if (!($fileinfo instanceof SplFileInfo) || !$fileinfo->isFile()) {
                continue;
            }

            $path = wp_normalize_path($fileinfo->getPathname());
            if (!self::is_under_root($path, $root) || !self::is_scan_extension($path) || self::path_is_excluded($path)) {
                continue;
            }

            fwrite($handle, $path . "\n");
            $written++;
            if (($already + $written) >= self::MAX_FILES) {
                break;
            }
        }

        return $written;
    }

    /**
     * @param SplFileInfo $current Current node.
     * @return bool
     */
    public static function filter_node($current) {
        if (!($current instanceof SplFileInfo)) {
            return false;
        }
        if ($current->isLink()) {
            return false;
        }
        if (self::path_is_excluded($current->getPathname())) {
            return false;
        }
        if ($current->isDir()) {
            return true;
        }
        return $current->isFile();
    }

    /**
     * Rules frozen for the active job, otherwise the saved skip list.
     *
     * @return array
     */
    private static function exclusion_rules() {
        if (is_array(self::$exclusion_rules)) {
            return self::$exclusion_rules;
        }

        $job = self::get_job();
        $raw = get_option(self::OPTION, array());
        $frozen = is_array($raw) && array_key_exists('exclusions', $raw);
        if ($frozen && in_array($job['status'], array('counting', 'running'), true)) {
            $source = is_array($job['exclusions']) ? $job['exclusions'] : array();
        } else {
            $source = self::get_exclusions();
        }

        $rules = array();
        foreach ($source as $rule) {
            $rule = strtolower(trim(wp_normalize_path((string) $rule), '/'));
            if ($rule !== '') {
                $rules[] = $rule;
            }
        }
        self::$exclusion_rules = $rules;
        return $rules;
    }

    /**
     * Whether a file or folder path matches a skip rule.
     *
     * @param string $path Absolute or relative path.
     * @return bool
     */
    private static function path_is_excluded($path) {
        $path = strtolower(wp_normalize_path((string) $path));
        if ($path === '') {
            return false;
        }

        $parts = array_values(array_filter(explode('/', $path), 'strlen'));
        $haystack = '/' . implode('/', $parts) . '/';

        foreach (self::exclusion_rules() as $rule) {
            if (strpos($rule, '/') === false) {
                if (in_array($rule, $parts, true)) {
                    return true;
                }
                continue;
            }
            if (strpos($haystack, '/' . $rule . '/') !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $path Absolute file path.
     * @param string $root Root directory with trailing slash.
     * @return bool
     */
    private static function is_under_root($path, $root) {
        $path = wp_normalize_path($path);
        $root = wp_normalize_path($root);
        if (DIRECTORY_SEPARATOR === '\\') {
            return stripos($path, $root) === 0;
        }
        return strpos($path, $root) === 0;
    }

    /**
     * @param string $path File path.
     * @return bool
     */
    private static function is_scan_extension($path) {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        return in_array(
            $ext,
            array('php', 'js', 'mjs', 'cjs', 'css', 'scss', 'less', 'html', 'htm', 'json', 'svg', 'xml', 'vue', 'ts', 'tsx', 'jsx', 'twig'),
            true
        );
    }

    /**
     * @param string $path Absolute file path.
     * @return int Number of stored findings.
     */
    private static function scan_file($path) {
        if (!is_readable($path) || !self::is_scan_extension($path) || self::path_is_excluded($path)) {
            return 0;
        }

        $size = filesize($path);
        if (!is_int($size) || $size <= 0 || $size > self::MAX_FILE_BYTES) {
            return 0;
        }

        $content = file_get_contents($path);
        if (!is_string($content) || $content === '') {
            return 0;
        }

        $urls = self::extract_urls($content);
        if (!$urls) {
            return 0;
        }

        $source_ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $detected_from = self::detected_from_path($path);
        $page = self::page_from_path($path);
        $stored = 0;

        foreach ($urls as $url) {
            $origin = ASH_CSP_Normalizer::origin_from_url($url);
            if ($origin === '' || self::is_noise_origin($origin)) {
                continue;
            }

            $directive = self::classify_url($url, $source_ext);
            $item = array(
                'origin' => $origin,
                'directive' => $directive,
                'resource_type' => $directive,
                'method' => 'disk',
                'page' => $page,
                'detected_from' => $detected_from,
            );
            if (ASH_CSP_Repository::upsert($item)) {
                $stored++;
            }
        }

        return $stored;
    }

    /**
     * @param string $content File contents.
     * @return array
     */
    private static function extract_urls($content) {
        $content = str_replace('\\/', '/', $content);
        $found = array();

        if (preg_match_all('#https?://[^\s\'"<>\\\\]+#i', $content, $matches)) {
            $found = $matches[0];
        }
        if (preg_match_all('#(?<=[\'"])//(?:[a-z0-9-]+\.)+[a-z]{2,}[^\'"\s<>]*#i', $content, $relative)) {
            $found = array_merge($found, $relative[0]);
        }

        $urls = array();
        foreach ($found as $raw) {
            $url = rtrim((string) $raw, '.,);]}');
            if ($url === '' || strpos($url, 'data:') === 0) {
                continue;
            }
            $urls[$url] = true;
        }

        return array_keys($urls);
    }

    /**
     * @param string $url        Raw URL.
     * @param string $source_ext Extension of the scanned file.
     * @return string
     */
    private static function classify_url($url, $source_ext) {
        $path = (string) wp_parse_url($url, PHP_URL_PATH);
        $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        $by_ext = array(
            'js' => 'script-src',
            'mjs' => 'script-src',
            'cjs' => 'script-src',
            'css' => 'style-src',
            'scss' => 'style-src',
            'less' => 'style-src',
            'woff' => 'font-src',
            'woff2' => 'font-src',
            'ttf' => 'font-src',
            'otf' => 'font-src',
            'eot' => 'font-src',
            'png' => 'img-src',
            'jpg' => 'img-src',
            'jpeg' => 'img-src',
            'gif' => 'img-src',
            'webp' => 'img-src',
            'svg' => 'img-src',
            'ico' => 'img-src',
            'avif' => 'img-src',
            'mp4' => 'media-src',
            'webm' => 'media-src',
            'ogg' => 'media-src',
            'mp3' => 'media-src',
        );
        if (isset($by_ext[$ext])) {
            return $by_ext[$ext];
        }

        $host = strtolower((string) wp_parse_url($url, PHP_URL_HOST));
        if ($host !== '') {
            if (strpos($host, 'fonts.googleapis.com') !== false || strpos($host, 'fonts.gstatic.com') !== false) {
                return 'font-src';
            }
            if (preg_match('/(^|\.)(youtube\.com|youtu\.be|vimeo\.com)$/', $host)) {
                return 'frame-src';
            }
        }

        if (in_array($source_ext, array('js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx'), true)) {
            return 'script-src';
        }
        if (in_array($source_ext, array('css', 'scss', 'less'), true)) {
            return 'style-src';
        }

        return 'unknown';
    }

    /**
     * Drop documentation and placeholder hosts that are not runtime CSP sources.
     *
     * @param string $origin Normalized origin.
     * @return bool
     */
    private static function is_noise_origin($origin) {
        $host = strtolower((string) wp_parse_url($origin, PHP_URL_HOST));
        if ($host === '') {
            return true;
        }

        $blocked = array(
            'example.com',
            'example.org',
            'example.net',
            'localhost',
            '127.0.0.1',
            'w3.org',
            'www.w3.org',
            'schema.org',
            'www.schema.org',
            'purl.org',
            'json-schema.org',
            'gnu.org',
            'www.gnu.org',
            'opensource.org',
            'www.opensource.org',
            'php.net',
            'www.php.net',
        );

        return in_array($host, $blocked, true);
    }

    /**
     * @param string $path Absolute path.
     * @return string
     */
    private static function detected_from_path($path) {
        $path = wp_normalize_path($path);
        if (preg_match('#/plugins/([^/]+)/#', $path, $match)) {
            return $match[1];
        }
        if (preg_match('#/themes/([^/]+)/#', $path, $match)) {
            return $match[1];
        }
        return '';
    }

    /**
     * @param string $path Absolute path.
     * @return string
     */
    private static function page_from_path($path) {
        $path = wp_normalize_path($path);
        foreach (array('/plugins/', '/themes/') as $needle) {
            $pos = strpos($path, $needle);
            if ($pos !== false) {
                return ASH_CSP_Normalizer::page_path(substr($path, $pos));
            }
        }
        return ASH_CSP_Normalizer::page_path(basename($path));
    }
}
