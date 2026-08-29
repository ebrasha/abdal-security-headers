<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-csp-assistant.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 05:17:35
 * Description : Hybrid Smart CSP Assistant orchestrator, learning mode, and apply flow
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

class ASH_CSP_Assistant {
    const STATE_OPTION = 'ash_csp_assistant_state';
    const RATE_LIMIT = 40;
    const OPTION_MAP = array(
        'script-src' => 'csp_script_src',
        'style-src' => 'csp_style_src',
        'img-src' => 'csp_img_src',
        'font-src' => 'csp_font_src',
        'connect-src' => 'csp_connect_src',
        'frame-src' => 'csp_frame_src',
        'media-src' => 'csp_media_src',
        'worker-src' => 'csp_worker_src',
        'form-action' => 'csp_form_action',
        'base-uri' => 'csp_base_uri',
        'object-src' => 'csp_object_src',
        'default-src' => 'csp_default_src',
    );

    private static $booted = false;
    private static $instance = null;

    /**
     * @return self
     */
    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function __construct() {
        if (self::$booted) {
            return;
        }
        self::$booted = true;
        self::$instance = $this;

        ASH_CSP_Repository::maybe_install();
        if (!wp_next_scheduled('ash_csp_assistant_cron')) {
            wp_schedule_event(time() + 120, 'hourly', 'ash_csp_assistant_cron');
        }

        add_action('init', array($this, 'maybe_expire_learning'));
        add_action('ash_csp_assistant_cron', array($this, 'cron_tick'));
        add_action('send_headers', array($this, 'send_report_only_header'), 2);
        add_action('wp_enqueue_scripts', array($this, 'enqueue_runtime_observer'), 5);
        add_action('login_enqueue_scripts', array($this, 'enqueue_runtime_observer'), 5);
        add_action('wp_footer', array($this, 'collect_frontend_static'), 9999);
        add_action('login_footer', array($this, 'collect_frontend_static'), 9999);

        add_action('wp_ajax_ash_csp_assistant_state', array($this, 'ajax_state'));
        add_action('wp_ajax_ash_csp_assistant_start', array($this, 'ajax_start'));
        add_action('wp_ajax_ash_csp_assistant_stop', array($this, 'ajax_stop'));
        add_action('wp_ajax_ash_csp_assistant_ignore', array($this, 'ajax_ignore'));
        add_action('wp_ajax_ash_csp_assistant_apply', array($this, 'ajax_apply'));
        add_action('wp_ajax_ash_csp_assistant_diff', array($this, 'ajax_diff'));
        add_action('wp_ajax_ash_csp_assistant_clear', array($this, 'ajax_clear'));
        add_action('wp_ajax_ash_csp_assistant_details', array($this, 'ajax_details'));
        add_action('wp_ajax_ash_csp_assistant_continuous', array($this, 'ajax_continuous'));

        add_action('wp_ajax_ash_csp_report', array($this, 'ajax_report'));
        add_action('wp_ajax_nopriv_ash_csp_report', array($this, 'ajax_report'));
        add_action('wp_ajax_ash_csp_runtime', array($this, 'ajax_runtime'));
        add_action('wp_ajax_nopriv_ash_csp_runtime', array($this, 'ajax_runtime'));
    }

    /**
     * @return array
     */
    public static function default_state() {
        return array(
            'status' => 'not_scanned',
            'duration' => '1hour',
            'started_at' => '',
            'ends_at' => '',
            'token' => '',
            'continuous_monitoring' => 0,
            'last_review_at' => '',
        );
    }

    /**
     * @return array
     */
    public static function get_state() {
        $state = get_option(self::STATE_OPTION, array());
        if (!is_array($state)) {
            $state = array();
        }
        return array_merge(self::default_state(), $state);
    }

    /**
     * @param array $state State values.
     * @return void
     */
    public static function save_state($state) {
        update_option(self::STATE_OPTION, array_merge(self::get_state(), $state), false);
    }

    /**
     * Observation is active during timed learning or optional continuous monitoring.
     *
     * @return bool
     */
    public static function is_observing() {
        $state = self::get_state();
        if ($state['status'] === 'learning') {
            return true;
        }
        return !empty($state['continuous_monitoring']) && $state['status'] !== 'not_scanned';
    }

    /**
     * @return bool
     */
    public static function is_learning() {
        return self::get_state()['status'] === 'learning';
    }

    /**
     * Stop learning when the selected duration has elapsed.
     *
     * @return void
     */
    public function maybe_expire_learning() {
        $state = self::get_state();
        if ($state['status'] !== 'learning' || $state['duration'] === 'manual' || $state['ends_at'] === '') {
            return;
        }
        if (time() >= (int) $state['ends_at']) {
            self::complete_learning();
        }
    }

    /**
     * @return void
     */
    public function cron_tick() {
        $this->maybe_expire_learning();
        ASH_CSP_Repository::expire_old();
    }

    /**
     * Send Content-Security-Policy-Report-Only while observing, without blocking.
     *
     * @return void
     */
    public function send_report_only_header() {
        if (headers_sent() || !self::is_observing() || $this->is_admin_request()) {
            return;
        }

        if (self::is_learning()) {
            header_remove('Content-Security-Policy');
            header_remove('X-Content-Security-Policy');
            header_remove('X-WebKit-CSP');
        }

        $policy = $this->build_report_only_policy();
        if ($policy !== '') {
            @header('Content-Security-Policy-Report-Only: ' . $policy);
        }
    }

    /**
     * @return void
     */
    public function enqueue_runtime_observer() {
        if (!self::is_observing() || $this->is_admin_request()) {
            return;
        }

        $state = self::get_state();
        $path = ASH_PLUGIN_DIR . 'assets/js/csp-runtime-observer.js';
        $version = file_exists($path) ? (string) filemtime($path) : ASH_VERSION;

        wp_enqueue_script(
            'ash-csp-runtime-observer',
            ASH_PLUGIN_URL . 'assets/js/csp-runtime-observer.js',
            array(),
            $version,
            true
        );

        wp_localize_script('ash-csp-runtime-observer', 'ashCspObserver', array(
            'enabled' => true,
            'endpoint' => admin_url('admin-ajax.php'),
            'token' => $state['token'],
            'page' => ASH_CSP_Normalizer::page_path(isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/'),
        ));
    }

    /**
     * Snapshot actually enqueued frontend assets during observation.
     *
     * @return void
     */
    public function collect_frontend_static() {
        if (!self::is_observing() || $this->is_admin_request()) {
            return;
        }
        $page = ASH_CSP_Normalizer::page_path(isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/');
        ASH_CSP_Static_Detector::collect($page, true);
    }

    /**
     * @return void
     */
    public function ajax_state() {
        $this->require_admin();
        wp_send_json_success($this->payload());
    }

    /**
     * @return void
     */
    public function ajax_start() {
        $this->require_admin();
        $duration = isset($_POST['duration']) ? sanitize_key(wp_unslash($_POST['duration'])) : '1hour';
        $allowed = array('15min', '1hour', '6hours', '24hours', 'manual');
        if (!in_array($duration, $allowed, true)) {
            $duration = '1hour';
        }

        $now = time();
        $ends = 0;
        if ($duration === '15min') {
            $ends = $now + 15 * MINUTE_IN_SECONDS;
        } elseif ($duration === '1hour') {
            $ends = $now + HOUR_IN_SECONDS;
        } elseif ($duration === '6hours') {
            $ends = $now + 6 * HOUR_IN_SECONDS;
        } elseif ($duration === '24hours') {
            $ends = $now + DAY_IN_SECONDS;
        }

        self::save_state(array(
            'status' => 'learning',
            'duration' => $duration,
            'started_at' => (string) $now,
            'ends_at' => $ends ? (string) $ends : '',
            'token' => wp_generate_password(32, false, false),
        ));

        ASH_CSP_Static_Detector::collect('/', false);
        wp_send_json_success($this->payload());
    }

    /**
     * @return void
     */
    public function ajax_stop() {
        $this->require_admin();
        self::complete_learning();
        wp_send_json_success($this->payload());
    }

    /**
     * @return void
     */
    public function ajax_ignore() {
        $this->require_admin();
        $id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
        if ($id <= 0 || !ASH_CSP_Repository::set_status($id, 'ignored')) {
            wp_send_json_error(array('message' => __('Unable to ignore this source.', 'abdal-security-headers')));
        }
        wp_send_json_success($this->payload());
    }

    /**
     * @return void
     */
    public function ajax_details() {
        $this->require_admin();
        $id = isset($_POST['id']) ? (int) $_POST['id'] : 0;
        $row = ASH_CSP_Repository::get_source($id);
        if (!$row) {
            wp_send_json_error(array('message' => __('Source not found.', 'abdal-security-headers')));
        }
        wp_send_json_success($this->format_source($row));
    }

    /**
     * Saved plugin options used to compare discovered origins against CSP fields.
     *
     * @return array
     */
    private function plugin_options() {
        $options = get_option('ash_options', array());
        return is_array($options) ? $options : array();
    }

    /**
     * Whether a discovered origin is already present in the matching CSP field.
     *
     * @param array $row Database row.
     * @param array $options Saved plugin options.
     * @return bool
     */
    private function source_in_policy($row, $options) {
        $directive = isset($row['directive']) ? $row['directive'] : '';
        $origin = isset($row['origin']) ? $row['origin'] : '';
        if ($directive === '' || $directive === 'unknown' || $origin === '') {
            return false;
        }

        if (isset(self::OPTION_MAP[$directive])) {
            $option_key = self::OPTION_MAP[$directive];
            $value = isset($options[$option_key]) ? (string) $options[$option_key] : '';
            if (ASH_CSP_Normalizer::policy_covers_origin($value, $origin)) {
                return true;
            }
            if (trim($value) !== '' || $directive === 'default-src') {
                return false;
            }
        }

        $default = isset($options['csp_default_src']) ? (string) $options['csp_default_src'] : '';
        return ASH_CSP_Normalizer::policy_covers_origin($default, $origin);
    }

    /**
     * @return void
     */
    public function ajax_diff() {
        $this->require_admin();
        $ids = isset($_POST['ids']) ? (array) $_POST['ids'] : array();
        wp_send_json_success(array(
            'diff' => $this->build_diff($ids),
        ));
    }

    /**
     * Merge selected origins into existing CSP options. Current values are never replaced.
     *
     * @return void
     */
    public function ajax_apply() {
        $this->require_admin();
        $ids = isset($_POST['ids']) ? (array) $_POST['ids'] : array();
        $confirm_dangerous = !empty($_POST['confirm_dangerous']);
        $diff = $this->build_diff($ids);

        if (empty($diff['changes'])) {
            wp_send_json_error(array('message' => __('No eligible sources were selected.', 'abdal-security-headers')));
        }

        if ($diff['has_dangerous'] && !$confirm_dangerous) {
            wp_send_json_error(array(
                'message' => __('Dangerous CSP values require explicit confirmation.', 'abdal-security-headers'),
                'diff' => $diff,
            ));
        }

        $options = get_option('ash_options', array());
        if (!is_array($options)) {
            $options = array();
        }

        foreach ($diff['changes'] as $change) {
            if (empty($change['option']) || empty($change['proposed'])) {
                continue;
            }
            if (!empty($change['dangerous']) && !$confirm_dangerous) {
                continue;
            }
            $options[$change['option']] = $change['proposed'];
        }

        update_option('ash_options', $options);

        foreach ($diff['applied_ids'] as $id) {
            ASH_CSP_Repository::set_status((int) $id, 'applied');
        }

        $payload = $this->payload();
        $payload['updated_options'] = array();
        foreach ($diff['changes'] as $change) {
            $payload['updated_options'][$change['option']] = $change['proposed'];
        }
        $payload['message'] = __('Selected sources were merged into your current CSP directives.', 'abdal-security-headers');
        wp_send_json_success($payload);
    }

    /**
     * @return void
     */
    public function ajax_clear() {
        $this->require_admin();
        ASH_CSP_Repository::clear_all();
        self::save_state(self::default_state());
        wp_send_json_success($this->payload());
    }

    /**
     * @return void
     */
    public function ajax_continuous() {
        $this->require_admin();
        $enabled = !empty($_POST['enabled']) ? 1 : 0;
        $state = array('continuous_monitoring' => $enabled);
        if ($enabled && self::get_state()['token'] === '') {
            $state['token'] = wp_generate_password(32, false, false);
        }
        if ($enabled && self::get_state()['status'] === 'not_scanned') {
            $state['status'] = 'monitoring';
        }
        self::save_state($state);
        wp_send_json_success($this->payload());
    }

    /**
     * Accept CSP Report-Only violation reports. Stores origins only.
     *
     * @return void
     */
    public function ajax_report() {
        if (!self::is_observing() || !$this->allow_ingest()) {
            status_header(204);
            exit;
        }

        $raw = file_get_contents('php://input');
        if (!is_string($raw) || $raw === '') {
            status_header(204);
            exit;
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            status_header(204);
            exit;
        }

        $report = array();
        if (isset($data['csp-report']) && is_array($data['csp-report'])) {
            $report = $data['csp-report'];
        } elseif (isset($data['body']) && is_array($data['body'])) {
            $report = $data['body'];
        } elseif (isset($data[0]['body']) && is_array($data[0]['body'])) {
            $report = $data[0]['body'];
        }

        $blocked = '';
        if (isset($report['blocked-uri'])) {
            $blocked = (string) $report['blocked-uri'];
        } elseif (isset($report['blockedURL'])) {
            $blocked = (string) $report['blockedURL'];
        }

        $directive_raw = '';
        if (isset($report['effective-directive'])) {
            $directive_raw = (string) $report['effective-directive'];
        } elseif (isset($report['effectiveDirective'])) {
            $directive_raw = (string) $report['effectiveDirective'];
        } elseif (isset($report['violated-directive'])) {
            $directive_raw = (string) $report['violated-directive'];
        } elseif (isset($report['violatedDirective'])) {
            $directive_raw = (string) $report['violatedDirective'];
        }

        $document = '';
        if (isset($report['document-uri'])) {
            $document = (string) $report['document-uri'];
        } elseif (isset($report['documentURL'])) {
            $document = (string) $report['documentURL'];
        }

        $origin = ASH_CSP_Normalizer::origin_from_url($blocked);
        $directive = ASH_CSP_Normalizer::classify($directive_raw);
        if ($origin === '') {
            status_header(204);
            exit;
        }

        ASH_CSP_Repository::upsert(array(
            'origin' => $origin,
            'directive' => $directive,
            'resource_type' => $directive_raw !== '' ? sanitize_key($directive_raw) : 'report',
            'method' => 'report-only',
            'page' => ASH_CSP_Normalizer::page_path($document),
            'detected_from' => '',
        ));

        status_header(204);
        exit;
    }

    /**
     * Accept runtime observer batches. Origins only, no full URLs.
     *
     * @return void
     */
    public function ajax_runtime() {
        if (!self::is_observing() || !$this->allow_ingest()) {
            status_header(204);
            exit;
        }

        $state = self::get_state();
        $token = isset($_POST['token']) ? sanitize_text_field(wp_unslash($_POST['token'])) : '';
        if ($state['token'] === '' || !hash_equals($state['token'], $token)) {
            status_header(403);
            exit;
        }

        $items = isset($_POST['items']) ? wp_unslash($_POST['items']) : array();
        if (is_string($items)) {
            $decoded = json_decode($items, true);
            $items = is_array($decoded) ? $decoded : array();
        }
        if (!is_array($items)) {
            status_header(204);
            exit;
        }

        $page = isset($_POST['page']) ? ASH_CSP_Normalizer::page_path(wp_unslash($_POST['page'])) : '/';
        $items = array_slice($items, 0, 20);

        foreach ($items as $item) {
            if (!is_array($item) || empty($item['origin'])) {
                continue;
            }
            $origin = ASH_CSP_Normalizer::origin_from_url($item['origin']);
            $type = isset($item['type']) ? sanitize_key($item['type']) : '';
            $directive = ASH_CSP_Normalizer::classify($type);
            if ($origin === '') {
                continue;
            }
            ASH_CSP_Repository::upsert(array(
                'origin' => $origin,
                'directive' => $directive,
                'resource_type' => $type,
                'method' => 'runtime',
                'page' => $page,
                'detected_from' => '',
            ));
        }

        status_header(204);
        exit;
    }

    /**
     * Render the assistant card above the manual CSP editor.
     *
     * @return void
     */
    public static function render_admin_card() {
        $payload = self::instance()->payload();
        $strings = self::ui_strings();
        $durations = array(
            '15min' => $strings['duration15'],
            '1hour' => $strings['duration1h'],
            '6hours' => $strings['duration6h'],
            '24hours' => $strings['duration24h'],
            'manual' => $strings['durationManual'],
        );
        ?>
        <section class="ash-card ash-card--assistant" data-ash-assistant>
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-visibility" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html($strings['title']); ?></h2>
                    <p><?php echo esc_html($strings['subtitle']); ?></p>
                </div>
                <span class="ash-badge ash-badge--neutral"><?php echo esc_html($strings['hybrid']); ?></span>
            </header>

            <div class="ash-assistant__body">
                <div class="ash-assistant__status-row">
                    <div>
                        <span class="ash-assistant__label"><?php echo esc_html($strings['currentStatus']); ?></span>
                        <strong class="ash-assistant__status" data-ash-assistant-status><?php echo esc_html($payload['status_label']); ?></strong>
                    </div>
                    <div class="ash-assistant__controls">
                        <div class="ash-assistant__duration">
                            <span id="ash-assistant-duration-label" class="ash-assistant__duration-label"><?php echo esc_html($strings['duration']); ?></span>
                            <div class="ash-segmented" role="radiogroup" aria-labelledby="ash-assistant-duration-label">
                                <?php
                                $current_duration = !empty($payload['state']['duration']) ? $payload['state']['duration'] : '1hour';
                                foreach ($durations as $value => $label) :
                                    ?>
                                    <label class="ash-segmented__item">
                                        <input type="radio"
                                               name="ash_csp_assistant_duration"
                                               value="<?php echo esc_attr($value); ?>"
                                               data-ash-assistant-duration
                                               <?php checked($current_duration, $value); ?>>
                                        <span class="ash-segmented__text"><?php echo esc_html($label); ?></span>
                                    </label>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <button type="button" class="ash-btn ash-btn--primary" data-ash-assistant-start>
                            <span class="dashicons dashicons-search" aria-hidden="true"></span>
                            <?php echo esc_html($strings['startScan']); ?>
                            <span class="ash-spinner" aria-hidden="true"></span>
                        </button>
                        <button type="button" class="ash-btn ash-btn--secondary" data-ash-assistant-stop hidden>
                            <span class="dashicons dashicons-no" aria-hidden="true"></span>
                            <?php echo esc_html($strings['stopLearning']); ?>
                            <span class="ash-spinner" aria-hidden="true"></span>
                        </button>
                    </div>
                </div>

                <p class="ash-assistant__learning" data-ash-assistant-learning hidden>
                    <?php echo esc_html($strings['learningActive']); ?>
                    <span data-ash-assistant-count>0</span>
                    <?php echo esc_html($strings['sourcesObserved']); ?>
                </p>

                <label class="ash-assistant__continuous">
                    <input type="checkbox" data-ash-assistant-continuous <?php checked(!empty($payload['state']['continuous_monitoring'])); ?>>
                    <span><?php echo esc_html($strings['continuous']); ?></span>
                </label>

                <div class="ash-assistant__banner" data-ash-assistant-new hidden>
                    <strong><?php echo esc_html($strings['newDetected']); ?></strong>
                    <span data-ash-assistant-new-count>0</span>
                </div>

                <div class="ash-assistant__summary" data-ash-assistant-summary></div>

                <div class="ash-assistant__table-wrap">
                    <table class="ash-assistant-table">
                        <thead>
                            <tr>
                                <th scope="col"><input type="checkbox" data-ash-assistant-check-all aria-label="<?php echo esc_attr($strings['selectAll']); ?>"></th>
                                <th scope="col"><?php echo esc_html($strings['colSource']); ?></th>
                                <th scope="col"><?php echo esc_html($strings['colDirective']); ?></th>
                                <th scope="col"><?php echo esc_html($strings['colMethod']); ?></th>
                                <th scope="col"><?php echo esc_html($strings['colDetectedOn']); ?></th>
                                <th scope="col"><?php echo esc_html($strings['colConfidence']); ?></th>
                                <th scope="col"><?php echo esc_html($strings['colStatus']); ?></th>
                                <th scope="col"><?php echo esc_html($strings['colAction']); ?></th>
                            </tr>
                        </thead>
                        <tbody data-ash-assistant-rows>
                            <tr>
                                <td colspan="8"><?php echo esc_html($strings['empty']); ?></td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="ash-assistant__actions">
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-assistant-review>
                        <?php echo esc_html($strings['review']); ?>
                    </button>
                    <button type="button" class="ash-btn ash-btn--primary" data-ash-assistant-apply>
                        <?php echo esc_html($strings['applySelected']); ?>
                        <span class="ash-spinner" aria-hidden="true"></span>
                    </button>
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-assistant-clear>
                        <?php echo esc_html($strings['clearData']); ?>
                        <span class="ash-spinner" aria-hidden="true"></span>
                    </button>
                </div>
            </div>
        </section>

        <div class="ash-modal" id="ash-assistant-modal" hidden>
            <div class="ash-modal__backdrop" data-ash-assistant-modal-dismiss></div>
            <div class="ash-modal__dialog ash-assistant-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="ash-assistant-modal-title">
                <h2 id="ash-assistant-modal-title"></h2>
                <div class="ash-assistant-modal__body" id="ash-assistant-modal-body"></div>
                <div class="ash-modal__actions">
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-assistant-modal-cancel>
                        <?php echo esc_html($strings['cancel']); ?>
                    </button>
                    <button type="button" class="ash-btn ash-btn--primary" data-ash-assistant-modal-confirm hidden>
                        <?php echo esc_html($strings['apply']); ?>
                        <span class="ash-spinner" aria-hidden="true"></span>
                    </button>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * @return array
     */
    public static function ui_strings() {
        return array(
            'title' => __('Smart CSP Assistant', 'abdal-security-headers'),
            'subtitle' => __('Automatically discover the resources used by your site and generate CSP recommendations.', 'abdal-security-headers'),
            'hybrid' => __('Hybrid Detection', 'abdal-security-headers'),
            'currentStatus' => __('Current Status', 'abdal-security-headers'),
            'notScanned' => __('Not scanned', 'abdal-security-headers'),
            'learning' => __('Learning', 'abdal-security-headers'),
            'analysisComplete' => __('Analysis complete', 'abdal-security-headers'),
            'monitoring' => __('Monitoring', 'abdal-security-headers'),
            'startScan' => __('Start Smart Scan', 'abdal-security-headers'),
            'learningActive' => __('Learning Mode Active', 'abdal-security-headers'),
            'stopLearning' => __('Stop Learning', 'abdal-security-headers'),
            'duration' => __('Learning duration', 'abdal-security-headers'),
            'duration15' => __('15 Minutes', 'abdal-security-headers'),
            'duration1h' => __('1 Hour', 'abdal-security-headers'),
            'duration6h' => __('6 Hours', 'abdal-security-headers'),
            'duration24h' => __('24 Hours', 'abdal-security-headers'),
            'durationManual' => __('Manual', 'abdal-security-headers'),
            'sourcesObserved' => __('sources observed', 'abdal-security-headers'),
            'continuous' => __('Keep watching for new sources after learning completes.', 'abdal-security-headers'),
            'newDetected' => __('New CSP Source Detected', 'abdal-security-headers'),
            'review' => __('Review Suggestions', 'abdal-security-headers'),
            'applySelected' => __('Apply Selected Sources', 'abdal-security-headers'),
            'clearData' => __('Clear Learning Data', 'abdal-security-headers'),
            'colSource' => __('Source', 'abdal-security-headers'),
            'colDirective' => __('Directive', 'abdal-security-headers'),
            'colMethod' => __('Detection Method', 'abdal-security-headers'),
            'colDetectedOn' => __('Detected On', 'abdal-security-headers'),
            'colConfidence' => __('Confidence', 'abdal-security-headers'),
            'colStatus' => __('Status', 'abdal-security-headers'),
            'colAction' => __('Action', 'abdal-security-headers'),
            'add' => __('Add', 'abdal-security-headers'),
            'ignore' => __('Ignore', 'abdal-security-headers'),
            'details' => __('Details', 'abdal-security-headers'),
            'empty' => __('No sources detected yet. Start a Smart Scan to begin discovery.', 'abdal-security-headers'),
            'selectAll' => __('Select all sources', 'abdal-security-headers'),
            'methodStatic' => __('Static', 'abdal-security-headers'),
            'methodReport' => __('Report-Only', 'abdal-security-headers'),
            'methodRuntime' => __('Runtime', 'abdal-security-headers'),
            'trusted' => __('Trusted', 'abdal-security-headers'),
            'likelySafe' => __('Likely Safe', 'abdal-security-headers'),
            'unknown' => __('Unknown', 'abdal-security-headers'),
            'potentiallyRisky' => __('Potentially Risky', 'abdal-security-headers'),
            'statusNew' => __('New', 'abdal-security-headers'),
            'statusIgnored' => __('Ignored', 'abdal-security-headers'),
            'statusApplied' => __('Applied', 'abdal-security-headers'),
            'statusAdded' => __('Added', 'abdal-security-headers'),
            'statusWarning' => __('Warning', 'abdal-security-headers'),
            'origin' => __('Origin', 'abdal-security-headers'),
            'resourceType' => __('Resource Type', 'abdal-security-headers'),
            'detectionMethods' => __('Detection Methods', 'abdal-security-headers'),
            'firstSeen' => __('First Seen', 'abdal-security-headers'),
            'lastSeen' => __('Last Seen', 'abdal-security-headers'),
            'detectionCount' => __('Detection Count', 'abdal-security-headers'),
            'pagesDetected' => __('Pages Detected', 'abdal-security-headers'),
            'detectedFrom' => __('Detected from', 'abdal-security-headers'),
            'requiredDirective' => __('Required Directive', 'abdal-security-headers'),
            'policyDiff' => __('Policy Diff', 'abdal-security-headers'),
            'current' => __('Current', 'abdal-security-headers'),
            'proposed' => __('Proposed', 'abdal-security-headers'),
            'newToken' => __('New', 'abdal-security-headers'),
            'apply' => __('Apply', 'abdal-security-headers'),
            'cancel' => __('Cancel', 'abdal-security-headers'),
            'dangerousWarning' => __('This value can weaken your Content Security Policy. Confirm only if your site requires it.', 'abdal-security-headers'),
            'confirmDangerous' => __('I understand this weakens CSP and I want to add it anyway.', 'abdal-security-headers'),
            'confirmClear' => __('Clear all Smart CSP discovery data? This cannot be undone.', 'abdal-security-headers'),
            'noSelection' => __('Select at least one source to apply.', 'abdal-security-headers'),
            'unknownSkip' => __('Unknown resource types are kept for review and are not applied automatically.', 'abdal-security-headers'),
            'requestFailed' => __('The Smart CSP Assistant request failed. Please try again.', 'abdal-security-headers'),
            /* translators: %d: number of detected sources */
            'summaryTotal' => __('%d Sources Detected', 'abdal-security-headers'),
            /* translators: %d: number of script sources */
            'summaryScript' => __('%d Script Sources', 'abdal-security-headers'),
            /* translators: %d: number of style sources */
            'summaryStyle' => __('%d Style Sources', 'abdal-security-headers'),
            /* translators: %d: number of image sources */
            'summaryImg' => __('%d Image Sources', 'abdal-security-headers'),
            /* translators: %d: number of font sources */
            'summaryFont' => __('%d Font Sources', 'abdal-security-headers'),
            /* translators: %d: number of connect sources */
            'summaryConnect' => __('%d Connect Sources', 'abdal-security-headers'),
            /* translators: %d: number of frame sources */
            'summaryFrame' => __('%d Frame Sources', 'abdal-security-headers'),
            /* translators: %d: number of media sources */
            'summaryMedia' => __('%d Media Sources', 'abdal-security-headers'),
            /* translators: %d: number of worker sources */
            'summaryWorker' => __('%d Worker Sources', 'abdal-security-headers'),
            /* translators: %d: number of form destinations */
            'summaryForm' => __('%d Form Destinations', 'abdal-security-headers'),
            /* translators: %d: number of unknown sources */
            'summaryUnknown' => __('%d Unknown Sources', 'abdal-security-headers'),
        );
    }

    /**
     * @return array
     */
    public function payload() {
        $state = self::get_state();
        $summary = ASH_CSP_Repository::summary();
        $options = get_option('ash_options', array());
        if (!is_array($options)) {
            $options = array();
        }

        $sources = array();
        foreach (ASH_CSP_Repository::get_sources() as $row) {
            $sources[] = $this->format_source($row, $options);
        }

        $status_key = $state['status'];
        if (!empty($state['continuous_monitoring']) && $status_key === 'analysis_complete') {
            $status_key = 'monitoring';
        }

        $labels = self::ui_strings();
        $status_labels = array(
            'not_scanned' => $labels['notScanned'],
            'learning' => $labels['learning'],
            'analysis_complete' => $labels['analysisComplete'],
            'monitoring' => $labels['monitoring'],
        );

        return array(
            'state' => $state,
            'status_key' => $status_key,
            'status_label' => isset($status_labels[$status_key]) ? $status_labels[$status_key] : $labels['notScanned'],
            'observing' => self::is_observing(),
            'learning' => self::is_learning(),
            'summary' => $summary,
            'sources' => $sources,
            'count' => $summary['total'],
        );
    }

    /**
     * @param array      $row     Database row.
     * @param array|null $options Saved plugin options.
     * @return array
     */
    private function format_source($row, $options = null) {
        if (!is_array($options)) {
            $options = $this->plugin_options();
        }

        $pages = json_decode((string) $row['pages_detected'], true);
        if (!is_array($pages)) {
            $pages = array();
        }
        $methods = array_filter(explode(',', (string) $row['detection_methods']));
        $in_policy = $this->source_in_policy($row, $options);
        $db_status = $row['status'];
        $status = $in_policy ? 'added' : $db_status;

        return array(
            'id' => (int) $row['id'],
            'origin' => $row['origin'],
            'directive' => $row['directive'],
            'resource_type' => $row['resource_type'],
            'first_seen' => $row['first_seen'],
            'last_seen' => $row['last_seen'],
            'detection_count' => (int) $row['detection_count'],
            'detection_methods' => $methods,
            'pages_detected' => $pages,
            'detected_from' => $row['detected_from'],
            'confidence' => $row['confidence'],
            'status' => $status,
            'db_status' => $db_status,
            'in_policy' => $in_policy,
            'is_new' => (int) $row['is_new'],
            'dangerous' => ASH_CSP_Normalizer::is_dangerous($row['origin']),
            'selectable' => $row['directive'] !== 'unknown' && $db_status !== 'ignored' && !$in_policy,
        );
    }

    /**
     * @param array $ids Selected IDs.
     * @return array
     */
    private function build_diff($ids) {
        $options = get_option('ash_options', array());
        if (!is_array($options)) {
            $options = array();
        }

        $rows = ASH_CSP_Repository::get_sources_by_ids($ids);
        $grouped = array();
        $applied_ids = array();
        $has_dangerous = false;
        $skipped_unknown = false;

        foreach ($rows as $row) {
            if ($row['directive'] === 'unknown') {
                $skipped_unknown = true;
                continue;
            }
            if ($row['status'] === 'ignored') {
                continue;
            }
            if (!isset(self::OPTION_MAP[$row['directive']])) {
                continue;
            }
            if (ASH_CSP_Normalizer::is_dangerous($row['origin'])) {
                $has_dangerous = true;
            }
            $grouped[$row['directive']][] = $row;
            $applied_ids[] = (int) $row['id'];
        }

        $changes = array();
        foreach ($grouped as $directive => $items) {
            $option_key = self::OPTION_MAP[$directive];
            $current = isset($options[$option_key]) ? trim((string) $options[$option_key]) : '';
            $added = array();
            $proposed = $current;
            foreach ($items as $item) {
                $merged = self::merge_token($proposed, $item['origin']);
                if ($merged !== $proposed) {
                    $added[] = $item['origin'];
                    $proposed = $merged;
                }
            }
            if (empty($added)) {
                continue;
            }
            $changes[] = array(
                'directive' => $directive,
                'option' => $option_key,
                'current' => $current,
                'proposed' => $proposed,
                'added' => $added,
                'dangerous' => $has_dangerous && $this->list_has_dangerous($added),
            );
        }

        return array(
            'changes' => $changes,
            'applied_ids' => $applied_ids,
            'has_dangerous' => $has_dangerous,
            'skipped_unknown' => $skipped_unknown,
        );
    }

    /**
     * @param string $current Existing directive value.
     * @param string $token Token to merge.
     * @return string
     */
    public static function merge_token($current, $token) {
        $token = trim((string) $token);
        $current = trim((string) $current);
        if ($token === '') {
            return $current;
        }
        $needle = rtrim($token, '/');
        $parts = preg_split('/\s+/', $current, -1, PREG_SPLIT_NO_EMPTY);
        foreach ($parts as $part) {
            if (strcasecmp(rtrim($part, '/'), $needle) === 0) {
                return $current;
            }
        }
        return $current === '' ? $token : $current . ' ' . $token;
    }

    /**
     * @return string
     */
    private function build_report_only_policy() {
        $options = get_option('ash_options', array());
        if (!is_array($options)) {
            $options = array();
        }

        $directives = array();
        foreach (self::OPTION_MAP as $directive => $option_key) {
            if (!empty($options[$option_key])) {
                $directives[] = $directive . ' ' . trim((string) $options[$option_key]);
            }
        }

        if (empty($directives)) {
            $directives = array(
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self'",
                "img-src 'self' data:",
                "font-src 'self' data:",
                "connect-src 'self'",
                "frame-src 'self'",
                "media-src 'self'",
                "worker-src 'self'",
                "object-src 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            );
        }

        $report_uri = admin_url('admin-ajax.php') . '?action=ash_csp_report';
        $directives[] = 'report-uri ' . $report_uri;
        return implode('; ', $directives);
    }

    /**
     * @return void
     */
    private static function complete_learning() {
        $state = self::get_state();
        $status = !empty($state['continuous_monitoring']) ? 'monitoring' : 'analysis_complete';
        self::save_state(array(
            'status' => $status,
            'ends_at' => '',
            'last_review_at' => (string) time(),
        ));
    }

    /**
     * @return void
     */
    private function require_admin() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You are not allowed to manage these settings.', 'abdal-security-headers')), 403);
        }
        check_ajax_referer('ash_csp_assistant', 'nonce');
    }

    /**
     * @return bool
     */
    private function allow_ingest() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        $key = 'ash_csp_rl_' . md5($ip);
        $count = (int) get_transient($key);
        if ($count >= self::RATE_LIMIT) {
            return false;
        }
        set_transient($key, $count + 1, MINUTE_IN_SECONDS);
        return true;
    }

    /**
     * @return bool
     */
    private function is_admin_request() {
        if (is_admin() && !wp_doing_ajax()) {
            return true;
        }
        $request_uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        return $request_uri !== '' && strpos($request_uri, '/wp-admin/') !== false;
    }

    /**
     * @param array $tokens Origin list.
     * @return bool
     */
    private function list_has_dangerous($tokens) {
        foreach ($tokens as $token) {
            if (ASH_CSP_Normalizer::is_dangerous($token)) {
                return true;
            }
        }
        return false;
    }
}
