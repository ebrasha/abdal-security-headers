<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-dashboard-widget.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 15:21:41
 * Description : Registers the standard WordPress dashboard widget for security status
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

class ASH_Dashboard_Widget {
    const WIDGET_ID = 'ash_dashboard_widget';

    /**
     * Core HTTP security headers counted in the Active Headers metric.
     *
     * @var array
     */
    private $header_keys = array(
        'x_xss_protection',
        'x_content_type_options',
        'strict_transport_security',
        'permissions_policy',
        'x_frame_options',
        'referrer_policy',
    );

    /**
     * Additional hardening toggles used for overall security status.
     *
     * @var array
     */
    private $feature_keys = array(
        'remove_x_powered_by',
        'hide_wp_version',
        'remove_login_errors',
        'disable_xmlrpc',
        'remove_x_pingback',
        'restrict_rest_api',
    );

    public function __construct() {
        add_action('wp_dashboard_setup', array($this, 'register'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }

    /**
     * Register a normal dashboard widget. WordPress keeps drag, collapse, and placement.
     *
     * @return void
     */
    public function register() {
        if (!current_user_can('manage_options')) {
            return;
        }

        wp_add_dashboard_widget(
            self::WIDGET_ID,
            __('Abdal Security Headers', 'abdal-security-headers'),
            array($this, 'render')
        );
    }

    /**
     * Load widget CSS only on the main WordPress dashboard.
     *
     * @param string $hook Current admin page hook.
     * @return void
     */
    public function enqueue_assets($hook) {
        if ($hook !== 'index.php' || !current_user_can('manage_options')) {
            return;
        }

        $css_path = ASH_PLUGIN_DIR . 'assets/css/dashboard-widget.css';
        $css_version = file_exists($css_path) ? (string) filemtime($css_path) : ASH_VERSION;

        wp_enqueue_style(
            'ash-dashboard-widget',
            ASH_PLUGIN_URL . 'assets/css/dashboard-widget.css',
            array('dashicons'),
            $css_version
        );
    }

    /**
     * Render widget body. The postbox title is owned by WordPress.
     *
     * @return void
     */
    public function render() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $data = $this->collect();
        $settings_url = admin_url('admin.php?page=abdal-security-headers');
        $report_url = admin_url('admin.php?page=abdal-security-headers-csp') . '#ash-csp-assistant';
        $logo_url = ASH_PLUGIN_URL . 'assets/images/logo-200x200.png';
        $logo_path = ASH_PLUGIN_DIR . 'assets/images/logo-200x200.png';
        ?>
        <div class="ash-dash">
            <section class="ash-dash__status" aria-label="<?php echo esc_attr__('Security overview', 'abdal-security-headers'); ?>">
                <div class="ash-dash__status-item ash-dash__status-item--<?php echo esc_attr($data['security']['tone']); ?>">
                    <span class="ash-dash__status-icon" aria-hidden="true">
                        <span class="dashicons dashicons-shield"></span>
                    </span>
                    <div class="ash-dash__status-copy">
                        <span class="ash-dash__label"><?php echo esc_html__('Security status', 'abdal-security-headers'); ?></span>
                        <strong class="ash-dash__value"><?php echo esc_html($data['security']['label']); ?></strong>
                    </div>
                </div>
                <div class="ash-dash__status-item ash-dash__status-item--blue">
                    <span class="ash-dash__status-icon" aria-hidden="true">
                        <span class="dashicons dashicons-screenoptions"></span>
                    </span>
                    <div class="ash-dash__status-copy">
                        <span class="ash-dash__label"><?php echo esc_html__('Active headers', 'abdal-security-headers'); ?></span>
                        <strong class="ash-dash__value"><?php echo esc_html($data['headers_active'] . ' / ' . $data['headers_total']); ?></strong>
                    </div>
                </div>
                <div class="ash-dash__status-item ash-dash__status-item--<?php echo esc_attr($data['csp']['tone']); ?>">
                    <span class="ash-dash__status-icon" aria-hidden="true">
                        <span class="dashicons dashicons-media-document"></span>
                    </span>
                    <div class="ash-dash__status-copy">
                        <span class="ash-dash__label"><?php echo esc_html__('CSP status', 'abdal-security-headers'); ?></span>
                        <strong class="ash-dash__value"><?php echo esc_html($data['csp']['label']); ?></strong>
                    </div>
                </div>
            </section>

            <section class="ash-dash__mid">
                <div class="ash-dash__mascot-wrap">
                    <?php if (is_file($logo_path)) : ?>
                        <img class="ash-dash__mascot"
                             src="<?php echo esc_url($logo_url); ?>"
                             width="128"
                             height="128"
                             alt="<?php echo esc_attr__('Abdal Security Headers mascot', 'abdal-security-headers'); ?>">
                    <?php else : ?>
                        <span class="ash-dash__mascot-fallback dashicons dashicons-shield" aria-hidden="true"></span>
                    <?php endif; ?>
                </div>
                <div class="ash-dash__activity">
                    <h3 class="ash-dash__section-title"><?php echo esc_html__('Recent Activity', 'abdal-security-headers'); ?></h3>
                    <?php if (empty($data['activities'])) : ?>
                        <p class="ash-dash__empty"><?php echo esc_html__('No recent activity yet.', 'abdal-security-headers'); ?></p>
                    <?php else : ?>
                        <ul class="ash-dash__activity-list">
                            <?php foreach ($data['activities'] as $activity) : ?>
                                <li class="ash-dash__activity-item ash-dash__activity-item--<?php echo esc_attr($activity['tone']); ?>">
                                    <span class="ash-dash__activity-icon dashicons <?php echo esc_attr($activity['icon']); ?>" aria-hidden="true"></span>
                                    <span class="ash-dash__activity-title"><?php echo esc_html($activity['title']); ?></span>
                                    <time class="ash-dash__activity-time" datetime="<?php echo esc_attr(gmdate('c', $activity['time'])); ?>">
                                        <?php echo esc_html($this->format_ago($activity['time'])); ?>
                                    </time>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>
            </section>

            <section class="ash-dash__stats" aria-label="<?php echo esc_attr__('Statistics', 'abdal-security-headers'); ?>">
                <ul class="ash-dash__stats-bar">
                    <?php foreach ($data['stats'] as $stat) : ?>
                        <li class="ash-dash__stat ash-dash__stat--<?php echo esc_attr($stat['tone']); ?>">
                            <span class="ash-dash__stat-icon dashicons <?php echo esc_attr($stat['icon']); ?>" aria-hidden="true"></span>
                            <div class="ash-dash__stat-copy">
                                <span class="ash-dash__stat-label"><?php echo esc_html($stat['label']); ?></span>
                                <strong class="ash-dash__stat-value"><?php echo esc_html($stat['value']); ?></strong>
                            </div>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </section>

            <div class="ash-dash__actions">
                <a class="ash-dash__btn ash-dash__btn--primary" href="<?php echo esc_url($settings_url); ?>">
                    <span class="dashicons dashicons-admin-generic" aria-hidden="true"></span>
                    <?php echo esc_html__('Open Settings', 'abdal-security-headers'); ?>
                </a>
                <a class="ash-dash__report-link" href="<?php echo esc_url($report_url); ?>">
                    <?php echo esc_html__('View Full Report', 'abdal-security-headers'); ?>
                    <span class="ash-dash__report-arrow" aria-hidden="true"><?php echo is_rtl() ? '←' : '→'; ?></span>
                </a>
            </div>
        </div>
        <?php
    }

    /**
     * Build widget data from current plugin options and discovery records.
     *
     * @return array
     */
    private function collect() {
        $options = get_option('ash_options', array());
        if (!is_array($options)) {
            $options = array();
        }

        $headers_total = count($this->header_keys);
        $headers_active = $this->count_enabled($options, $this->header_keys);
        $features_active = $this->count_enabled($options, $this->feature_keys);
        $features_total = count($this->feature_keys);
        $security = $this->security_status($headers_active, $headers_total, $features_active, $features_total);

        if (class_exists('ASH_Security_Status')) {
            $payload = ASH_Security_Status::payload($options, false, false);
            if (isset($payload['headers']['active'])) {
                $headers_active = (int) $payload['headers']['active'];
            }
            if (isset($payload['headers']['total'])) {
                $headers_total = (int) $payload['headers']['total'];
            }
            $score = isset($payload['score']) ? (int) $payload['score'] : 0;
            $security = $this->security_from_score($score);
        }

        $state = class_exists('ASH_CSP_Assistant') ? ASH_CSP_Assistant::get_state() : array();
        $disk_job = class_exists('ASH_CSP_Disk_Scanner') ? ASH_CSP_Disk_Scanner::get_job() : array();

        $source_total = class_exists('ASH_CSP_Repository') ? ASH_CSP_Repository::count_sources() : 0;
        $violation_total = class_exists('ASH_CSP_Repository') ? ASH_CSP_Repository::count_violations() : 0;
        $csp = $this->csp_status($options, $state);
        if (class_exists('ASH_Security_Status') && isset($payload) && isset($payload['csp']) && is_array($payload['csp'])) {
            $csp = $this->csp_from_payload($payload['csp']);
        }

        return array(
            'security' => $security,
            'headers_active' => $headers_active,
            'headers_total' => $headers_total,
            'csp' => $csp,
            'activities' => $this->build_activities($state, $disk_job),
            'stats' => $this->build_stats($headers_active, $headers_total, $source_total, $violation_total),
        );
    }

    /**
     * Map the live 0-100 score onto the compact widget status labels.
     *
     * @param int $score Weighted score.
     * @return array
     */
    private function security_from_score($score) {
        $score = (int) $score;
        if ($score >= 80) {
            return array(
                'tone' => 'good',
                'label' => _x('Good', 'security status', 'abdal-security-headers'),
            );
        }
        if ($score >= 50) {
            return array(
                'tone' => 'warning',
                'label' => __('Warning', 'abdal-security-headers'),
            );
        }
        return array(
            'tone' => 'attention',
            'label' => _x('Needs attention', 'security status', 'abdal-security-headers'),
        );
    }

    /**
     * @param array $csp Payload CSP status.
     * @return array
     */
    private function csp_from_payload($csp) {
        $status = isset($csp['status']) ? (string) $csp['status'] : '';
        $label = isset($csp['label']) ? (string) $csp['label'] : '';
        $tone = 'muted';
        if ($status === 'enabled') {
            $tone = 'good';
        } elseif ($status === 'report_only') {
            $tone = 'purple';
        } elseif ($status === 'invalid') {
            $tone = 'warning';
        }
        return array(
            'tone' => $tone,
            'label' => $label,
        );
    }

    /**
     * @param array $options Plugin options.
     * @param array $keys Option keys.
     * @return int
     */
    private function count_enabled($options, $keys) {
        $count = 0;
        foreach ($keys as $key) {
            if (isset($options[$key]) && (string) $options[$key] === '1') {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Match the settings dashboard scoring, using Warning as the middle label.
     *
     * @param int $header_active Enabled header count.
     * @param int $header_total Total header count.
     * @param int $feature_active Enabled feature count.
     * @param int $feature_total Total feature count.
     * @return array
     */
    private function security_status($header_active, $header_total, $feature_active, $feature_total) {
        $total = $header_total + $feature_total;
        $active = $header_active + $feature_active;
        $ratio = $total > 0 ? ($active / $total) : 0;

        if ($ratio >= 0.75) {
            return array(
                'tone' => 'good',
                'label' => _x('Good', 'security status', 'abdal-security-headers'),
            );
        }

        if ($ratio >= 0.4) {
            return array(
                'tone' => 'warning',
                'label' => __('Warning', 'abdal-security-headers'),
            );
        }

        return array(
            'tone' => 'attention',
            'label' => _x('Needs attention', 'security status', 'abdal-security-headers'),
        );
    }

    /**
     * @param array $options Plugin options.
     * @param array $state Assistant state.
     * @return array
     */
    private function csp_status($options, $state) {
        $status = isset($state['status']) ? (string) $state['status'] : '';
        if ($status === 'learning' || (class_exists('ASH_CSP_Assistant') && ASH_CSP_Assistant::is_learning())) {
            return array(
                'tone' => 'purple',
                'label' => __('Learning', 'abdal-security-headers'),
            );
        }

        $enabled = isset($options['content_security_policy']) && (string) $options['content_security_policy'] === '1';
        if ($enabled) {
            return array(
                'tone' => 'good',
                'label' => _x('Enabled', 'CSP status', 'abdal-security-headers'),
            );
        }

        return array(
            'tone' => 'muted',
            'label' => _x('Disabled', 'CSP status', 'abdal-security-headers'),
        );
    }

    /**
     * Derive recent events from stored timestamps. Does not write a log.
     *
     * @param array $state Assistant state.
     * @param array $disk_job Disk scanner job.
     * @return array
     */
    private function build_activities($state, $disk_job) {
        $items = array();

        $started = $this->unix_ts(isset($state['started_at']) ? $state['started_at'] : '');
        if ($started > 0) {
            $items[] = array(
                'title' => __('Learning Started', 'abdal-security-headers'),
                'time' => $started,
                'icon' => 'dashicons-info',
                'tone' => 'blue',
            );
        }

        $reviewed = $this->unix_ts(isset($state['last_review_at']) ? $state['last_review_at'] : '');
        if ($reviewed > 0) {
            $status = isset($state['status']) ? (string) $state['status'] : '';
            $title = in_array($status, array('analysis_complete', 'monitoring'), true)
                ? __('CSP Scan Completed', 'abdal-security-headers')
                : __('Learning Completed', 'abdal-security-headers');
            $items[] = array(
                'title' => $title,
                'time' => $reviewed,
                'icon' => 'dashicons-yes-alt',
                'tone' => 'green',
            );
        }

        $disk_status = isset($disk_job['status']) ? (string) $disk_job['status'] : '';
        $disk_updated = $this->unix_ts(isset($disk_job['updated_at']) ? $disk_job['updated_at'] : 0);
        if ($disk_status === 'complete' && $disk_updated > 0) {
            $items[] = array(
                'title' => __('Deep File Scan Completed', 'abdal-security-headers'),
                'time' => $disk_updated,
                'icon' => 'dashicons-portfolio',
                'tone' => 'purple',
            );
        }

        $latest = class_exists('ASH_CSP_Repository') ? ASH_CSP_Repository::latest_source() : null;
        $violation = class_exists('ASH_CSP_Repository') ? ASH_CSP_Repository::latest_violation() : null;
        $violation_id = ($violation && isset($violation['id'])) ? (int) $violation['id'] : 0;

        if (is_array($latest)) {
            $source_ts = $this->unix_ts(isset($latest['last_seen']) ? $latest['last_seen'] : '');
            $source_id = isset($latest['id']) ? (int) $latest['id'] : 0;
            if ($source_ts > 0 && $source_id !== $violation_id) {
                $items[] = array(
                    'title' => __('CSP Source Detected', 'abdal-security-headers'),
                    'time' => $source_ts,
                    'icon' => 'dashicons-info',
                    'tone' => 'blue',
                );
            }
        }

        if (is_array($violation)) {
            $violation_ts = $this->unix_ts(isset($violation['last_seen']) ? $violation['last_seen'] : '');
            if ($violation_ts > 0) {
                $items[] = array(
                    'title' => __('CSP Violation Detected', 'abdal-security-headers'),
                    'time' => $violation_ts,
                    'icon' => 'dashicons-warning',
                    'tone' => 'warning',
                );
            }
        }

        usort($items, function ($a, $b) {
            return (int) $b['time'] - (int) $a['time'];
        });

        return array_slice($items, 0, 3);
    }

    /**
     * @param int $headers_active Enabled headers.
     * @param int $headers_total Total headers.
     * @param int $source_total Detected sources.
     * @param int $violation_total Report-Only / warning sources.
     * @return array
     */
    private function build_stats($headers_active, $headers_total, $source_total, $violation_total) {
        return array(
            array(
                'label' => __('Detected CSP Sources', 'abdal-security-headers'),
                'value' => number_format_i18n($source_total),
                'icon' => 'dashicons-shield',
                'tone' => 'neutral',
            ),
            array(
                'label' => __('Active Security Headers', 'abdal-security-headers'),
                'value' => $headers_active . ' / ' . $headers_total,
                'icon' => 'dashicons-lock',
                'tone' => ($headers_active === $headers_total && $headers_total > 0) ? 'neutral' : 'danger',
            ),
            array(
                'label' => __('CSP Violations', 'abdal-security-headers'),
                'value' => number_format_i18n($violation_total),
                'icon' => 'dashicons-chart-line',
                'tone' => $violation_total > 0 ? 'purple' : 'neutral',
            ),
        );
    }

    /**
     * @param mixed $value Unix timestamp or MySQL datetime.
     * @return int
     */
    private function unix_ts($value) {
        if ($value === '' || $value === null) {
            return 0;
        }
        if (is_numeric($value)) {
            $ts = (int) $value;
            return $ts > 0 ? $ts : 0;
        }

        $dt = date_create((string) $value, wp_timezone());
        if (!$dt) {
            $parsed = strtotime((string) $value);
            return $parsed ? (int) $parsed : 0;
        }
        return (int) $dt->getTimestamp();
    }

    /**
     * @param int $timestamp Unix timestamp.
     * @return string
     */
    private function format_ago($timestamp) {
        $timestamp = (int) $timestamp;
        if ($timestamp <= 0) {
            return '';
        }
        $now = time();
        if ($timestamp > $now) {
            $timestamp = $now;
        }
        return sprintf(
            /* translators: %s: human-readable time difference */
            __('%s ago', 'abdal-security-headers'),
            human_time_diff($timestamp, $now)
        );
    }
}
