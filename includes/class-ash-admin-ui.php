<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-admin-ui.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 04:26:15
 * Description : Renders the card-based admin dashboard for security header settings
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

class ASH_Admin_UI {
    private $options;

    public function __construct($options) {
        $this->options = is_array($options) ? $options : array();
        if (class_exists('ASH_Header_Settings')) {
            $this->options = ASH_Header_Settings::hydrate($this->options);
        }
        if (class_exists('ASH_Feature_Settings')) {
            $this->options = ASH_Feature_Settings::hydrate($this->options);
        }
        if (class_exists('ASH_Security_Profile')) {
            $this->options = ASH_Security_Profile::hydrate($this->options);
        }
    }

    /**
     * Render the Security Control Center dashboard.
     *
     * @return void
     */
    public function render() {
        $payload = class_exists('ASH_Security_Status')
            ? ASH_Security_Status::payload($this->options, false)
            : array();
        $catalog = class_exists('ASH_Security_Profile') ? ASH_Security_Profile::catalog() : array();
        $stored_profile = isset($payload['profile']['stored']) ? $payload['profile']['stored'] : 'manual';
        ?>
        <div class="wrap ash-wrap" data-ash-dashboard>
            <header class="ash-page-header">
                <div class="ash-page-header__main">
                    <span class="ash-page-header__icon dashicons dashicons-shield" aria-hidden="true"></span>
                    <div class="ash-page-header__copy">
                        <div class="ash-page-header__title-row">
                            <h1><?php echo esc_html__('Abdal Security Headers', 'abdal-security-headers'); ?></h1>
                            <span class="ash-badge ash-badge--neutral">
                                <?php
                                echo esc_html(
                                    sprintf(
                                        /* translators: %s: plugin version number */
                                        __('Version %s', 'abdal-security-headers'),
                                        ASH_VERSION
                                    )
                                );
                                ?>
                            </span>
                            <span class="ash-badge ash-badge--success">
                                <span class="dashicons dashicons-yes" aria-hidden="true"></span>
                                <?php echo esc_html_x('Active', 'plugin status badge', 'abdal-security-headers'); ?>
                            </span>
                        </div>
                        <p class="ash-page-header__subtitle">
                            <?php echo esc_html__('Review live security status, apply a Security Profile, and open headers, features, or Content Security Policy.', 'abdal-security-headers'); ?>
                        </p>
                    </div>
                </div>
                <div class="ash-page-header__actions">
                    <?php $this->render_help_menu(); ?>
                </div>
            </header>

            <?php settings_errors(); ?>

            <?php $this->render_dashboard_metrics($payload); ?>

            <div class="ash-dashboard-stack">
                <?php $this->render_dashboard_profiles($catalog, $stored_profile, $payload); ?>
                <?php $this->render_dashboard_summary($payload); ?>
                <?php $this->render_dashboard_attention($payload); ?>
                <?php $this->render_dashboard_quick_actions(); ?>
            </div>

            <div class="ash-action-bar" data-ash-action-bar>
                <p class="ash-action-bar__note">
                    <span class="dashicons dashicons-info" aria-hidden="true"></span>
                    <?php echo esc_html__('Apply updates Security Headers and Security Features only. Content Security Policy is never changed by a profile.', 'abdal-security-headers'); ?>
                </p>
                <div class="ash-action-bar__actions">
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-recalculate>
                        <span class="dashicons dashicons-update" aria-hidden="true"></span>
                        <?php echo esc_html__('Recalculate Security Status', 'abdal-security-headers'); ?>
                    </button>
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-reset-profile>
                        <span class="dashicons dashicons-image-rotate" aria-hidden="true"></span>
                        <?php echo esc_html__('Reset Profile to Defaults', 'abdal-security-headers'); ?>
                    </button>
                    <button type="button" class="ash-btn ash-btn--primary" data-ash-apply-profile>
                        <span class="dashicons dashicons-shield" aria-hidden="true"></span>
                        <span class="ash-btn__label"><?php echo esc_html__('Apply Security Profile', 'abdal-security-headers'); ?></span>
                        <span class="ash-spinner" aria-hidden="true"></span>
                    </button>
                </div>
            </div>

            <?php $this->render_confirm_modal(); ?>
            <?php $this->render_credit_footer(); ?>
        </div>
        <?php
    }

    /**
     * @param array $payload Status payload.
     * @return void
     */
    private function render_dashboard_metrics($payload) {
        $score = isset($payload['score']) ? (int) $payload['score'] : 0;
        $score_tone = isset($payload['score_tone']) ? (string) $payload['score_tone'] : 'muted';
        $headers = isset($payload['headers']) && is_array($payload['headers']) ? $payload['headers'] : array();
        $features = isset($payload['features']) && is_array($payload['features']) ? $payload['features'] : array();
        $csp = isset($payload['csp']) && is_array($payload['csp']) ? $payload['csp'] : array();
        $csp_tone = isset($csp['tone']) ? (string) $csp['tone'] : 'muted';
        ?>
        <section class="ash-summary-grid" aria-label="<?php echo esc_attr__('Security overview', 'abdal-security-headers'); ?>" data-ash-metrics>
            <article class="ash-summary-card ash-summary-card--<?php echo esc_attr($score_tone); ?>" data-ash-metric="score">
                <span class="ash-summary-card__icon dashicons dashicons-chart-bar" aria-hidden="true"></span>
                <div class="ash-summary-card__body">
                    <span class="ash-summary-card__label"><?php echo esc_html__('Security Score', 'abdal-security-headers'); ?></span>
                    <strong class="ash-summary-card__value" data-ash-metric-value><?php echo esc_html((string) $score); ?></strong>
                    <span class="ash-summary-card__hint" data-ash-metric-hint><?php echo esc_html(isset($payload['score_hint']) ? $payload['score_hint'] : ''); ?></span>
                </div>
            </article>
            <article class="ash-summary-card ash-summary-card--blue" data-ash-metric="headers">
                <span class="ash-summary-card__icon dashicons dashicons-screenoptions" aria-hidden="true"></span>
                <div class="ash-summary-card__body">
                    <span class="ash-summary-card__label"><?php echo esc_html__('Active Headers', 'abdal-security-headers'); ?></span>
                    <strong class="ash-summary-card__value" data-ash-metric-value><?php echo esc_html(isset($headers['label']) ? $headers['label'] : '0 / 0'); ?></strong>
                    <span class="ash-summary-card__hint" data-ash-metric-hint><?php echo esc_html(isset($headers['hint']) ? $headers['hint'] : ''); ?></span>
                </div>
            </article>
            <article class="ash-summary-card ash-summary-card--purple" data-ash-metric="features">
                <span class="ash-summary-card__icon dashicons dashicons-admin-plugins" aria-hidden="true"></span>
                <div class="ash-summary-card__body">
                    <span class="ash-summary-card__label"><?php echo esc_html__('Active Features', 'abdal-security-headers'); ?></span>
                    <strong class="ash-summary-card__value" data-ash-metric-value><?php echo esc_html(isset($features['label']) ? $features['label'] : '0 / 0'); ?></strong>
                    <span class="ash-summary-card__hint" data-ash-metric-hint><?php echo esc_html(isset($features['hint']) ? $features['hint'] : ''); ?></span>
                </div>
            </article>
            <article class="ash-summary-card ash-summary-card--<?php echo esc_attr($csp_tone); ?>" data-ash-metric="csp">
                <span class="ash-summary-card__icon dashicons dashicons-media-document" aria-hidden="true"></span>
                <div class="ash-summary-card__body">
                    <span class="ash-summary-card__label"><?php echo esc_html__('CSP Status', 'abdal-security-headers'); ?></span>
                    <strong class="ash-summary-card__value" data-ash-metric-value><?php echo esc_html(isset($csp['label']) ? $csp['label'] : ''); ?></strong>
                    <span class="ash-summary-card__hint" data-ash-metric-hint><?php echo esc_html(isset($csp['hint']) ? $csp['hint'] : ''); ?></span>
                </div>
            </article>
        </section>
        <?php
    }

    /**
     * @param array  $catalog Catalog.
     * @param string $stored Stored profile id.
     * @param array  $payload Payload.
     * @return void
     */
    private function render_dashboard_profiles($catalog, $stored, $payload) {
        $profile = isset($payload['profile']) && is_array($payload['profile']) ? $payload['profile'] : array();
        ?>
        <section class="ash-card">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-admin-generic" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Security Profile', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('Profiles change Security Headers and Security Features only. Content Security Policy stays independent.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--padded">
                <div class="ash-profile-grid" role="radiogroup" aria-label="<?php echo esc_attr__('Security Profile', 'abdal-security-headers'); ?>" data-ash-profile-group>
                    <?php foreach ($catalog as $id => $item) : ?>
                        <?php
                        $selected = ($id === $stored);
                        $is_recommended = ($id === 'recommended');
                        $is_hardened = ($id === 'hardened');
                        ?>
                        <button type="button"
                                class="ash-card ash-profile-card<?php echo $selected ? ' is-selected' : ''; ?>"
                                role="radio"
                                aria-checked="<?php echo $selected ? 'true' : 'false'; ?>"
                                data-ash-profile-option="<?php echo esc_attr($id); ?>">
                            <span class="ash-card__title-row">
                                <strong><?php echo esc_html($item['label']); ?></strong>
                                <?php if ($is_recommended) : ?>
                                    <span class="ash-badge ash-badge--success"><?php echo esc_html__('Recommended', 'abdal-security-headers'); ?></span>
                                <?php endif; ?>
                                <?php if ($is_hardened) : ?>
                                    <span class="ash-badge ash-badge--warning"><?php echo esc_html__('High impact', 'abdal-security-headers'); ?></span>
                                <?php endif; ?>
                            </span>
                            <span class="ash-profile-card__desc"><?php echo esc_html($item['description']); ?></span>
                            <?php if ($is_hardened) : ?>
                                <span class="ash-callout ash-callout--warning">
                                    <?php echo esc_html($item['hint']); ?>
                                </span>
                            <?php endif; ?>
                        </button>
                    <?php endforeach; ?>
                </div>
            </div>
            <footer class="ash-card__footer" data-ash-profile-status>
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <span data-ash-profile-status-text>
                    <?php echo esc_html(isset($profile['status_text']) ? $profile['status_text'] : ''); ?>
                </span>
            </footer>
        </section>
        <?php
    }

    /**
     * @param array $payload Payload.
     * @return void
     */
    private function render_dashboard_summary($payload) {
        $rows = isset($payload['summary']) && is_array($payload['summary']) ? $payload['summary'] : array();
        ?>
        <section class="ash-card">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-list-view" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Configuration Summary', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('Live values from the current plugin configuration.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list" data-ash-summary-list>
                <?php foreach ($rows as $row) : ?>
                    <div class="ash-toggle-row">
                        <div class="ash-toggle-row__info">
                            <span class="ash-toggle-row__label"><?php echo esc_html(isset($row['label']) ? $row['label'] : ''); ?></span>
                        </div>
                        <span class="ash-metric-value"><?php echo esc_html(isset($row['value']) ? $row['value'] : ''); ?></span>
                    </div>
                <?php endforeach; ?>
            </div>
        </section>
        <?php
    }

    /**
     * @param array $payload Payload.
     * @return void
     */
    private function render_dashboard_attention($payload) {
        $items = isset($payload['attention']) && is_array($payload['attention']) ? $payload['attention'] : array();
        ?>
        <section class="ash-card">
            <header class="ash-card__header">
                <span class="ash-card__icon ash-card__icon--warning dashicons dashicons-warning" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Security Attention', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('Only issues present in the current configuration are listed.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--padded" data-ash-attention-list>
                <?php if (empty($items)) : ?>
                    <p class="ash-section-help"><?php echo esc_html__('No configuration issues detected.', 'abdal-security-headers'); ?></p>
                <?php else : ?>
                    <?php foreach ($items as $item) : ?>
                        <?php
                        $tone = (isset($item['tone']) && $item['tone'] === 'muted') ? 'muted' : 'warning';
                        $class = $tone === 'muted' ? 'ash-callout' : 'ash-callout ash-callout--warning';
                        ?>
                        <div class="<?php echo esc_attr($class); ?>">
                            <strong><?php echo esc_html(isset($item['title']) ? $item['title'] : ''); ?></strong>
                            <span><?php echo esc_html(isset($item['description']) ? $item['description'] : ''); ?></span>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </section>
        <?php
    }

    /**
     * @return void
     */
    private function render_dashboard_quick_actions() {
        $headers_url = admin_url('admin.php?page=abdal-security-headers-headers');
        $features_url = admin_url('admin.php?page=abdal-security-headers-features');
        $csp_url = admin_url('admin.php?page=abdal-security-headers-csp');
        ?>
        <section class="ash-card">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-admin-links" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Quick Security Actions', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('Open a settings screen or refresh the live security status.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--padded">
                <div class="ash-quick-actions">
                    <a class="ash-btn ash-btn--secondary" href="<?php echo esc_url($headers_url); ?>">
                        <span class="dashicons dashicons-lock" aria-hidden="true"></span>
                        <?php echo esc_html__('Security Headers', 'abdal-security-headers'); ?>
                    </a>
                    <a class="ash-btn ash-btn--secondary" href="<?php echo esc_url($features_url); ?>">
                        <span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>
                        <?php echo esc_html__('Security Features', 'abdal-security-headers'); ?>
                    </a>
                    <a class="ash-btn ash-btn--secondary" href="<?php echo esc_url($csp_url); ?>">
                        <span class="dashicons dashicons-media-document" aria-hidden="true"></span>
                        <?php echo esc_html__('Content Security Policy', 'abdal-security-headers'); ?>
                    </a>
                    <button type="button" class="ash-btn ash-btn--primary" data-ash-apply-profile>
                        <span class="dashicons dashicons-shield" aria-hidden="true"></span>
                        <?php echo esc_html__('Apply Security Profile', 'abdal-security-headers'); ?>
                    </button>
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-recalculate>
                        <span class="dashicons dashicons-update" aria-hidden="true"></span>
                        <?php echo esc_html__('Recalculate Security Status', 'abdal-security-headers'); ?>
                    </button>
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-reset-profile>
                        <span class="dashicons dashicons-image-rotate" aria-hidden="true"></span>
                        <?php echo esc_html__('Reset Profile to Defaults', 'abdal-security-headers'); ?>
                    </button>
                </div>
            </div>
        </section>
        <?php
    }

    /**
     * Render the Security Headers screen.
     *
     * @return void
     */
    public function render_security_headers() {
        ?>
        <div class="wrap ash-wrap">
            <header class="ash-page-header">
                <div class="ash-page-header__main">
                    <span class="ash-page-header__icon dashicons dashicons-lock" aria-hidden="true"></span>
                    <div class="ash-page-header__copy">
                        <div class="ash-page-header__title-row">
                            <h1><?php echo esc_html__('Security Headers', 'abdal-security-headers'); ?></h1>
                            <span class="ash-badge ash-badge--neutral">
                                <?php
                                echo esc_html(
                                    sprintf(
                                        /* translators: %s: plugin version number */
                                        __('Version %s', 'abdal-security-headers'),
                                        ASH_VERSION
                                    )
                                );
                                ?>
                            </span>
                        </div>
                        <p class="ash-page-header__subtitle">
                            <?php echo esc_html__('Configure each HTTP security header and the values sent with responses.', 'abdal-security-headers'); ?>
                        </p>
                    </div>
                </div>
                <div class="ash-page-header__actions">
                    <?php $this->render_help_menu(); ?>
                </div>
            </header>

            <?php settings_errors(); ?>

            <form method="post" action="options.php" id="ash-settings-form" class="ash-form" data-ash-headers-page>
                <?php settings_fields('ash_options_group'); ?>
                <input type="hidden" name="ash_options[_ash_screen]" value="headers">

                <div class="ash-headers-stack">
                    <?php $this->render_xss_header_card(); ?>
                    <?php $this->render_xcto_header_card(); ?>
                    <?php $this->render_hsts_header_card(); ?>
                    <?php $this->render_permissions_policy_header_card(); ?>
                    <?php $this->render_xfo_header_card(); ?>
                    <?php $this->render_referrer_policy_header_card(); ?>
                </div>

                <?php $this->render_action_bar(); ?>
            </form>

            <?php $this->render_pp_custom_template(); ?>
            <?php $this->render_confirm_modal(); ?>
            <?php $this->render_credit_footer(); ?>
        </div>
        <?php
    }

    /**
     * Render the X-XSS-Protection card.
     *
     * @return void
     */
    private function render_xss_header_card() {
        $policy = $this->option_string('xss_policy', '0');
        $report_url = $this->option_string('xss_report_url', '');
        $enabled = $this->is_enabled('x_xss_protection');
        $policy_choices = array(
            '0' => '0',
            '1' => '1',
            '1_mode_block' => '1; mode=block',
            '1_report' => '1; report=<URL>',
        );
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-header-card data-ash-enable="x_xss_protection">
            <header class="ash-card__header">
                <span class="ash-card__icon ash-card__icon--warning dashicons dashicons-warning" aria-hidden="true"></span>
                <div>
                    <div class="ash-card__title-row">
                        <h2>X-XSS-Protection</h2>
                        <span class="ash-badge ash-badge--warning"><?php echo esc_html__('Deprecated / Legacy', 'abdal-security-headers'); ?></span>
                    </div>
                    <p><?php echo esc_html__('Legacy browser XSS filter. Modern browsers ignore this header; prefer Content-Security-Policy.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'x_xss_protection',
                    __('Enable X-XSS-Protection', 'abdal-security-headers'),
                    __('Send the X-XSS-Protection header with the selected policy.', 'abdal-security-headers'),
                    'headers',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <?php
                    $this->render_field_row(
                        __('Policy', 'abdal-security-headers'),
                        __('Choose the legacy XSS filter policy sent to older browsers.', 'abdal-security-headers'),
                        $this->get_select_markup(
                            'ash-xss-policy',
                            'ash_options[xss_policy]',
                            $policy_choices,
                            $policy,
                            array(
                                'data-ash-xss-policy' => '1',
                                'dir' => 'ltr',
                            )
                        )
                    );
                    ?>
                    <div class="ash-field-row ash-field-row--block" data-ash-xss-report-row <?php echo $policy === '1_report' ? '' : 'hidden'; ?>>
                        <div class="ash-field-row__info">
                            <label class="ash-field-row__label" for="ash-xss-report-url"><?php echo esc_html__('Reporting URL', 'abdal-security-headers'); ?></label>
                            <?php $this->render_info_icon(__('Endpoint that receives XSS filter reports when the report policy is selected.', 'abdal-security-headers')); ?>
                        </div>
                        <div class="ash-field-row__control">
                            <input type="url"
                                   class="ash-input"
                                   id="ash-xss-report-url"
                                   name="ash_options[xss_report_url]"
                                   value="<?php echo esc_attr($report_url); ?>"
                                   placeholder="https://example.com/xss-report"
                                   spellcheck="false"
                                   autocomplete="off"
                                   dir="ltr">
                        </div>
                    </div>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('The default policy is 0, which turns the legacy filter off when the header is sent.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the X-Content-Type-Options card.
     *
     * @return void
     */
    private function render_xcto_header_card() {
        $enabled = $this->is_enabled('x_content_type_options');
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-header-card data-ash-enable="x_content_type_options">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-media-document" aria-hidden="true"></span>
                <div>
                    <h2>X-Content-Type-Options</h2>
                    <p><?php echo esc_html__('Prevents browsers from MIME-sniffing a response away from the declared content type.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'x_content_type_options',
                    __('Enable X-Content-Type-Options', 'abdal-security-headers'),
                    __('When enabled, the plugin always sends nosniff. There are no additional options.', 'abdal-security-headers'),
                    'headers',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-yes" aria-hidden="true"></span>
                <?php echo esc_html__('When enabled, always send X-Content-Type-Options: nosniff.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the Strict-Transport-Security card.
     *
     * @return void
     */
    private function render_hsts_header_card() {
        $enabled = $this->is_enabled('strict_transport_security');
        $max_age = $this->option_string('hsts_max_age', '31536000');
        $presets = class_exists('ASH_Header_Settings') ? ASH_Header_Settings::max_age_preset_values() : array('31536000');
        $is_custom = !in_array($max_age, $presets, true);
        $preset_value = $is_custom ? 'custom' : $max_age;
        $preset_choices = array(
            '86400' => '86400 — ' . __('1 Day', 'abdal-security-headers'),
            '604800' => '604800 — ' . __('1 Week', 'abdal-security-headers'),
            '2592000' => '2592000 — ' . __('1 Month', 'abdal-security-headers'),
            '15768000' => '15768000 — ' . __('6 Months', 'abdal-security-headers'),
            '31536000' => '31536000 — ' . __('1 Year', 'abdal-security-headers'),
            '63072000' => '63072000 — ' . __('2 Years', 'abdal-security-headers'),
            'custom' => __('Custom value', 'abdal-security-headers'),
        );
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-header-card data-ash-enable="strict_transport_security">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-lock" aria-hidden="true"></span>
                <div>
                    <h2>Strict-Transport-Security</h2>
                    <p><?php echo esc_html__('Forces browsers to use HTTPS for future requests to this host.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'strict_transport_security',
                    __('Enable Strict-Transport-Security', 'abdal-security-headers'),
                    __('Instruct browsers to use HTTPS for this host for the configured lifetime.', 'abdal-security-headers'),
                    'headers',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <?php
                    $this->render_field_row(
                        'max-age',
                        __('How long browsers should remember to use HTTPS only.', 'abdal-security-headers'),
                        $this->get_select_markup(
                            'ash-hsts-max-age-preset',
                            'ash_options[hsts_max_age_preset]',
                            $preset_choices,
                            $preset_value,
                            array(
                                'data-ash-hsts-preset' => '1',
                                'dir' => 'ltr',
                            )
                        )
                    );
                    ?>
                    <div class="ash-field-row ash-field-row--block" data-ash-hsts-custom-row <?php echo $is_custom ? '' : 'hidden'; ?>>
                        <div class="ash-field-row__info">
                            <label class="ash-field-row__label" for="ash-hsts-max-age-custom"><?php echo esc_html__('Custom max-age (seconds)', 'abdal-security-headers'); ?></label>
                            <?php $this->render_info_icon(__('Enter max-age in seconds.', 'abdal-security-headers')); ?>
                        </div>
                        <div class="ash-field-row__control">
                            <input type="number"
                                   class="ash-input"
                                   id="ash-hsts-max-age-custom"
                                   name="ash_options[hsts_max_age_custom]"
                                   value="<?php echo esc_attr($max_age); ?>"
                                   min="0"
                                   max="630720000"
                                   step="1"
                                   inputmode="numeric"
                                   dir="ltr">
                        </div>
                    </div>
                    <?php
                    $this->render_toggle_row(
                        'hsts_include_subdomains',
                        __('Include Subdomains', 'abdal-security-headers'),
                        __('Adds includeSubDomains so the policy also applies to subdomains.', 'abdal-security-headers'),
                        'headers',
                        'ash_options',
                        null,
                        array(
                            'attrs' => array(
                                'data-ash-hsts-subdomains' => '1',
                            ),
                        )
                    );
                    $this->render_toggle_row(
                        'hsts_preload',
                        __('Preload', 'abdal-security-headers'),
                        __('Adds preload. Requires includeSubDomains and a max-age of at least one year.', 'abdal-security-headers'),
                        'headers',
                        'ash_options',
                        null,
                        array(
                            'attrs' => array(
                                'data-ash-hsts-preload' => '1',
                            ),
                        )
                    );
                    ?>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-lock" aria-hidden="true"></span>
                <?php echo esc_html__('This header is sent only over HTTPS. Preload requires includeSubDomains and max-age of at least 31536000.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the Permissions-Policy card.
     *
     * @return void
     */
    private function render_permissions_policy_header_card() {
        $enabled = $this->is_enabled('permissions_policy');
        $directives = isset($this->options['pp_directives']) && is_array($this->options['pp_directives'])
            ? $this->options['pp_directives']
            : array();
        $custom = isset($this->options['pp_custom']) && is_array($this->options['pp_custom'])
            ? $this->options['pp_custom']
            : array();
        $names = class_exists('ASH_Header_Settings') ? ASH_Header_Settings::directive_names() : array();
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-header-card data-ash-enable="permissions_policy">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-privacy" aria-hidden="true"></span>
                <div>
                    <h2>Permissions-Policy</h2>
                    <p><?php echo esc_html__('Restricts access to powerful browser features such as camera and geolocation.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'permissions_policy',
                    __('Enable Permissions-Policy', 'abdal-security-headers'),
                    __('Control which origins may use powerful browser features.', 'abdal-security-headers'),
                    'headers',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <div class="ash-section-label"><?php echo esc_html__('Directives', 'abdal-security-headers'); ?></div>
                    <div class="ash-pp-list">
                        <?php foreach ($names as $name) : ?>
                            <?php
                            $state = isset($directives[$name]) && is_array($directives[$name]) ? $directives[$name] : array();
                            $this->render_pp_directive_item($name, $state, false, '');
                            ?>
                        <?php endforeach; ?>
                    </div>
                    <div class="ash-section-label"><?php echo esc_html__('Custom Directives', 'abdal-security-headers'); ?></div>
                    <p class="ash-section-help"><?php echo esc_html__('Add feature names that are not listed above. Directives set to Not Set are omitted from the header.', 'abdal-security-headers'); ?></p>
                    <div class="ash-pp-list" data-ash-pp-custom-list>
                        <?php foreach ($custom as $index => $item) : ?>
                            <?php
                            if (!is_array($item) || empty($item['name'])) {
                                continue;
                            }
                            $this->render_pp_directive_item((string) $item['name'], $item, true, (string) $index);
                            ?>
                        <?php endforeach; ?>
                    </div>
                    <div class="ash-pp-add">
                        <label class="screen-reader-text" for="ash-pp-new-name"><?php echo esc_html__('Directive name', 'abdal-security-headers'); ?></label>
                        <input type="text"
                               class="ash-input"
                               id="ash-pp-new-name"
                               data-ash-pp-new-name
                               maxlength="64"
                               spellcheck="false"
                               autocomplete="off"
                               dir="ltr"
                               placeholder="directive-name">
                        <button type="button" class="ash-btn ash-btn--secondary" data-ash-pp-add>
                            <span class="dashicons dashicons-plus-alt2" aria-hidden="true"></span>
                            <?php echo esc_html__('Add directive', 'abdal-security-headers'); ?>
                        </button>
                    </div>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('Directives configured as Not Set, or with Enable Directive turned off, are not included in the generated header.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the X-Frame-Options card.
     *
     * @return void
     */
    private function render_xfo_header_card() {
        $enabled = $this->is_enabled('x_frame_options');
        $policy = $this->option_string('x_frame_options_policy', 'SAMEORIGIN');
        $choices = array(
            'DENY' => 'DENY',
            'SAMEORIGIN' => 'SAMEORIGIN',
        );
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-header-card data-ash-enable="x_frame_options">
            <header class="ash-card__header">
                        <span class="ash-card__icon dashicons dashicons-align-full-width" aria-hidden="true"></span>
                <div>
                    <h2>X-Frame-Options</h2>
                    <p><?php echo esc_html__('Controls whether the site can be embedded in frames to reduce clickjacking risk.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'x_frame_options',
                    __('Enable X-Frame-Options', 'abdal-security-headers'),
                    __('Control whether the site may be embedded in frames.', 'abdal-security-headers'),
                    'headers',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <?php
                    $this->render_field_row(
                        __('Policy', 'abdal-security-headers'),
                        __('DENY blocks all framing. SAMEORIGIN allows framing by this origin only. ALLOW-FROM is obsolete and is not offered.', 'abdal-security-headers'),
                        $this->get_select_markup(
                            'ash-xfo-policy',
                            'ash_options[x_frame_options_policy]',
                            $choices,
                            $policy,
                            array(
                                'dir' => 'ltr',
                            )
                        )
                    );
                    ?>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('The default policy is SAMEORIGIN.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the Referrer-Policy card.
     *
     * @return void
     */
    private function render_referrer_policy_header_card() {
        $enabled = $this->is_enabled('referrer_policy');
        $policy = $this->option_string('referrer_policy_value', 'strict-origin-when-cross-origin');
        $sensitive_label = __('privacy/security sensitive', 'abdal-security-headers');
        $choices = array(
            'no-referrer' => 'no-referrer',
            'no-referrer-when-downgrade' => 'no-referrer-when-downgrade',
            'origin' => 'origin',
            'origin-when-cross-origin' => 'origin-when-cross-origin',
            'same-origin' => 'same-origin',
            'strict-origin' => 'strict-origin',
            'strict-origin-when-cross-origin' => 'strict-origin-when-cross-origin',
            'unsafe-url' => 'unsafe-url — ' . $sensitive_label,
        );
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-header-card data-ash-enable="referrer_policy">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-admin-links" aria-hidden="true"></span>
                <div>
                    <h2>Referrer-Policy</h2>
                    <p><?php echo esc_html__('Limits referrer information sent with navigations and resource requests.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'referrer_policy',
                    __('Enable Referrer-Policy', 'abdal-security-headers'),
                    __('Control how much referrer information is sent with requests.', 'abdal-security-headers'),
                    'headers',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <?php
                    $this->render_field_row(
                        __('Policy', 'abdal-security-headers'),
                        __('Choose the Referrer-Policy value sent with responses.', 'abdal-security-headers'),
                        $this->get_select_markup(
                            'ash-referrer-policy',
                            'ash_options[referrer_policy_value]',
                            $choices,
                            $policy,
                            array(
                                'data-ash-referrer-policy' => '1',
                                'dir' => 'ltr',
                            )
                        )
                    );
                    ?>
                    <div class="ash-callout ash-callout--warning" data-ash-referrer-warning <?php echo $policy === 'unsafe-url' ? '' : 'hidden'; ?>>
                        <?php echo esc_html__('unsafe-url sends the full URL across origins and is privacy-sensitive.', 'abdal-security-headers'); ?>
                    </div>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('The default policy is strict-origin-when-cross-origin.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render one Permissions-Policy directive editor.
     *
     * @param string $name Directive name.
     * @param array  $state Saved state.
     * @param bool   $is_custom Whether this is a custom directive row.
     * @param string $index Custom list index.
     * @return void
     */
    private function render_pp_directive_item($name, $state, $is_custom, $index) {
        $state = is_array($state) ? $state : array();
        $enabled = isset($state['enabled']) && (string) $state['enabled'] === '1';
        $policy = isset($state['policy']) ? (string) $state['policy'] : 'not_set';
        $origins = isset($state['origins']) && is_array($state['origins']) ? $state['origins'] : array();
        $origins_text = implode("\n", $origins);
        $policy_choices = $this->get_pp_policy_choices();

        if ($is_custom) {
            $base = 'ash_options[pp_custom][' . $index . ']';
            $id_base = 'ash-pp-custom-' . $index;
        } else {
            $base = 'ash_options[pp_directives][' . $name . ']';
            $id_base = 'ash-pp-' . $name;
        }
        ?>
        <div class="ash-pp-item<?php echo $is_custom ? ' ash-pp-item--custom' : ''; ?>"
             data-ash-pp-item
             data-ash-pp-name="<?php echo esc_attr($name); ?>"
             <?php echo $is_custom ? 'data-ash-pp-custom-row' : ''; ?>>
            <div class="ash-pp-item__head">
                <?php if ($is_custom) : ?>
                    <label class="screen-reader-text" for="<?php echo esc_attr($id_base . '-name'); ?>"><?php echo esc_html__('Directive name', 'abdal-security-headers'); ?></label>
                    <input type="text"
                           class="ash-input ash-pp-item__name-input"
                           id="<?php echo esc_attr($id_base . '-name'); ?>"
                           name="<?php echo esc_attr($base . '[name]'); ?>"
                           value="<?php echo esc_attr($name); ?>"
                           maxlength="64"
                           spellcheck="false"
                           autocomplete="off"
                           dir="ltr"
                           data-ash-pp-name-input>
                <?php else : ?>
                    <span class="ash-pp-item__name"><?php echo esc_html($name); ?></span>
                <?php endif; ?>
                <div class="ash-pp-item__actions">
                    <?php
                    $this->render_toggle_row(
                        $id_base . '-enabled',
                        __('Enable Directive', 'abdal-security-headers'),
                        __('Include this directive in the generated Permissions-Policy header.', 'abdal-security-headers'),
                        'headers',
                        'ash_options',
                        array($id_base . '-enabled' => $enabled ? '1' : '0'),
                        array(
                            'name' => $base . '[enabled]',
                            'input_id' => $id_base . '-enabled',
                            'checked' => $enabled,
                            'row_class' => 'ash-toggle-row--compact',
                        )
                    );
                    ?>
                    <?php if ($is_custom) : ?>
                        <button type="button" class="ash-btn ash-btn--secondary ash-btn--compact" data-ash-pp-remove>
                            <?php echo esc_html__('Remove', 'abdal-security-headers'); ?>
                        </button>
                    <?php endif; ?>
                </div>
            </div>
            <div class="ash-pp-item__body">
                <?php
                $this->render_field_row(
                    __('Policy', 'abdal-security-headers'),
                    __('Choose how this feature may be used.', 'abdal-security-headers'),
                    $this->get_select_markup(
                        $id_base . '-policy',
                        $base . '[policy]',
                        $policy_choices,
                        $policy,
                        array(
                            'data-ash-pp-policy' => '1',
                        )
                    )
                );
                ?>
                <div class="ash-field-row ash-field-row--block" data-ash-pp-origins-row <?php echo $policy === 'custom' ? '' : 'hidden'; ?>>
                    <div class="ash-field-row__info">
                        <label class="ash-field-row__label" for="<?php echo esc_attr($id_base . '-origins'); ?>"><?php echo esc_html__('Custom Origins', 'abdal-security-headers'); ?></label>
                        <?php $this->render_info_icon(__('One origin per line. Use self or full origins such as https://example.com.', 'abdal-security-headers')); ?>
                    </div>
                    <div class="ash-field-row__control">
                        <textarea class="ash-textarea"
                                  id="<?php echo esc_attr($id_base . '-origins'); ?>"
                                  name="<?php echo esc_attr($base . '[origins]'); ?>"
                                  rows="3"
                                  spellcheck="false"
                                  autocomplete="off"
                                  dir="ltr"
                                  placeholder="<?php echo esc_attr("self\nhttps://example.com\nhttps://cdn.example.com"); ?>"><?php echo esc_textarea($origins_text); ?></textarea>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Hidden template used to add custom Permissions-Policy directives.
     *
     * @return void
     */
    private function render_pp_custom_template() {
        $policy_choices = $this->get_pp_policy_choices();
        ?>
        <template id="ash-pp-custom-template">
            <div class="ash-pp-item ash-pp-item--custom" data-ash-pp-item data-ash-pp-name="" data-ash-pp-custom-row data-ash-pp-custom-new>
                <div class="ash-pp-item__head">
                    <label class="screen-reader-text" for="ash-pp-custom-__INDEX__-name"><?php echo esc_html__('Directive name', 'abdal-security-headers'); ?></label>
                    <input type="text"
                           class="ash-input ash-pp-item__name-input"
                           id="ash-pp-custom-__INDEX__-name"
                           name="ash_options[pp_custom][__INDEX__][name]"
                           value=""
                           maxlength="64"
                           spellcheck="false"
                           autocomplete="off"
                           dir="ltr"
                           data-ash-pp-name-input>
                    <div class="ash-pp-item__actions">
                        <div class="ash-toggle-row ash-toggle-row--compact">
                            <div class="ash-toggle-row__info">
                                <label class="ash-toggle-row__label" for="ash-pp-custom-__INDEX__-enabled"><?php echo esc_html__('Enable Directive', 'abdal-security-headers'); ?></label>
                            </div>
                            <label class="ash-switch">
                                <input type="checkbox"
                                       id="ash-pp-custom-__INDEX__-enabled"
                                       name="ash_options[pp_custom][__INDEX__][enabled]"
                                       value="1">
                                <span class="ash-switch__ui" aria-hidden="true"></span>
                            </label>
                        </div>
                        <button type="button" class="ash-btn ash-btn--secondary ash-btn--compact" data-ash-pp-remove>
                            <?php echo esc_html__('Remove', 'abdal-security-headers'); ?>
                        </button>
                    </div>
                </div>
                <div class="ash-pp-item__body">
                    <div class="ash-field-row">
                        <div class="ash-field-row__info">
                            <label class="ash-field-row__label" for="ash-pp-custom-__INDEX__-policy"><?php echo esc_html__('Policy', 'abdal-security-headers'); ?></label>
                        </div>
                        <div class="ash-field-row__control">
                            <select class="ash-select" id="ash-pp-custom-__INDEX__-policy" name="ash_options[pp_custom][__INDEX__][policy]" data-ash-pp-policy>
                                <?php foreach ($policy_choices as $value => $label) : ?>
                                    <option value="<?php echo esc_attr($value); ?>"><?php echo esc_html($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                    <div class="ash-field-row ash-field-row--block" data-ash-pp-origins-row hidden>
                        <div class="ash-field-row__info">
                            <label class="ash-field-row__label" for="ash-pp-custom-__INDEX__-origins"><?php echo esc_html__('Custom Origins', 'abdal-security-headers'); ?></label>
                        </div>
                        <div class="ash-field-row__control">
                            <textarea class="ash-textarea"
                                      id="ash-pp-custom-__INDEX__-origins"
                                      name="ash_options[pp_custom][__INDEX__][origins]"
                                      rows="3"
                                      spellcheck="false"
                                      autocomplete="off"
                                      dir="ltr"
                                      placeholder="<?php echo esc_attr("self\nhttps://example.com\nhttps://cdn.example.com"); ?>"></textarea>
                        </div>
                    </div>
                </div>
            </div>
        </template>
        <?php
    }

    /**
     * Permissions-Policy allowlist choices.
     *
     * @return array
     */
    private function get_pp_policy_choices() {
        return array(
            'not_set' => __('Not Set', 'abdal-security-headers'),
            'deny' => __('Deny All', 'abdal-security-headers') . ' → ()',
            'self' => __('Self', 'abdal-security-headers') . ' → (self)',
            'all' => __('Allow All', 'abdal-security-headers') . ' → *',
            'custom' => __('Custom Origins', 'abdal-security-headers'),
        );
    }

    /**
     * Render a labeled control row.
     *
     * @param string $label Field label.
     * @param string $description Helper text.
     * @param string $control_html Escaped control markup.
     * @return void
     */
    private function render_field_row($label, $description, $control_html) {
        $id = '';
        if (preg_match('/\sid=(["\'])([^"\']+)\1/', $control_html, $match)) {
            $id = $match[2];
        }
        ?>
        <div class="ash-field-row">
            <div class="ash-field-row__info">
                <?php if ($id !== '') : ?>
                    <label class="ash-field-row__label" for="<?php echo esc_attr($id); ?>"><?php echo esc_html($label); ?></label>
                <?php else : ?>
                    <span class="ash-field-row__label"><?php echo esc_html($label); ?></span>
                <?php endif; ?>
                <?php $this->render_info_icon($description); ?>
            </div>
            <div class="ash-field-row__control">
                <?php echo $control_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
            </div>
        </div>
        <?php
    }

    /**
     * Build a styled select element.
     *
     * @param string $id Select id.
     * @param string $name Input name.
     * @param array  $choices Value => label.
     * @param string $current Selected value.
     * @param array  $attrs Extra attributes.
     * @return string
     */
    private function get_select_markup($id, $name, $choices, $current, $attrs = array()) {
        $html = '<select class="ash-select" id="' . esc_attr($id) . '" name="' . esc_attr($name) . '"';
        foreach ($attrs as $attr_name => $attr_value) {
            $safe_name = preg_replace('/[^a-zA-Z0-9_-]/', '', (string) $attr_name);
            if ($safe_name === '') {
                continue;
            }
            $html .= ' ' . $safe_name . '="' . esc_attr((string) $attr_value) . '"';
        }
        $html .= '>';
        foreach ($choices as $value => $label) {
            $html .= '<option value="' . esc_attr((string) $value) . '" ' . selected((string) $current, (string) $value, false) . '>' . esc_html($label) . '</option>';
        }
        $html .= '</select>';
        return $html;
    }

    /**
     * Build a styled textarea.
     *
     * @param string $id Field id.
     * @param string $name Input name.
     * @param string $value Current text.
     * @param array  $attrs Extra attributes.
     * @return string
     */
    private function get_textarea_markup($id, $name, $value, $attrs = array()) {
        $html = '<textarea class="ash-textarea" id="' . esc_attr($id) . '" name="' . esc_attr($name) . '" rows="4" spellcheck="false" autocomplete="off" dir="ltr"';
        foreach ($attrs as $attr_name => $attr_value) {
            $safe_name = preg_replace('/[^a-zA-Z0-9_-]/', '', (string) $attr_name);
            if ($safe_name === '') {
                continue;
            }
            $html .= ' ' . $safe_name . '="' . esc_attr((string) $attr_value) . '"';
        }
        $html .= '>' . esc_textarea((string) $value) . '</textarea>';
        return $html;
    }

    /**
     * Join a stored list for a textarea.
     *
     * @param string $key Option key.
     * @return string
     */
    private function option_lines($key) {
        $value = isset($this->options[$key]) && is_array($this->options[$key]) ? $this->options[$key] : array();
        return implode("\n", $value);
    }

    /**
     * WordPress roles for REST access checkboxes.
     *
     * @return array
     */
    private function get_role_choices() {
        $choices = array();
        if (!function_exists('wp_roles')) {
            return $choices;
        }
        $roles = wp_roles();
        if (!is_object($roles) || !isset($roles->role_names) || !is_array($roles->role_names)) {
            return $choices;
        }
        foreach ($roles->role_names as $slug => $label) {
            $choices[$slug] = translate_user_role($label);
        }
        return $choices;
    }

    /**
     * Read a stored option as a string.
     *
     * @param string $key Option key.
     * @param string $default Fallback.
     * @return string
     */
    private function option_string($key, $default = '') {
        return isset($this->options[$key]) ? (string) $this->options[$key] : $default;
    }

    /**
     * Render the Security Features screen.
     *
     * @return void
     */
    public function render_security_features() {
        ?>
        <div class="wrap ash-wrap">
            <header class="ash-page-header">
                <div class="ash-page-header__main">
                    <span class="ash-page-header__icon dashicons dashicons-admin-tools" aria-hidden="true"></span>
                    <div class="ash-page-header__copy">
                        <div class="ash-page-header__title-row">
                            <h1><?php echo esc_html__('Security Features', 'abdal-security-headers'); ?></h1>
                            <span class="ash-badge ash-badge--neutral">
                                <?php
                                echo esc_html(
                                    sprintf(
                                        /* translators: %s: plugin version number */
                                        __('Version %s', 'abdal-security-headers'),
                                        ASH_VERSION
                                    )
                                );
                                ?>
                            </span>
                        </div>
                        <p class="ash-page-header__subtitle">
                            <?php echo esc_html__('Configure WordPress hardening without turning off legitimate site features by default.', 'abdal-security-headers'); ?>
                        </p>
                    </div>
                </div>
                <div class="ash-page-header__actions">
                    <?php $this->render_help_menu(); ?>
                </div>
            </header>

            <?php settings_errors(); ?>

            <form method="post" action="options.php" id="ash-settings-form" class="ash-form" data-ash-features-page>
                <?php settings_fields('ash_options_group'); ?>
                <input type="hidden" name="ash_options[_ash_screen]" value="features">

                <div class="ash-features-stack">
                    <?php $this->render_powered_by_feature_card(); ?>
                    <?php $this->render_hide_version_feature_card(); ?>
                    <?php $this->render_login_errors_feature_card(); ?>
                    <?php $this->render_xmlrpc_feature_card(); ?>
                    <?php $this->render_pingback_header_feature_card(); ?>
                    <?php $this->render_rest_api_feature_card(); ?>
                </div>

                <?php $this->render_action_bar(); ?>
            </form>

            <?php $this->render_confirm_modal(); ?>
            <?php $this->render_credit_footer(); ?>
        </div>
        <?php
    }

    /**
     * Render the Remove X-Powered-By card.
     *
     * @return void
     */
    private function render_powered_by_feature_card() {
        $enabled = $this->is_enabled('remove_x_powered_by');
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-feature-card data-ash-enable="remove_x_powered_by">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-hidden" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Remove X-Powered-By Header', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('Hides server technology details exposed by the X-Powered-By header.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'remove_x_powered_by',
                    __('Enable Remove X-Powered-By Header', 'abdal-security-headers'),
                    __('When enabled, the plugin removes the X-Powered-By response header. There are no additional options.', 'abdal-security-headers'),
                    'features',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
            </div>
        </section>
        <?php
    }

    /**
     * Render the Hide WordPress Version card.
     *
     * @return void
     */
    private function render_hide_version_feature_card() {
        $enabled = $this->is_enabled('hide_wp_version');
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-feature-card data-ash-enable="hide_wp_version">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-wordpress" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Hide WordPress Version', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('WordPress exposes generator information in HTML, RSS, Atom, and RDF output.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'hide_wp_version',
                    __('Enable Hide WordPress Version', 'abdal-security-headers'),
                    __('Turn on WordPress version hiding, then choose which generator outputs to remove.', 'abdal-security-headers'),
                    'features',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <?php
                    $this->render_toggle_row(
                        'hide_generator_meta',
                        __('Hide Generator Meta Version', 'abdal-security-headers'),
                        __('Removes the generator meta tag from HTML output.', 'abdal-security-headers'),
                        'features'
                    );
                    $this->render_toggle_row(
                        'hide_version_feeds',
                        __('Hide Version from RSS / Atom / RDF Feeds', 'abdal-security-headers'),
                        __('Removes generator version strings from RSS, Atom, and RDF feeds.', 'abdal-security-headers'),
                        'features'
                    );
                    ?>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('Version query parameters are not removed from CSS or JavaScript assets, so cache busting keeps working.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the login error protection card.
     *
     * @return void
     */
    private function render_login_errors_feature_card() {
        $enabled = $this->is_enabled('remove_login_errors');
        $mode = $this->option_string('login_error_mode', 'generic');
        $custom = $this->option_string('login_error_custom', '');
        $choices = array(
            'generic' => __('Generic Error', 'abdal-security-headers'),
            'hide' => __('Hide Error Completely', 'abdal-security-headers'),
            'custom' => __('Custom Error Message', 'abdal-security-headers'),
        );
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-feature-card data-ash-enable="remove_login_errors">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-lock" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Remove Login Error Messages', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('Stop login failure responses from revealing whether a username or email address exists.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'remove_login_errors',
                    __('Enable Login Error Protection', 'abdal-security-headers'),
                    __('Only authentication failure messages are changed. Informational and successful login messages are left alone.', 'abdal-security-headers'),
                    'features',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <?php
                    $this->render_field_row(
                        __('Error Mode', 'abdal-security-headers'),
                        __('Choose how authentication failure messages are shown.', 'abdal-security-headers'),
                        $this->get_select_markup(
                            'ash-login-error-mode',
                            'ash_options[login_error_mode]',
                            $choices,
                            $mode,
                            array(
                                'data-ash-login-mode' => '1',
                            )
                        )
                    );
                    ?>
                    <div class="ash-field-row ash-field-row--block" data-ash-login-custom-row <?php echo $mode === 'custom' ? '' : 'hidden'; ?>>
                        <div class="ash-field-row__info">
                            <label class="ash-field-row__label" for="ash-login-error-custom"><?php echo esc_html__('Custom Error Message', 'abdal-security-headers'); ?></label>
                            <?php $this->render_info_icon(__('This plain-text message replaces authentication failure errors.', 'abdal-security-headers')); ?>
                        </div>
                        <div class="ash-field-row__control">
                            <input type="text"
                                   class="ash-input"
                                   id="ash-login-error-custom"
                                   name="ash_options[login_error_custom]"
                                   value="<?php echo esc_attr($custom); ?>"
                                   maxlength="200"
                                   autocomplete="off">
                        </div>
                    </div>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('Recommended mode is Generic Error. The default message is Invalid username or password.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the XML-RPC protection card.
     *
     * @return void
     */
    private function render_xmlrpc_feature_card() {
        $enabled = $this->is_enabled('disable_xmlrpc');
        $mode = $this->option_string('xmlrpc_mode', 'auth');
        $choices = array(
            'auth' => __('Disable Authenticated XML-RPC Methods', 'abdal-security-headers'),
            'pingback' => __('Disable Pingback Methods Only', 'abdal-security-headers'),
            'all' => __('Disable All XML-RPC Methods', 'abdal-security-headers'),
            'custom' => __('Custom Method Policy', 'abdal-security-headers'),
        );
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-feature-card data-ash-enable="disable_xmlrpc">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-share-alt2" aria-hidden="true"></span>
                <div>
                    <div class="ash-card__title-row">
                        <h2><?php echo esc_html__('Disable XML-RPC', 'abdal-security-headers'); ?></h2>
                        <span class="ash-badge ash-badge--warning" data-ash-xmlrpc-all-badge <?php echo $mode === 'all' ? '' : 'hidden'; ?>><?php echo esc_html__('High impact', 'abdal-security-headers'); ?></span>
                    </div>
                    <p><?php echo esc_html__('The WordPress xmlrpc_enabled filter only disables methods that require authentication. Pingbacks and some other methods can remain available.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'disable_xmlrpc',
                    __('Enable XML-RPC Protection', 'abdal-security-headers'),
                    __('Apply a selected XML-RPC policy instead of a single on/off switch.', 'abdal-security-headers'),
                    'features',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <?php
                    $this->render_field_row(
                        __('Protection Mode', 'abdal-security-headers'),
                        __('Choose which XML-RPC methods remain available.', 'abdal-security-headers'),
                        $this->get_select_markup(
                            'ash-xmlrpc-mode',
                            'ash_options[xmlrpc_mode]',
                            $choices,
                            $mode,
                            array(
                                'data-ash-xmlrpc-mode' => '1',
                            )
                        )
                    );
                    ?>
                    <div class="ash-callout ash-callout--warning" data-ash-xmlrpc-all-warning <?php echo $mode === 'all' ? '' : 'hidden'; ?>>
                        <?php echo esc_html__('Disable All XML-RPC Methods is the strongest restriction. Some applications and integrations depend on XML-RPC.', 'abdal-security-headers'); ?>
                    </div>
                    <div data-ash-xmlrpc-custom-panel <?php echo $mode === 'custom' ? '' : 'hidden'; ?>>
                        <?php
                        $this->render_field_row(
                            __('Allowed XML-RPC Methods', 'abdal-security-headers'),
                            __('One method name per line. If this list is not empty, only these methods remain.', 'abdal-security-headers'),
                            $this->get_textarea_markup(
                                'ash-xmlrpc-allow',
                                'ash_options[xmlrpc_allow_methods]',
                                $this->option_lines('xmlrpc_allow_methods'),
                                array(
                                    'placeholder' => 'wp.getPosts',
                                )
                            )
                        );
                        $this->render_field_row(
                            __('Blocked XML-RPC Methods', 'abdal-security-headers'),
                            __('One method name per line. These methods are removed even if they appear in the allow list.', 'abdal-security-headers'),
                            $this->get_textarea_markup(
                                'ash-xmlrpc-block',
                                'ash_options[xmlrpc_block_methods]',
                                $this->option_lines('xmlrpc_block_methods'),
                                array(
                                    'placeholder' => 'pingback.ping',
                                )
                            )
                        );
                        ?>
                    </div>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('Pingback mode blocks pingback.ping and pingback.extensions.getPingbacks. Removing the X-Pingback header is recommended when pingbacks or all XML-RPC methods are blocked.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the Remove X-Pingback Header card.
     *
     * @return void
     */
    private function render_pingback_header_feature_card() {
        $enabled = $this->is_enabled('remove_x_pingback');
        $xmlrpc_on = $this->is_enabled('disable_xmlrpc');
        $xmlrpc_mode = $this->option_string('xmlrpc_mode', 'auth');
        $recommend = $xmlrpc_on && in_array($xmlrpc_mode, array('pingback', 'all'), true) && !$enabled;
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-feature-card data-ash-enable="remove_x_pingback">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-admin-links" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Remove X-Pingback Header', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('Removes the X-Pingback response header from WordPress output.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'remove_x_pingback',
                    __('Enable Remove X-Pingback Header', 'abdal-security-headers'),
                    __('When enabled, the plugin removes the X-Pingback header. There are no additional options.', 'abdal-security-headers'),
                    'features',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                            'data-ash-pingback-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-callout ash-callout--warning" data-ash-pingback-recommend <?php echo $recommend ? '' : 'hidden'; ?>>
                    <?php echo esc_html__('XML-RPC pingback protection or complete XML-RPC blocking is enabled. Removing the X-Pingback header is recommended.', 'abdal-security-headers'); ?>
                </div>
            </div>
        </section>
        <?php
    }

    /**
     * Render the REST API access control card.
     *
     * @return void
     */
    private function render_rest_api_feature_card() {
        $enabled = $this->is_enabled('restrict_rest_api');
        $policy = $this->option_string('rest_access_policy', 'authenticated');
        $capability = $this->option_string('rest_capability', 'edit_posts');
        $selected_roles = isset($this->options['rest_roles']) && is_array($this->options['rest_roles']) ? $this->options['rest_roles'] : array();
        $users_on = $this->is_enabled('rest_users_restrict');
        $users_policy = $this->option_string('rest_users_policy', 'authenticated');
        $users_cap = $this->option_string('rest_users_capability', 'list_users');
        $policy_choices = array(
            'wordpress' => __('WordPress Default', 'abdal-security-headers'),
            'authenticated' => __('Authenticated Users Only', 'abdal-security-headers'),
            'roles' => __('Selected Roles', 'abdal-security-headers'),
            'capability' => __('Required Capability', 'abdal-security-headers'),
            'administrators' => __('Administrators Only', 'abdal-security-headers'),
            'block_all' => __('Block All REST Access', 'abdal-security-headers'),
        );
        $users_choices = array(
            'wordpress' => __('WordPress Default', 'abdal-security-headers'),
            'authenticated' => __('Authenticated Users Only', 'abdal-security-headers'),
            'capability' => __('Required Capability', 'abdal-security-headers'),
            'administrators' => __('Administrators Only', 'abdal-security-headers'),
        );
        ?>
        <section class="ash-card ash-header-card<?php echo $enabled ? '' : ' is-disabled'; ?>" data-ash-feature-card data-ash-enable="restrict_rest_api">
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-rest-api" aria-hidden="true"></span>
                <div>
                    <div class="ash-card__title-row">
                        <h2><?php echo esc_html__('Restrict REST API Access', 'abdal-security-headers'); ?></h2>
                        <span class="ash-badge ash-badge--warning" data-ash-rest-blockall-badge <?php echo $policy === 'block_all' ? '' : 'hidden'; ?>><?php echo esc_html__('High impact', 'abdal-security-headers'); ?></span>
                    </div>
                    <p><?php echo esc_html__('Apply a REST access policy. Gutenberg and other dashboard tools need REST access for authenticated users.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--list">
                <?php
                $this->render_toggle_row(
                    'restrict_rest_api',
                    __('Enable REST API Access Control', 'abdal-security-headers'),
                    __('When this is off, WordPress REST behavior is unchanged except for optional user-endpoint protection below.', 'abdal-security-headers'),
                    'features',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-header-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-header-card__config">
                    <?php
                    $this->render_field_row(
                        __('Access Policy', 'abdal-security-headers'),
                        __('WordPress Default applies no extra restriction. Administrators Only uses the manage_options capability.', 'abdal-security-headers'),
                        $this->get_select_markup(
                            'ash-rest-policy',
                            'ash_options[rest_access_policy]',
                            $policy_choices,
                            $policy,
                            array(
                                'data-ash-rest-policy' => '1',
                            )
                        )
                    );
                    ?>
                    <div class="ash-callout ash-callout--warning" data-ash-rest-blockall-warning <?php echo $policy === 'block_all' ? '' : 'hidden'; ?>>
                        <?php echo esc_html__('Block All REST Access is not recommended as a default. Gutenberg, Site Health, plugins, themes, and integrations may stop working.', 'abdal-security-headers'); ?>
                    </div>
                    <div data-ash-rest-roles-panel <?php echo $policy === 'roles' ? '' : 'hidden'; ?>>
                        <div class="ash-section-label"><?php echo esc_html__('Selected Roles', 'abdal-security-headers'); ?></div>
                        <p class="ash-section-help"><?php echo esc_html__('Roles are loaded from WordPress, including custom roles. Super Admins on Multisite are allowed.', 'abdal-security-headers'); ?></p>
                        <div class="ash-role-list">
                            <?php foreach ($this->get_role_choices() as $slug => $label) : ?>
                                <?php
                                $this->render_toggle_row(
                                    'rest_role_' . $slug,
                                    $label,
                                    '',
                                    'features',
                                    'ash_options',
                                    null,
                                    array(
                                        'name' => 'ash_options[rest_roles][]',
                                        'input_id' => 'ash-rest-role-' . $slug,
                                        'value' => $slug,
                                        'checked' => in_array($slug, $selected_roles, true),
                                    )
                                );
                                ?>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="ash-field-row ash-field-row--block" data-ash-rest-cap-row <?php echo $policy === 'capability' ? '' : 'hidden'; ?>>
                        <div class="ash-field-row__info">
                            <label class="ash-field-row__label" for="ash-rest-capability"><?php echo esc_html__('Required Capability', 'abdal-security-headers'); ?></label>
                            <?php $this->render_info_icon(__('Access is allowed when the current user has this WordPress capability. Examples: read, edit_posts, edit_pages, manage_options.', 'abdal-security-headers')); ?>
                        </div>
                        <div class="ash-field-row__control">
                            <input type="text"
                                   class="ash-input"
                                   id="ash-rest-capability"
                                   name="ash_options[rest_capability]"
                                   value="<?php echo esc_attr($capability); ?>"
                                   maxlength="64"
                                   spellcheck="false"
                                   autocomplete="off"
                                   dir="ltr"
                                   placeholder="edit_posts">
                        </div>
                    </div>
                    <div class="ash-section-label"><?php echo esc_html__('REST API Exceptions', 'abdal-security-headers'); ?></div>
                    <p class="ash-section-help"><?php echo esc_html__('Allow lists bypass the access policy. Restricted lists always block matching namespaces or routes.', 'abdal-security-headers'); ?></p>
                    <?php
                    $this->render_field_row(
                        __('Allowed Namespaces', 'abdal-security-headers'),
                        __('One namespace per line, such as wp/v2 or wc/v3. Custom plugin namespaces are allowed.', 'abdal-security-headers'),
                        $this->get_textarea_markup(
                            'ash-rest-allow-ns',
                            'ash_options[rest_allow_namespaces]',
                            $this->option_lines('rest_allow_namespaces'),
                            array(
                                'placeholder' => 'wp/v2',
                            )
                        )
                    );
                    $this->render_field_row(
                        __('Allowed Routes', 'abdal-security-headers'),
                        __('One route per line, such as /wp/v2/posts. Matching prefixes are included.', 'abdal-security-headers'),
                        $this->get_textarea_markup(
                            'ash-rest-allow-routes',
                            'ash_options[rest_allow_routes]',
                            $this->option_lines('rest_allow_routes'),
                            array(
                                'placeholder' => '/wp/v2/posts',
                            )
                        )
                    );
                    $this->render_field_row(
                        __('Restricted Namespaces', 'abdal-security-headers'),
                        __('These namespaces are blocked even if the access policy would allow them.', 'abdal-security-headers'),
                        $this->get_textarea_markup(
                            'ash-rest-deny-ns',
                            'ash_options[rest_deny_namespaces]',
                            $this->option_lines('rest_deny_namespaces'),
                            array(
                                'placeholder' => 'wp/v2',
                            )
                        )
                    );
                    $this->render_field_row(
                        __('Restricted Routes', 'abdal-security-headers'),
                        __('These routes are blocked even if the access policy would allow them.', 'abdal-security-headers'),
                        $this->get_textarea_markup(
                            'ash-rest-deny-routes',
                            'ash_options[rest_deny_routes]',
                            $this->option_lines('rest_deny_routes'),
                            array(
                                'placeholder' => '/wp/v2/users',
                            )
                        )
                    );
                    ?>
                </div>
                <div class="ash-section-label"><?php echo esc_html__('REST User Endpoint Protection', 'abdal-security-headers'); ?></div>
                <p class="ash-section-help"><?php echo esc_html__('Protect /wp/v2/users without disabling the rest of the REST API. This option can run even when Access Control is off.', 'abdal-security-headers'); ?></p>
                <?php
                $this->render_toggle_row(
                    'rest_users_restrict',
                    __('Restrict REST User Endpoints', 'abdal-security-headers'),
                    __('Applies an extra policy to user-related REST routes such as /wp/v2/users.', 'abdal-security-headers'),
                    'features',
                    'ash_options',
                    null,
                    array(
                        'attrs' => array(
                            'data-ash-users-enable' => '1',
                        ),
                    )
                );
                ?>
                <div class="ash-feature-subconfig<?php echo $users_on ? '' : ' is-muted'; ?>" data-ash-rest-users-panel>
                    <?php
                    $this->render_field_row(
                        __('Access Policy', 'abdal-security-headers'),
                        __('Choose who may access WordPress user REST endpoints.', 'abdal-security-headers'),
                        $this->get_select_markup(
                            'ash-rest-users-policy',
                            'ash_options[rest_users_policy]',
                            $users_choices,
                            $users_policy,
                            array(
                                'data-ash-rest-users-policy' => '1',
                            )
                        )
                    );
                    ?>
                    <div class="ash-field-row ash-field-row--block" data-ash-rest-users-cap-row <?php echo $users_policy === 'capability' ? '' : 'hidden'; ?>>
                        <div class="ash-field-row__info">
                            <label class="ash-field-row__label" for="ash-rest-users-capability"><?php echo esc_html__('Required Capability', 'abdal-security-headers'); ?></label>
                            <?php $this->render_info_icon(__('User endpoints are allowed when the current user has this capability.', 'abdal-security-headers')); ?>
                        </div>
                        <div class="ash-field-row__control">
                            <input type="text"
                                   class="ash-input"
                                   id="ash-rest-users-capability"
                                   name="ash_options[rest_users_capability]"
                                   value="<?php echo esc_attr($users_cap); ?>"
                                   maxlength="64"
                                   spellcheck="false"
                                   autocomplete="off"
                                   dir="ltr"
                                   placeholder="list_users">
                        </div>
                    </div>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('REST API Access Control is off for new installations. If you enable it, Authenticated Users Only is the default policy. Block All REST Access is never the default.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the Content Security Policy screen, including Smart CSP Assistant.
     *
     * @return void
     */
    public function render_content_security_policy() {
        $directive_fields = $this->get_csp_directive_fields();
        $general_fields = $this->get_csp_general_fields();
        ?>
        <div class="wrap ash-wrap">
            <header class="ash-page-header">
                <div class="ash-page-header__main">
                    <span class="ash-page-header__icon dashicons dashicons-media-document" aria-hidden="true"></span>
                    <div class="ash-page-header__copy">
                        <div class="ash-page-header__title-row">
                            <h1><?php echo esc_html__('Content Security Policy', 'abdal-security-headers'); ?></h1>
                            <span class="ash-badge ash-badge--neutral">
                                <?php
                                echo esc_html(
                                    sprintf(
                                        /* translators: %s: plugin version number */
                                        __('Version %s', 'abdal-security-headers'),
                                        ASH_VERSION
                                    )
                                );
                                ?>
                            </span>
                        </div>
                        <p class="ash-page-header__subtitle">
                            <?php echo esc_html__('Configure Content Security Policy (CSP) directives', 'abdal-security-headers'); ?>
                        </p>
                    </div>
                </div>
                <div class="ash-page-header__actions">
                    <?php $this->render_help_menu(); ?>
                </div>
            </header>

            <?php settings_errors(); ?>

            <form method="post" action="options.php" id="ash-settings-form" class="ash-form">
                <?php settings_fields('ash_options_group'); ?>
                <input type="hidden" name="ash_options[_ash_screen]" value="csp">

                <?php
                if (class_exists('ASH_CSP_Assistant')) {
                    ASH_CSP_Assistant::render_admin_card();
                }
                ?>

                <section class="ash-card ash-card--csp" data-ash-csp-card>
                    <header class="ash-card__header">
                        <span class="ash-card__icon dashicons dashicons-shield" aria-hidden="true"></span>
                        <div>
                            <h2><?php echo esc_html__('Content Security Policy', 'abdal-security-headers'); ?></h2>
                            <p><?php echo esc_html__('Configure Content Security Policy (CSP) directives', 'abdal-security-headers'); ?></p>
                        </div>
                    </header>

                    <div class="ash-csp-layout">
                        <div class="ash-csp-panel ash-csp-general">
                            <h3><?php echo esc_html__('General settings', 'abdal-security-headers'); ?></h3>
                            <div class="ash-csp-general__body">
                                <?php $this->render_toggle_row('content_security_policy', esc_html__('Enable Content Security Policy', 'abdal-security-headers'), esc_html__('When enabled, the generated Content-Security-Policy header is sent with HTTP responses.', 'abdal-security-headers'), 'csp'); ?>
                                <?php foreach ($general_fields as $id => $field) : ?>
                                    <?php $this->render_text_field($id, $field['label'], $field['description'], $field['directive']); ?>
                                <?php endforeach; ?>
                            </div>
                        </div>

                        <div class="ash-csp-panel ash-csp-directives" data-ash-csp-panel>
                            <h3><?php echo esc_html__('CSP Directives', 'abdal-security-headers'); ?></h3>
                            <div class="ash-csp-grid">
                                <?php foreach ($directive_fields as $id => $field) : ?>
                                    <?php $this->render_text_field($id, $field['label'], $field['description'], $field['directive'], true); ?>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>

                    <div class="ash-csp-preview">
                        <div class="ash-csp-preview__header">
                            <h3><?php echo esc_html__('CSP Header Preview', 'abdal-security-headers'); ?></h3>
                        </div>
                        <div class="ash-codebox">
                            <button type="button" class="ash-copy" data-ash-copy aria-label="<?php echo esc_attr__('Copy CSP header', 'abdal-security-headers'); ?>" title="<?php echo esc_attr__('Copy CSP header', 'abdal-security-headers'); ?>">
                                <span class="dashicons dashicons-admin-page" aria-hidden="true"></span>
                            </button>
                            <pre id="csp-preview-content" class="ash-codebox__content"></pre>
                        </div>
                    </div>
                </section>

                <?php $this->render_action_bar(); ?>
            </form>

            <?php $this->render_confirm_modal(); ?>
            <?php $this->render_csp_editor_modal(); ?>
            <?php $this->render_credit_footer(); ?>
        </div>
        <?php
    }

    /**
     * Render the plugin Settings screen.
     *
     * @param array $plugin_settings Stored plugin-owned settings.
     * @return void
     */
    public function render_plugin_settings($plugin_settings) {
        if (!is_array($plugin_settings)) {
            $plugin_settings = array();
        }
        ?>
        <div class="wrap ash-wrap" data-ash-settings-page>
            <header class="ash-page-header">
                <div class="ash-page-header__main">
                    <span class="ash-page-header__icon dashicons dashicons-admin-generic" aria-hidden="true"></span>
                    <div class="ash-page-header__copy">
                        <div class="ash-page-header__title-row">
                            <h1><?php echo esc_html__('Settings', 'abdal-security-headers'); ?></h1>
                            <span class="ash-badge ash-badge--neutral">
                                <?php
                                echo esc_html(
                                    sprintf(
                                        /* translators: %s: plugin version number */
                                        __('Version %s', 'abdal-security-headers'),
                                        ASH_VERSION
                                    )
                                );
                                ?>
                            </span>
                        </div>
                        <p class="ash-page-header__subtitle">
                            <?php echo esc_html__('Export or import plugin configuration, and choose what happens to stored data on uninstall.', 'abdal-security-headers'); ?>
                        </p>
                    </div>
                </div>
                <div class="ash-page-header__actions">
                    <?php $this->render_help_menu(); ?>
                </div>
            </header>

            <?php settings_errors(); ?>

            <?php $this->render_settings_transfer(); ?>

            <form method="post" action="options.php" id="ash-settings-form" class="ash-form">
                <?php settings_fields('ash_plugin_settings_group'); ?>
                <input type="hidden" name="ash_plugin_settings[remove_data_on_uninstall]" value="0">

                <section class="ash-card">
                    <header class="ash-card__header">
                        <span class="ash-card__icon ash-card__icon--warning dashicons dashicons-trash" aria-hidden="true"></span>
                        <div>
                            <h2><?php echo esc_html__('Uninstall', 'abdal-security-headers'); ?></h2>
                            <p><?php echo esc_html__('Control what happens to stored plugin data when this plugin is deleted.', 'abdal-security-headers'); ?></p>
                        </div>
                    </header>
                    <div class="ash-card__body ash-card__body--list">
                        <?php
                        $this->render_toggle_row(
                            'remove_data_on_uninstall',
                            __('Delete all plugin data on uninstall', 'abdal-security-headers'),
                            __('When enabled, deleting this plugin also removes its settings, CSP assistant data, custom tables, and related stored files. This cannot be undone.', 'abdal-security-headers'),
                            'plugin',
                            'ash_plugin_settings',
                            $plugin_settings
                        );
                        ?>
                    </div>
                    <footer class="ash-card__footer">
                        <span class="dashicons dashicons-info" aria-hidden="true"></span>
                        <?php echo esc_html__('Leave this off if you want to keep your configuration after the plugin is deleted.', 'abdal-security-headers'); ?>
                    </footer>
                </section>

                <?php $this->render_action_bar(); ?>
            </form>

            <?php $this->render_confirm_modal(); ?>
            <?php $this->render_credit_footer(); ?>
        </div>
        <?php
    }

    /**
     * Export and import card. Kept outside the Uninstall form so file uploads cannot collide with Save.
     *
     * @return void
     */
    private function render_settings_transfer() {
        ?>
        <section class="ash-card" data-ash-settings-transfer>
            <header class="ash-card__header">
                <span class="ash-card__icon dashicons dashicons-download" aria-hidden="true"></span>
                <div>
                    <h2><?php echo esc_html__('Export and Import', 'abdal-security-headers'); ?></h2>
                    <p><?php echo esc_html__('Download a JSON file of all plugin settings, or restore them from a previous export.', 'abdal-security-headers'); ?></p>
                </div>
            </header>
            <div class="ash-card__body ash-card__body--padded">
                <div class="ash-transfer">
                    <div class="ash-transfer__block">
                        <p class="ash-section-help">
                            <?php echo esc_html__('Export includes Security Headers, Security Features, Content Security Policy, Security Profile, uninstall settings, and CSP Assistant scan exclusions.', 'abdal-security-headers'); ?>
                        </p>
                        <div class="ash-quick-actions">
                            <button type="button" class="ash-btn ash-btn--secondary" data-ash-export-settings>
                                <span class="dashicons dashicons-download" aria-hidden="true"></span>
                                <span class="ash-btn__label"><?php echo esc_html__('Export', 'abdal-security-headers'); ?></span>
                                <span class="ash-spinner" aria-hidden="true"></span>
                            </button>
                        </div>
                    </div>
                    <div class="ash-transfer__block">
                        <p class="ash-section-help">
                            <?php echo esc_html__('Import replaces the current plugin configuration on this site. Choose a JSON file exported from Abdal Security Headers.', 'abdal-security-headers'); ?>
                        </p>
                        <div class="ash-callout ash-callout--warning">
                            <strong><?php echo esc_html__('Import cannot be undone from this screen.', 'abdal-security-headers'); ?></strong>
                            <span><?php echo esc_html__('Security Headers, Security Features, Content Security Policy, Security Profile, and Settings will be overwritten.', 'abdal-security-headers'); ?></span>
                        </div>
                        <input
                            type="file"
                            id="ash-import-file"
                            class="ash-file-input"
                            name="ash_import_file"
                            accept=".json,application/json"
                            data-ash-import-file
                            aria-describedby="ash-import-filename"
                            aria-label="<?php echo esc_attr__('Settings JSON file', 'abdal-security-headers'); ?>"
                        >
                        <div class="ash-transfer__file">
                            <button type="button" class="ash-btn ash-btn--secondary" data-ash-choose-file>
                                <span class="dashicons dashicons-media-default" aria-hidden="true"></span>
                                <?php echo esc_html__('Choose file', 'abdal-security-headers'); ?>
                            </button>
                            <span class="ash-transfer__filename" id="ash-import-filename" data-ash-import-filename>
                                <?php echo esc_html__('No file selected', 'abdal-security-headers'); ?>
                            </span>
                        </div>
                        <div class="ash-quick-actions">
                            <button type="button" class="ash-btn ash-btn--primary" data-ash-import-settings>
                                <span class="dashicons dashicons-upload" aria-hidden="true"></span>
                                <span class="ash-btn__label"><?php echo esc_html__('Import', 'abdal-security-headers'); ?></span>
                                <span class="ash-spinner" aria-hidden="true"></span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            <footer class="ash-card__footer">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('The export does not include CSP Assistant learning data or scan jobs.', 'abdal-security-headers'); ?>
            </footer>
        </section>
        <?php
    }

    /**
     * Render the shared Help dropdown.
     *
     * @return void
     */
    private function render_help_menu() {
        ?>
        <div class="ash-help" data-ash-help>
            <button type="button" class="ash-help__toggle" data-ash-help-toggle aria-expanded="false" aria-haspopup="true">
                <span class="dashicons dashicons-editor-help" aria-hidden="true"></span>
                <?php echo esc_html__('Help', 'abdal-security-headers'); ?>
                <span class="dashicons dashicons-arrow-down-alt2" aria-hidden="true"></span>
            </button>
            <div class="ash-help__menu" hidden>
                <a href="https://github.com/ebrasha/abdal-security-headers" target="_blank" rel="noopener noreferrer">
                    <?php echo esc_html__('Documentation', 'abdal-security-headers'); ?>
                </a>
                <a href="https://github.com/ebrasha/abdal-security-headers/issues" target="_blank" rel="noopener noreferrer">
                    <?php echo esc_html__('Report an issue', 'abdal-security-headers'); ?>
                </a>
                <a href="mailto:Prof.Shafiei@Gmail.com">
                    <?php echo esc_html__('Contact support', 'abdal-security-headers'); ?>
                </a>
            </div>
        </div>
        <?php
    }

    /**
     * Render the programmer credit as the last visible item on plugin admin screens.
     *
     * @return void
     */
    private function render_credit_footer() {
        ?>
        <footer class="ash-credit">
            <?php echo esc_html__('Handcrafted with ❤️ Passion by Ebrahim Shafiei (EbraSha)', 'abdal-security-headers'); ?>
        </footer>
        <?php
    }

    /**
     * Render the sticky Save / Reset bar used by settings forms.
     *
     * @return void
     */
    private function render_action_bar() {
        ?>
        <div class="ash-action-bar" data-ash-action-bar>
            <p class="ash-action-bar__note">
                <span class="dashicons dashicons-info" aria-hidden="true"></span>
                <?php echo esc_html__('Your changes are not saved automatically.', 'abdal-security-headers'); ?>
            </p>
            <div class="ash-action-bar__actions">
                <button type="button" class="ash-btn ash-btn--secondary" id="ash-reset-button">
                    <span class="dashicons dashicons-image-rotate" aria-hidden="true"></span>
                    <?php echo esc_html__('Reset', 'abdal-security-headers'); ?>
                </button>
                <button type="submit" class="ash-btn ash-btn--primary" id="ash-submit-button" name="submit" value="1">
                    <span class="dashicons dashicons-lock" aria-hidden="true"></span>
                    <span class="ash-btn__label"><?php echo esc_html__('Save Changes', 'abdal-security-headers'); ?></span>
                    <span class="ash-spinner" aria-hidden="true"></span>
                </button>
            </div>
        </div>
        <?php
    }

    /**
     * Render the large CSP directive editor overlay.
     *
     * @return void
     */
    private function render_csp_editor_modal() {
        ?>
        <div class="ash-modal ash-modal--editor" id="ash-csp-editor-modal" hidden>
            <div class="ash-modal__backdrop" data-ash-csp-editor-dismiss></div>
            <div class="ash-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="ash-csp-editor-title">
                <h2 id="ash-csp-editor-title"></h2>
                <div class="ash-csp-editor__body">
                    <textarea id="ash-csp-editor-text" spellcheck="false" autocomplete="off" dir="ltr"></textarea>
                </div>
                <div class="ash-modal__actions">
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-csp-editor-cancel>
                        <?php echo esc_html__('Cancel', 'abdal-security-headers'); ?>
                    </button>
                    <button type="button" class="ash-btn ash-btn--primary" data-ash-csp-editor-ok>
                        <?php echo esc_html_x('OK', 'csp editor confirm', 'abdal-security-headers'); ?>
                    </button>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render the shared confirm/alert overlay used by Save and Reset.
     *
     * @return void
     */
    private function render_confirm_modal() {
        ?>
        <div class="ash-modal" id="ash-confirm-modal" hidden>
            <div class="ash-modal__backdrop" data-ash-confirm-dismiss></div>
            <div class="ash-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="ash-confirm-modal-title">
                <h2 id="ash-confirm-modal-title"></h2>
                <div id="ash-confirm-modal-body"></div>
                <div class="ash-modal__actions">
                    <button type="button" class="ash-btn ash-btn--secondary" data-ash-confirm-cancel>
                        <?php echo esc_html__('Cancel', 'abdal-security-headers'); ?>
                    </button>
                    <button type="button" class="ash-btn ash-btn--primary" data-ash-confirm-ok>
                        <?php echo esc_html__('Yes', 'abdal-security-headers'); ?>
                    </button>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render a compact toggle row used by settings cards.
     *
     * @param string     $id Field option key.
     * @param string     $label Translated field label.
     * @param string     $description Translated helper text.
     * @param string     $group Summary group identifier.
     * @param string     $option_name Option array name in the form.
     * @param array|null $values Option values for this row. Defaults to header options.
     * @param array      $args Optional name, input_id, checked, row_class, and attrs.
     * @return void
     */
    private function render_toggle_row($id, $label, $description, $group, $option_name = 'ash_options', $values = null, $args = array()) {
        $source = is_array($values) ? $values : $this->options;
        $checked = isset($source[$id]) && (string) $source[$id] === '1';
        if (!is_array($args)) {
            $args = array();
        }
        if (array_key_exists('checked', $args)) {
            $checked = (bool) $args['checked'];
        }
        $name = isset($args['name']) ? (string) $args['name'] : $option_name . '[' . $id . ']';
        $input_id = isset($args['input_id']) ? (string) $args['input_id'] : $id;
        $value = isset($args['value']) ? (string) $args['value'] : '1';
        $row_class = isset($args['row_class']) ? trim('ash-toggle-row ' . (string) $args['row_class']) : 'ash-toggle-row';
        $attrs = isset($args['attrs']) && is_array($args['attrs']) ? $args['attrs'] : array();
        ?>
        <div class="<?php echo esc_attr($row_class); ?>">
            <div class="ash-toggle-row__info">
                <label class="ash-toggle-row__label" for="<?php echo esc_attr($input_id); ?>"><?php echo esc_html($label); ?></label>
                <?php $this->render_info_icon($description); ?>
            </div>
            <label class="ash-switch">
                <input type="checkbox"
                       id="<?php echo esc_attr($input_id); ?>"
                       name="<?php echo esc_attr($name); ?>"
                       value="<?php echo esc_attr($value); ?>"
                       data-ash-group="<?php echo esc_attr($group); ?>"
                       <?php
                        foreach ($attrs as $attr_name => $attr_value) {
                            $safe_name = preg_replace('/[^a-zA-Z0-9_-]/', '', (string) $attr_name);
                            if ($safe_name === '') {
                                continue;
                            }
                            echo ' ' . $safe_name . '="' . esc_attr((string) $attr_value) . '"';
                        }
                        ?>
                       <?php checked(true, $checked); ?>>
                <span class="ash-switch__ui" aria-hidden="true"></span>
            </label>
        </div>
        <?php
    }

    /**
     * Render a CSP text input with a technical label and helper description.
     *
     * @param string $id Field option key.
     * @param string $label Translated field label.
     * @param string $description Translated helper text.
     * @param string $directive CSP directive name.
     * @param bool   $use_editor Open the large editor modal when the field is activated.
     * @return void
     */
    private function render_text_field($id, $label, $description, $directive, $use_editor = false) {
        $value = isset($this->options[$id]) ? $this->options[$id] : '';
        ?>
        <div class="ash-text-field">
            <div class="ash-text-field__label-row">
                <label for="<?php echo esc_attr($id); ?>">
                    <span class="ash-text-field__name"><?php echo esc_html($directive); ?></span>
                    <span class="ash-text-field__hint"><?php echo esc_html($label); ?></span>
                </label>
                <?php $this->render_info_icon($description); ?>
            </div>
            <input type="text"
                   id="<?php echo esc_attr($id); ?>"
                   name="ash_options[<?php echo esc_attr($id); ?>]"
                   value="<?php echo esc_attr($value); ?>"
                   spellcheck="false"
                   autocomplete="off"
                   data-csp-directive="<?php echo esc_attr($directive); ?>"
                   <?php echo $use_editor ? 'readonly data-ash-csp-editor="1"' : ''; ?>>
        </div>
        <?php
    }

    /**
     * Render a compact info icon with accessible helper text.
     *
     * @param string $description Translated description.
     * @return void
     */
    private function render_info_icon($description) {
        if ($description === '') {
            return;
        }
        ?>
        <span class="ash-info" tabindex="0" role="img" aria-label="<?php echo esc_attr($description); ?>" title="<?php echo esc_attr($description); ?>">
            <span class="dashicons dashicons-info" aria-hidden="true"></span>
        </span>
        <?php
    }

    /**
     * Get security header toggle definitions.
     *
     * @return array
     */
    private function get_header_fields() {
        return array(
            'x_xss_protection' => array(
                'label' => __('X-XSS-Protection', 'abdal-security-headers'),
                'description' => __('Enables the legacy browser XSS filter for older clients.', 'abdal-security-headers'),
            ),
            'x_content_type_options' => array(
                'label' => __('X-Content-Type-Options', 'abdal-security-headers'),
                'description' => __('Prevents browsers from MIME-sniffing a response away from the declared content type.', 'abdal-security-headers'),
            ),
            'strict_transport_security' => array(
                'label' => __('Strict-Transport-Security', 'abdal-security-headers'),
                'description' => __('Forces browsers to use HTTPS for future requests to this host.', 'abdal-security-headers'),
            ),
            'permissions_policy' => array(
                'label' => __('Permissions-Policy', 'abdal-security-headers'),
                'description' => __('Restricts access to powerful browser features such as camera and geolocation.', 'abdal-security-headers'),
            ),
            'x_frame_options' => array(
                'label' => __('X-Frame-Options', 'abdal-security-headers'),
                'description' => __('Controls whether the site can be embedded in frames to reduce clickjacking risk.', 'abdal-security-headers'),
            ),
            'referrer_policy' => array(
                'label' => __('Referrer-Policy', 'abdal-security-headers'),
                'description' => __('Limits referrer information sent with navigations and resource requests.', 'abdal-security-headers'),
            ),
        );
    }

    /**
     * Get additional security feature toggle definitions.
     *
     * @return array
     */
    private function get_feature_fields() {
        return array(
            'remove_x_powered_by' => array(
                'label' => __('Remove X-Powered-By Header', 'abdal-security-headers'),
                'description' => __('Hides server technology details exposed by the X-Powered-By header.', 'abdal-security-headers'),
            ),
            'hide_wp_version' => array(
                'label' => __('Hide WordPress Version', 'abdal-security-headers'),
                'description' => __('Removes the public WordPress version from generator markup and feeds.', 'abdal-security-headers'),
            ),
            'remove_login_errors' => array(
                'label' => __('Remove Login Error Messages', 'abdal-security-headers'),
                'description' => __('Replaces detailed login errors with a generic message to reduce user enumeration.', 'abdal-security-headers'),
            ),
            'disable_xmlrpc' => array(
                'label' => __('Disable XML-RPC', 'abdal-security-headers'),
                'description' => __('Applies a selected XML-RPC method policy instead of a single complete shutdown.', 'abdal-security-headers'),
            ),
            'remove_x_pingback' => array(
                'label' => __('Remove X-Pingback Header', 'abdal-security-headers'),
                'description' => __('Removes the X-Pingback response header from WordPress output.', 'abdal-security-headers'),
            ),
            'restrict_rest_api' => array(
                'label' => __('Restrict REST API Access', 'abdal-security-headers'),
                'description' => __('Applies a configurable REST API access policy instead of blocking every request.', 'abdal-security-headers'),
            ),
        );
    }

    /**
     * Get CSP source directive fields shown in the main grid.
     *
     * @return array
     */
    private function get_csp_directive_fields() {
        return array(
            'csp_default_src' => array(
                'label' => __('Default Source', 'abdal-security-headers'),
                'directive' => 'default-src',
                'description' => __('Default fallback for other resource types', 'abdal-security-headers'),
            ),
            'csp_script_src' => array(
                'label' => __('Script Source', 'abdal-security-headers'),
                'directive' => 'script-src',
                'description' => __('Valid sources for JavaScript files', 'abdal-security-headers'),
            ),
            'csp_style_src' => array(
                'label' => __('Style Source', 'abdal-security-headers'),
                'directive' => 'style-src',
                'description' => __('Valid sources for CSS files', 'abdal-security-headers'),
            ),
            'csp_img_src' => array(
                'label' => __('Image Source', 'abdal-security-headers'),
                'directive' => 'img-src',
                'description' => __('Valid sources for images', 'abdal-security-headers'),
            ),
            'csp_connect_src' => array(
                'label' => __('Connect Source', 'abdal-security-headers'),
                'directive' => 'connect-src',
                'description' => __('Valid sources for AJAX, WebSocket, or EventSource connections', 'abdal-security-headers'),
            ),
            'csp_font_src' => array(
                'label' => __('Font Source', 'abdal-security-headers'),
                'directive' => 'font-src',
                'description' => __('Valid sources for fonts', 'abdal-security-headers'),
            ),
            'csp_object_src' => array(
                'label' => __('Object Source', 'abdal-security-headers'),
                'directive' => 'object-src',
                'description' => __('Valid sources for plugins', 'abdal-security-headers'),
            ),
            'csp_media_src' => array(
                'label' => __('Media Source', 'abdal-security-headers'),
                'directive' => 'media-src',
                'description' => __('Valid sources for audio and video elements', 'abdal-security-headers'),
            ),
            'csp_frame_src' => array(
                'label' => __('Frame Source', 'abdal-security-headers'),
                'directive' => 'frame-src',
                'description' => __('Valid sources for iframes', 'abdal-security-headers'),
            ),
            'csp_worker_src' => array(
                'label' => __('Worker Source', 'abdal-security-headers'),
                'directive' => 'worker-src',
                'description' => __('Valid sources for web workers', 'abdal-security-headers'),
            ),
            'csp_form_action' => array(
                'label' => __('Form Action', 'abdal-security-headers'),
                'directive' => 'form-action',
                'description' => __('Valid targets for form submissions', 'abdal-security-headers'),
            ),
            'csp_base_uri' => array(
                'label' => __('Base URI', 'abdal-security-headers'),
                'directive' => 'base-uri',
                'description' => __('Valid values for the base element', 'abdal-security-headers'),
            ),
            'csp_sandbox' => array(
                'label' => __('Sandbox', 'abdal-security-headers'),
                'directive' => 'sandbox',
                'description' => __('Enables sandbox for the requested resource', 'abdal-security-headers'),
            ),
        );
    }

    /**
     * Get CSP reporting fields shown in the general settings panel.
     *
     * @return array
     */
    private function get_csp_general_fields() {
        return array(
            'csp_report_uri' => array(
                'label' => __('Report URI', 'abdal-security-headers'),
                'directive' => 'report-uri',
                'description' => __('URI to send violation reports to', 'abdal-security-headers'),
            ),
            'csp_report_to' => array(
                'label' => __('Report To', 'abdal-security-headers'),
                'directive' => 'report-to',
                'description' => __('Group name for violation reports', 'abdal-security-headers'),
            ),
        );
    }

    /**
     * Check whether a stored option is enabled.
     *
     * @param string $key Option key.
     * @return bool
     */
    private function is_enabled($key) {
        return isset($this->options[$key]) && (string) $this->options[$key] === '1';
    }

    /**
     * Count enabled options from a list of keys.
     *
     * @param array $keys Option keys.
     * @return int
     */
    private function count_enabled($keys) {
        $count = 0;
        foreach ($keys as $key) {
            if ($this->is_enabled($key)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Derive the summary security status from enabled settings.
     *
     * @param int $header_active Enabled header count.
     * @param int $header_total Total header count.
     * @param int $feature_active Enabled feature count.
     * @param int $feature_total Total feature count.
     * @return array
     */
    private function get_security_status($header_active, $header_total, $feature_active, $feature_total) {
        $total = $header_total + $feature_total;
        $active = $header_active + $feature_active;
        $ratio = $total > 0 ? ($active / $total) : 0;

        if ($ratio >= 0.75) {
            return array(
                'tone' => 'green',
                'label' => _x('Good', 'security status', 'abdal-security-headers'),
                'hint' => __('Most security controls are enabled.', 'abdal-security-headers'),
            );
        }

        if ($ratio >= 0.4) {
            return array(
                'tone' => 'warning',
                'label' => _x('Fair', 'security status', 'abdal-security-headers'),
                'hint' => __('Some recommended security controls are still disabled.', 'abdal-security-headers'),
            );
        }

        return array(
            'tone' => 'muted',
            'label' => _x('Needs attention', 'security status', 'abdal-security-headers'),
            'hint' => __('Enable more security headers and hardening options.', 'abdal-security-headers'),
        );
    }
}
