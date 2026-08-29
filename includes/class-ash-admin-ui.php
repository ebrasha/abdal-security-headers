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
    }

    /**
     * Render the complete settings dashboard.
     *
     * @return void
     */
    public function render() {
        $header_fields = $this->get_header_fields();
        $feature_fields = $this->get_feature_fields();
        $directive_fields = $this->get_csp_directive_fields();
        $general_fields = $this->get_csp_general_fields();

        $header_total = count($header_fields);
        $feature_total = count($feature_fields);
        $header_active = $this->count_enabled(array_keys($header_fields));
        $feature_active = $this->count_enabled(array_keys($feature_fields));
        $csp_enabled = $this->is_enabled('content_security_policy');
        $status = $this->get_security_status($header_active, $header_total, $feature_active, $feature_total);
        ?>
        <div class="wrap ash-wrap">
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
                            <?php echo esc_html__('Configure HTTP security headers, hardening options, and Content Security Policy from one dashboard.', 'abdal-security-headers'); ?>
                        </p>
                    </div>
                </div>
                <div class="ash-page-header__actions">
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
                </div>
            </header>

            <?php settings_errors(); ?>

            <form method="post" action="options.php" id="ash-settings-form" class="ash-form">
                <?php settings_fields('ash_options_group'); ?>

                <section class="ash-summary-grid" aria-label="<?php echo esc_attr__('Security overview', 'abdal-security-headers'); ?>">
                    <article class="ash-summary-card ash-summary-card--<?php echo esc_attr($status['tone']); ?>" data-ash-summary="status">
                        <span class="ash-summary-card__icon dashicons dashicons-shield" aria-hidden="true"></span>
                        <div class="ash-summary-card__body">
                            <span class="ash-summary-card__label"><?php echo esc_html__('Security status', 'abdal-security-headers'); ?></span>
                            <strong class="ash-summary-card__value" data-ash-summary-value><?php echo esc_html($status['label']); ?></strong>
                            <span class="ash-summary-card__hint" data-ash-summary-hint><?php echo esc_html($status['hint']); ?></span>
                        </div>
                    </article>

                    <article class="ash-summary-card ash-summary-card--blue" data-ash-summary="headers">
                        <span class="ash-summary-card__icon dashicons dashicons-screenoptions" aria-hidden="true"></span>
                        <div class="ash-summary-card__body">
                            <span class="ash-summary-card__label"><?php echo esc_html__('Active headers', 'abdal-security-headers'); ?></span>
                            <strong class="ash-summary-card__value" data-ash-summary-value><?php echo esc_html($header_active . ' / ' . $header_total); ?></strong>
                            <span class="ash-summary-card__hint" data-ash-summary-hint>
                                <?php
                                echo esc_html(
                                    sprintf(
                                        /* translators: 1: number of enabled headers, 2: total headers */
                                        __('%1$d of %2$d security headers are enabled', 'abdal-security-headers'),
                                        $header_active,
                                        $header_total
                                    )
                                );
                                ?>
                            </span>
                        </div>
                    </article>

                    <article class="ash-summary-card ash-summary-card--purple" data-ash-summary="features">
                        <span class="ash-summary-card__icon dashicons dashicons-admin-plugins" aria-hidden="true"></span>
                        <div class="ash-summary-card__body">
                            <span class="ash-summary-card__label"><?php echo esc_html__('Additional features', 'abdal-security-headers'); ?></span>
                            <strong class="ash-summary-card__value" data-ash-summary-value><?php echo esc_html($feature_active . ' / ' . $feature_total); ?></strong>
                            <span class="ash-summary-card__hint" data-ash-summary-hint>
                                <?php
                                echo esc_html(
                                    sprintf(
                                        /* translators: 1: number of enabled features, 2: total features */
                                        __('%1$d of %2$d additional features are enabled', 'abdal-security-headers'),
                                        $feature_active,
                                        $feature_total
                                    )
                                );
                                ?>
                            </span>
                        </div>
                    </article>

                    <article class="ash-summary-card <?php echo $csp_enabled ? 'ash-summary-card--green' : 'ash-summary-card--muted'; ?>" data-ash-summary="csp">
                        <span class="ash-summary-card__icon dashicons dashicons-media-document" aria-hidden="true"></span>
                        <div class="ash-summary-card__body">
                            <span class="ash-summary-card__label"><?php echo esc_html__('CSP status', 'abdal-security-headers'); ?></span>
                            <strong class="ash-summary-card__value" data-ash-summary-value>
                                <?php echo $csp_enabled ? esc_html_x('Enabled', 'CSP status', 'abdal-security-headers') : esc_html_x('Disabled', 'CSP status', 'abdal-security-headers'); ?>
                            </strong>
                            <span class="ash-summary-card__hint" data-ash-summary-hint>
                                <?php echo $csp_enabled ? esc_html__('Content Security Policy is being sent with responses.', 'abdal-security-headers') : esc_html__('Content Security Policy is currently turned off.', 'abdal-security-headers'); ?>
                            </span>
                        </div>
                    </article>
                </section>

                <div class="ash-settings-grid">
                    <section class="ash-card">
                        <header class="ash-card__header">
                            <span class="ash-card__icon dashicons dashicons-lock" aria-hidden="true"></span>
                            <div>
                                <h2><?php echo esc_html__('Security Headers', 'abdal-security-headers'); ?></h2>
                                <p><?php echo esc_html__('Enable the core HTTP security headers for the site.', 'abdal-security-headers'); ?></p>
                            </div>
                        </header>
                        <div class="ash-card__body ash-card__body--list">
                            <?php foreach ($header_fields as $id => $field) : ?>
                                <?php $this->render_toggle_row($id, $field['label'], $field['description'], 'headers'); ?>
                            <?php endforeach; ?>
                        </div>
                        <footer class="ash-card__footer">
                            <span class="dashicons dashicons-lock" aria-hidden="true"></span>
                            <?php echo esc_html__('Configure basic security headers for your website.', 'abdal-security-headers'); ?>
                        </footer>
                    </section>

                    <section class="ash-card">
                        <header class="ash-card__header">
                            <span class="ash-card__icon dashicons dashicons-admin-tools" aria-hidden="true"></span>
                            <div>
                                <h2><?php echo esc_html__('Additional Security Features', 'abdal-security-headers'); ?></h2>
                                <p><?php echo esc_html__('Harden WordPress by reducing information disclosure and attack surface.', 'abdal-security-headers'); ?></p>
                            </div>
                        </header>
                        <div class="ash-card__body ash-card__body--list">
                            <?php foreach ($feature_fields as $id => $field) : ?>
                                <?php $this->render_toggle_row($id, $field['label'], $field['description'], 'features'); ?>
                            <?php endforeach; ?>
                        </div>
                        <footer class="ash-card__footer">
                            <span class="dashicons dashicons-admin-tools" aria-hidden="true"></span>
                            <?php echo esc_html__('Enable additional security features to enhance your website protection.', 'abdal-security-headers'); ?>
                        </footer>
                    </section>
                </div>

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
            </form>

            <footer class="ash-credit">
                <?php echo esc_html__('Handcrafted with ❤️ Passion by Ebrahim Shafiei (EbraSha)', 'abdal-security-headers'); ?>
            </footer>

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
        </div>
        <?php
    }

    /**
     * Render a compact toggle row used by settings cards.
     *
     * @param string $id Field option key.
     * @param string $label Translated field label.
     * @param string $description Translated helper text.
     * @param string $group Summary group identifier.
     * @return void
     */
    private function render_toggle_row($id, $label, $description, $group) {
        $checked = $this->is_enabled($id);
        ?>
        <div class="ash-toggle-row">
            <div class="ash-toggle-row__info">
                <label class="ash-toggle-row__label" for="<?php echo esc_attr($id); ?>"><?php echo esc_html($label); ?></label>
                <?php $this->render_info_icon($description); ?>
            </div>
            <label class="ash-switch">
                <input type="checkbox"
                       id="<?php echo esc_attr($id); ?>"
                       name="ash_options[<?php echo esc_attr($id); ?>]"
                       value="1"
                       data-ash-group="<?php echo esc_attr($group); ?>"
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
                'description' => __('Removes the public WordPress version from markup, feeds, scripts, and styles.', 'abdal-security-headers'),
            ),
            'remove_login_errors' => array(
                'label' => __('Remove Login Error Messages', 'abdal-security-headers'),
                'description' => __('Replaces detailed login errors with a generic message to reduce user enumeration.', 'abdal-security-headers'),
            ),
            'disable_xmlrpc' => array(
                'label' => __('Disable XML-RPC', 'abdal-security-headers'),
                'description' => __('Disables XML-RPC methods and blocks direct access to xmlrpc.php.', 'abdal-security-headers'),
            ),
            'remove_x_pingback' => array(
                'label' => __('Remove X-Pingback Header', 'abdal-security-headers'),
                'description' => __('Removes the X-Pingback response header from WordPress output.', 'abdal-security-headers'),
            ),
            'restrict_rest_api' => array(
                'label' => __('Restrict REST API Access', 'abdal-security-headers'),
                'description' => __('Blocks REST API access and removes REST discovery links from the front end.', 'abdal-security-headers'),
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
