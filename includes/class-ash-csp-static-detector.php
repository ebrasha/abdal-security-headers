<?php
/**
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name : class-ash-csp-static-detector.php
 * Programmer : Ebrahim Shafiei (EbraSha)
 * Email : Prof.Shafiei@Gmail.com
 * Created On : 2026-08-29 05:17:35
 * Description : Collects WordPress-registered scripts, styles, and related origins
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

class ASH_CSP_Static_Detector {
    /**
     * Scan WordPress-registered assets and well-known site URLs.
     *
     * @param string $page Current page path.
     * @return array
     */
    public static function scan($page = '/', $lite = false) {
        $findings = array();
        $page = ASH_CSP_Normalizer::page_path($page);

        $findings = array_merge($findings, self::scan_scripts($page));
        $findings = array_merge($findings, self::scan_styles($page));
        $findings = array_merge($findings, self::scan_core_endpoints($page));
        if (!$lite) {
            $findings = array_merge($findings, self::scan_media($page));
        }

        return $findings;
    }

    /**
     * Persist scan results into the discovery repository.
     *
     * @param string $page Current page path.
     * @param bool   $lite Skip heavier media queries on frontend requests.
     * @return int Number of stored findings.
     */
    public static function collect($page = '/', $lite = false) {
        $count = 0;
        foreach (self::scan($page, $lite) as $item) {
            if (ASH_CSP_Repository::upsert($item)) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * @param string $page Page path.
     * @return array
     */
    private static function scan_scripts($page) {
        $findings = array();
        $scripts = wp_scripts();
        if (!($scripts instanceof WP_Scripts)) {
            return $findings;
        }

        $queued = is_array($scripts->queue) ? $scripts->queue : array();
        foreach ($scripts->registered as $handle => $dep) {
            if (empty($dep->src)) {
                continue;
            }
            $src = self::absolute_url($dep->src);
            $origin = ASH_CSP_Normalizer::origin_from_url($src);
            if ($origin === '') {
                continue;
            }
            $from = self::detected_from_src($src);
            if ($from === '' && in_array($handle, $queued, true)) {
                $from = __('Plugin script enqueue', 'abdal-security-headers');
            }
            $findings[] = array(
                'origin' => $origin,
                'directive' => 'script-src',
                'resource_type' => 'script',
                'method' => 'static',
                'page' => $page,
                'detected_from' => $from,
            );
        }

        return $findings;
    }

    /**
     * @param string $page Page path.
     * @return array
     */
    private static function scan_styles($page) {
        $findings = array();
        $styles = wp_styles();
        if (!($styles instanceof WP_Styles)) {
            return $findings;
        }

        foreach ($styles->registered as $dep) {
            if (empty($dep->src)) {
                continue;
            }
            $src = self::absolute_url($dep->src);
            $origin = ASH_CSP_Normalizer::origin_from_url($src);
            if ($origin === '') {
                continue;
            }
            $findings[] = array(
                'origin' => $origin,
                'directive' => 'style-src',
                'resource_type' => 'stylesheet',
                'method' => 'static',
                'page' => $page,
                'detected_from' => self::detected_from_src($src),
            );
        }

        return $findings;
    }

    /**
     * @param string $page Page path.
     * @return array
     */
    private static function scan_core_endpoints($page) {
        $findings = array();
        $targets = array(
            array(rest_url(), 'connect-src', 'fetch', __('WordPress REST API', 'abdal-security-headers')),
            array(admin_url('admin-ajax.php'), 'connect-src', 'fetch', __('WordPress AJAX', 'abdal-security-headers')),
            array(home_url('/'), 'form-action', 'form', __('WordPress site URL', 'abdal-security-headers')),
        );

        foreach ($targets as $target) {
            $origin = ASH_CSP_Normalizer::origin_from_url($target[0]);
            if ($origin === '') {
                continue;
            }
            $findings[] = array(
                'origin' => $origin,
                'directive' => $target[1],
                'resource_type' => $target[2],
                'method' => 'static',
                'page' => $page,
                'detected_from' => $target[3],
            );
        }

        return $findings;
    }

    /**
     * @param string $page Page path.
     * @return array
     */
    private static function scan_media($page) {
        $findings = array();
        $urls = array();

        $icon = get_site_icon_url();
        if (is_string($icon) && $icon !== '') {
            $urls[] = $icon;
        }

        $logo_id = get_theme_mod('custom_logo');
        if ($logo_id) {
            $logo = wp_get_attachment_url($logo_id);
            if (is_string($logo) && $logo !== '') {
                $urls[] = $logo;
            }
        }

        $attachments = get_posts(array(
            'post_type' => 'attachment',
            'post_status' => 'inherit',
            'posts_per_page' => 30,
            'fields' => 'ids',
            'orderby' => 'date',
            'order' => 'DESC',
            'no_found_rows' => true,
        ));
        foreach ($attachments as $attachment_id) {
            $url = wp_get_attachment_url($attachment_id);
            if (is_string($url) && $url !== '') {
                $urls[] = $url;
            }
        }

        foreach (array_unique($urls) as $url) {
            $origin = ASH_CSP_Normalizer::origin_from_url($url);
            if ($origin === '') {
                continue;
            }
            $findings[] = array(
                'origin' => $origin,
                'directive' => 'img-src',
                'resource_type' => 'image',
                'method' => 'static',
                'page' => $page,
                'detected_from' => self::detected_from_src($url),
            );
        }

        return $findings;
    }

    /**
     * @param string $src Script or style source.
     * @return string
     */
    private static function absolute_url($src) {
        $src = (string) $src;
        if ($src === '') {
            return '';
        }
        if (strpos($src, '//') === 0) {
            return (is_ssl() ? 'https:' : 'http:') . $src;
        }
        if (strpos($src, 'http://') !== 0 && strpos($src, 'https://') !== 0) {
            return site_url($src);
        }
        return $src;
    }

    /**
     * Identify a plugin or theme from a local URL. Never guess remote vendors.
     *
     * @param string $src Absolute URL.
     * @return string
     */
    private static function detected_from_src($src) {
        $path = (string) wp_parse_url($src, PHP_URL_PATH);
        if ($path === '') {
            return '';
        }

        if (preg_match('#/wp-content/plugins/([^/]+)/#', $path, $match)) {
            return $match[1];
        }
        if (preg_match('#/wp-content/themes/([^/]+)/#', $path, $match)) {
            return $match[1];
        }
        if (strpos($path, '/wp-includes/') !== false || strpos($path, '/wp-admin/') !== false) {
            return __('WordPress core', 'abdal-security-headers');
        }

        return '';
    }
}
