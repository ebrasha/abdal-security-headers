<?php

/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : GPL v3
 * Current Date : 2019-03-18-20
 * Current Time : 08:16 PM
 */

// Secure Access For This File
if (!function_exists('add_action')) {
    echo "Powered By Abdal Security Group";
    exit;
}


class ABDAL_SECURITY_HEADERS_SECURITY
{


    public function AbdalSecurityHeaders_xFrameOptions()
    {
        // X-Frame-Options
        header("X-Frame-Options: sameorigin");
    }

    public function AbdalSecurityHeaders_XssProtection()
    {
        // X-XSS-Protection
        header("X-XSS-Protection: 1; mode=block");
    }

    public function AbdalSecurityHeaders_xContentTypeOptions()
    {
        // X-Content-Type-Options
        header("X-Content-Type-Options: nosniff");
    }

    public function AbdalSecurityHeaders_xPoweredByHider()
    {

        header("X-Powered-By: Secured By Abdal Security Headers");
    }

    public function AbdalSecurityHeaders_ReferrerPolicy()
    {
        // Referrer-Policy
        header("Referrer-Policy: no-referrer");
    }

    public function AbdalSecurityHeaders_FeaturePolicy()
    {
        // Feature-Policy
        header("Feature-Policy: camera 'none'; fullscreen 'self'; geolocation *; microphone 'self' " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol());
    }

    /**
     * @return string
     */
    public function AbdalSecurityHeaders_WebSiteUrlWithProtocol()
    {

        // EXP = https://hackers.zone/
        return $this->AbdalSecurityHeaders_ProtocolFinder() . "://" . $this->AbdalSecurityHeaders_SimpleWebSiteUrl();

    }

    /**
     * @return string
     */
    public function AbdalSecurityHeaders_ProtocolFinder()
    {

        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {

            return "https";
        } else {

            return "http";
        }

    }

    /**
     * @return mixed
     */
    public function AbdalSecurityHeaders_SimpleWebSiteUrl()
    {
        // EXP = hackers.zone
        return $_SERVER['HTTP_HOST'];
    }

    public function AbdalSecurityHeaders_ExpectCT()
    {

        if ($this->AbdalSecurityHeaders_ProtocolFinder() == "https") {
            // Set  Expect-CT Header
            header("Expect-CT: max-age=7776000, enforce");
        }


    }

    public function AbdalSecurityHeaders_StrictTransportSecurity()
    {

        if ($this->AbdalSecurityHeaders_ProtocolFinder() == "https") {
// Strict-Transport-Security
            header("Strict-Transport-Security: max-age=31536000");
        }


    }

    public function AbdalSecurityHeaders_PublicKeyPins()
    {

        if ($this->AbdalSecurityHeaders_ProtocolFinder() == "https") {
            header('Public-Key-Pins: pin-sha256=""' . $this->AbdalSecurityHeaders_SslKey() . '; pin-sha256=""' . $this->AbdalSecurityHeaders_SslKey() . '; max-age=604800; includeSubDomains; report-uri="' . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . '/pkp-report.php"');
        }


    }

    public function AbdalSecurityHeaders_SslKey()
    {

        if ($this->AbdalSecurityHeaders_ProtocolFinder() == "https") {

            $orignal_parse = parse_url($this->AbdalSecurityHeaders_WebSiteUrlWithProtocol(), PHP_URL_HOST);
            $get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
            $read = stream_socket_client("ssl://" . $orignal_parse . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);
            $cert = stream_context_get_params($read);
            $certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);

            return $AbdalSecurityHeaders_SslKey = base64_encode($certinfo['extensions']['subjectKeyIdentifier']);


        }
    }

    public function AbdalSecurityHeaders_ContentSecurityPolicy()
    {
        // Content-Security-Policy
        header("Content-Security-Policy: default-src 'self' ; script-src * 'self' data: 'unsafe-inline' 'unsafe-eval'  " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . " :* :* https://*.google-analytics.com  https://*.cloudflare.com  https://*.google.com https://www.googletagmanager.com:* https://www.google-analytics.com:* https://pagead2.googlesyndication.com:* https://www.youtube.com:* https://adservice.google.com.au:* https://s.ytimg.com:* about; style-src 'self' data: 'unsafe-inline'  " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . " :* :* https://fonts.googleapis.com:* https://www.googletagmanager.com:* https://www.google-analytics.com:*; img-src 'self' data:  " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . " :* :* https://*.google-analytics.com  https://*.cloudflare.com  https://*.google.com https://www.googletagmanager.com:* https://secure.gravatar.com:* https://www.google-analytics.com:* https://a.impactradius-go.com:* https://www.paypalobjects.com:* https://namecheap.pxf.io:* https://www.paypalobjects.com:* https://stats.g.doubleclick.net:* https://*.doubleclick.net:* https://stats.g.doubleclick.net:* https://www.ojrq.net:* https://ak1s.abmr.net:* https://*.abmr.net:*; font-src 'self' data:  " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . " :* :* https://fonts.googleapis.com:* https://fonts.gstatic.com:* https://cdn.joinhoney.com:* https://www.googletagmanager.com:* https://www.google-analytics.com:* https://googleads.g.doubleclick.net:*; connect-src 'self'  " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . " :* :* https://*.google-analytics.com  https://*.cloudflare.com  https://*.google.com https://www.googletagmanager.com:* https://www.google-analytics.com:*; media-src 'self'  " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . " :* :* https://*.google-analytics.com  https://*.cloudflare.com  https://*.google.com https://www.googletagmanager.com:* https://secure.gravatar.com:* https://www.google-analytics.com:*; object-src 'self' ; child-src 'self' https://player.vimeo.com :* https://www.youtube.com https://www.googletagmanager.com:* https://www.google-analytics.com:*; frame-src 'self' https://www.youtube.com:* https://googleads.g.doubleclick.net:* https://*doubleclick.net; worker-src 'self' ; frame-ancestors 'self' ; form-action 'self'  " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . " :* :* :* https://www.googletagmanager.com:* https://www.google-analytics.com:* https://www.google-analytics.com:*; upgrade-insecure-requests; block-all-mixed-content; disown-opener; reflected-xss block; base-uri  " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . " :*; manifest-src 'self' 'self' 'self'; referrer no-referrer-when-downgrade; report-uri " . $this->AbdalSecurityHeaders_WebSiteUrlWithProtocol() . "/csp-report;");

    }

    /**
     * @return string
     */
    public function AbdalSecurityHeaders_WebSiteUrlWithWww()
    {
        // EXP = www.hackers.zone
        return "www." . $_SERVER['HTTP_HOST'];
    }

}