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


class ABDAL_SECURITY_HEADERS_SECURITY
{


    public function xFrameOptions()
    {
        // X-Frame-Options
        header("X-Frame-Options: sameorigin");
    }

    public function XssProtection()
    {
        // X-XSS-Protection
        header("X-XSS-Protection: 1; mode=block");
    }

    public function xContentTypeOptions()
    {
        // X-Content-Type-Options
        header("X-Content-Type-Options: nosniff");
    }

    public function xPoweredByHider()
    {

        header("X-Powered-By: Secured By Abdal Security Headers");
    }

    public function ReferrerPolicy()
    {
        // Referrer-Policy
        header("Referrer-Policy: no-referrer");
    }

    public function FeaturePolicy()
    {
        // Feature-Policy
        header("Feature-Policy: camera 'none'; fullscreen 'self'; geolocation *; microphone 'self' " . $this->WebSiteUrlWithProtocol());
    }

    /**
     * @return string
     */
    public function WebSiteUrlWithProtocol()
    {

        // EXP = https://hackers.zone/
        return $this->ProtocolFinder() . "://" . $this->SimpleWebSiteUrl();

    }

    /**
     * @return string
     */
    public function ProtocolFinder()
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
    public function SimpleWebSiteUrl()
    {
        // EXP = hackers.zone
        return $_SERVER['HTTP_HOST'];
    }

    public function ExpectCT()
    {

        if ($this->ProtocolFinder() == "https") {
            // Set  Expect-CT Header
            header("Expect-CT: max-age=7776000, enforce");
        }


    }

    public function StrictTransportSecurity()
    {

        if ($this->ProtocolFinder() == "https") {
// Strict-Transport-Security
            header("Strict-Transport-Security: max-age=31536000");
        }


    }

    public function PublicKeyPins()
    {

        if ($this->ProtocolFinder() == "https") {
            header('Public-Key-Pins: pin-sha256=""' . $this->SslKey() . '; pin-sha256=""' . $this->SslKey() . '; max-age=604800; includeSubDomains; report-uri="' . $this->WebSiteUrlWithProtocol() . '/pkp-report.php"');
        }


    }

    public function SslKey()
    {

        if ($this->ProtocolFinder() == "https") {

            $orignal_parse = parse_url($this->WebSiteUrlWithProtocol(), PHP_URL_HOST);
            $get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
            $read = stream_socket_client("ssl://" . $orignal_parse . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);
            $cert = stream_context_get_params($read);
            $certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);

            return $SslKey = base64_encode($certinfo['extensions']['subjectKeyIdentifier']);


        }
    }

    public function ContentSecurityPolicy()
    {
        // Content-Security-Policy
        header("Content-Security-Policy: default-src 'self' ; script-src * 'self' data: 'unsafe-inline' 'unsafe-eval'  " . $this->WebSiteUrlWithProtocol() . "   https://*.google-analytics.com  https://*.cloudflare.com  https://*.google.com https://www.googletagmanager.com:* https://www.google-analytics.com:* https://pagead2.googlesyndication.com:* https://www.youtube.com:* https://adservice.google.com.au:* https://s.ytimg.com:* about; style-src 'self' data: 'unsafe-inline'  " . $this->WebSiteUrlWithProtocol() . "  https://fonts.googleapis.com:* https://www.googletagmanager.com:* https://www.google-analytics.com:*; img-src 'self' data: https:  " . $this->WebSiteUrlWithProtocol() . " *.gravatar.com  *.wordpress.org *.wordpress.com  https://*.google-analytics.com  https://*.cloudflare.com  https://*.google.com https://www.googletagmanager.com:* https://secure.gravatar.com:* https://www.google-analytics.com:* https://a.impactradius-go.com:* https://www.paypalobjects.com:* https://namecheap.pxf.io:* https://www.paypalobjects.com:* https://stats.g.doubleclick.net:* https://*.doubleclick.net:* https://stats.g.doubleclick.net:* https://www.ojrq.net:* https://ak1s.abmr.net:* https://*.abmr.net:*; font-src 'self' data:  " . $this->WebSiteUrlWithProtocol() . "   https://fonts.googleapis.com:* https://fonts.gstatic.com:* https://cdn.joinhoney.com:* https://www.googletagmanager.com:* https://www.google-analytics.com:* https://googleads.g.doubleclick.net:*; connect-src 'self'  " . $this->WebSiteUrlWithProtocol() . "   https://*.google-analytics.com  https://*.cloudflare.com  https://*.google.com https://www.googletagmanager.com:* https://www.google-analytics.com:*; media-src 'self'  " . $this->WebSiteUrlWithProtocol() . "   https://*.google-analytics.com  https://*.cloudflare.com  https://*.google.com https://www.googletagmanager.com:* https://secure.gravatar.com:* https://www.google-analytics.com:*; object-src 'self' ; child-src 'self' https://player.vimeo.com  https://www.youtube.com https://www.googletagmanager.com:* https://www.google-analytics.com:*; frame-src 'self' https://www.youtube.com:* https://googleads.g.doubleclick.net:*  *.doubleclick.net; worker-src 'self' ; frame-ancestors 'self' ; form-action 'self'  " . $this->WebSiteUrlWithProtocol() . "  https://www.googletagmanager.com:* https://www.google-analytics.com:* https://www.google-analytics.com:*; upgrade-insecure-requests; block-all-mixed-content;  base-uri  " . $this->WebSiteUrlWithProtocol() . " ; manifest-src 'self' 'self' 'self';  ");

//         report-uri " . $this->WebSiteUrlWithProtocol() . "/csp-report;

    }

    /**
     * @return string
     */
    public function WebSiteUrlWithWww()
    {
        // EXP = www.hackers.zone
        return "www." . $_SERVER['HTTP_HOST'];
    }

}