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


// Prevent Direct Access
if (!function_exists('add_filter')) {
    header('Status: 403 Forbidden');
    header('HTTP/1.1 403 Forbidden');
    die("Protected By Abdal Security Group");
}


require_once plugin_dir_path(__FILE__) . 'engine/core.php';


$AbdalSecurityHeaders_SecObj->xFrameOptions();
$AbdalSecurityHeaders_SecObj->XssProtection();
$AbdalSecurityHeaders_SecObj->xContentTypeOptions();
$AbdalSecurityHeaders_SecObj->ReferrerPolicy();
$AbdalSecurityHeaders_SecObj->FeaturePolicy();
$AbdalSecurityHeaders_SecObj->PublicKeyPins();
$AbdalSecurityHeaders_SecObj->ExpectCT();
$AbdalSecurityHeaders_SecObj->StrictTransportSecurity();
$AbdalSecurityHeaders_SecObj->ContentSecurityPolicy();
$AbdalSecurityHeaders_SecObj->xPoweredByHider();




$AbdalSecurityHeaders_DashboardWidgetsObj->AbdalSecurityHeadersActiveDashboardWidget();