<?php

/*
Plugin Name: Abdal Security Headers
Plugin URI: https://hackers.zone/abdal-security-headers
Description:  Improve Your Website Security With Abdal Security Headers
Version: 1.0
Author: Ebrahim Shafiei
Author URI: https://hackers.zone/ebrahim-shafiei
License: GPL v3
Domain Path: /languages/
Text Domain: abdal-security-headers
*/

// Secure Access For This File
if ( ! function_exists( 'add_action' ) ) {
    echo "Powered By Abdal Security Group";
    exit;
}

require_once 'engine/core.php';


$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_xFrameOptions();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_XssProtection();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_xContentTypeOptions();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_ReferrerPolicy();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_FeaturePolicy();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_PublicKeyPins();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_ExpectCT();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_StrictTransportSecurity();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_ContentSecurityPolicy();
$AbdalSecurityHeaders_SecObj->AbdalSecurityHeaders_xPoweredByHider();



