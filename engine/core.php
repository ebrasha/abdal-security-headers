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


if (!defined('ABDAL_SECURITY_HEADERS_FILE')) {
    define('ABDAL_SECURITY_HEADERS_FILE', __FILE__);
}


require_once plugin_dir_path(ABDAL_SECURITY_HEADERS_FILE) . 'includes/class-security.php';


$AbdalSecurityHeaders_SecObj = new ABDAL_SECURITY_HEADERS_SECURITY;


