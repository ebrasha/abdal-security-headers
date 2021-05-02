<?php

/*
Plugin Name: Abdal Security Headers
Plugin URI: https://hackers.zone/abdal-security-headers
Description:  Improve Your WordPress Security With Abdal Security Headers
Version: 1.2.0
Author: Ebrahim Shafiei
Author URI: https://hackers.zone/ebrahim-shafiei-en
License: GPL v3
Domain Path: /languages/
Text Domain: abdal-security-headers
*/


// Prevent Direct Access
if (!function_exists('add_filter')) {
    header('Status: 403 Forbidden');
    header('HTTP/1.1 403 Forbidden');
    die("Protected By Abdal Security Group");
}


// Load The Abdal Security Headers Plugin
require_once plugin_dir_path(__FILE__) . 'abdal-security-headers-master.php';

