<?php
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : GPL v3
 * Current Date : 2019-03-24-17
 * Current Time : 05:51 PM
 */

// if not called from WordPress exit
if ( ! defined('WP_UNINSTALL_PLUGIN') ) {
    header('Status: 403 Forbidden');
    header('HTTP/1.1 403 Forbidden');
    die("Protected By Abdal Security Group");
}

