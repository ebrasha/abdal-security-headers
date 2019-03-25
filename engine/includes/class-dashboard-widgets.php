<?php
/**
 * Created by Abdal Security Group.
 * Programmer: Ebrahim Shafiei
 * Programmer WebSite: https://hackers.zone/
 * Programmer Email: Prof.Shafiei@Gmail.com
 * License : GPL v3
 * Current Date : 2019-03-24-16
 * Current Time : 04:05 PM
 */


require_once plugin_dir_path(__FILE__) . 'class-security.php';

class ABDAL_SECURITY_HEADERS_DASHBOARD_WIDGETS extends ABDAL_SECURITY_HEADERS_SECURITY
{

    public function AbdalSecurityHeadersMessageDashboard()
    {

        echo __('Abdal Security Headers Running Successfully','abdal-security-headers')."<br><strong>".__('Thanks For Using Our Plugin','abdal-security-headers')."</strong><br>";

    }

    public function AbdalSecurityHeadersFileDashboardWidgets()
    {
        wp_add_dashboard_widget('custom_help_widget', __('Abdal Security Headers','abdal-security-headers'), array(__CLASS__,'AbdalSecurityHeadersMessageDashboard'));
    }


    public  function AbdalSecurityHeadersActiveDashboardWidget(){
        add_action('wp_dashboard_setup', array(__CLASS__,'AbdalSecurityHeadersFileDashboardWidgets'));

    }
}