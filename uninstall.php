<?php
// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// Remove plugin options
delete_option('security_breach_scan_frequency');
delete_option('security_breach_email_notifications');
delete_option('security_breach_notification_email');
delete_option('security_breach_auto_scan');
delete_option('security_breach_scan_plugins');
delete_option('security_breach_scan_themes');
delete_option('security_breach_scan_core');
delete_option('security_breach_scan_malware');
delete_option('security_breach_severity_threshold');
delete_option('security_breach_db_version');

// Remove scheduled events
wp_clear_scheduled_hook('security_breach_daily_scan');

// Remove database table
$table_name = $wpdb->prefix . 'security_breach_scans';
$wpdb->query("DROP TABLE IF EXISTS $table_name");

// Remove any cached data
wp_cache_flush();
