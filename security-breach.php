<?php
/**
 * Plugin Name: Security Breach
 * Plugin URI: https://atipat.lorwongam.com/security-breach
 * Description: Comprehensive WordPress security vulnerability scanner that checks all security levels and provides solving suggestions.
 * Version: 1.0.0
 * Author: Atipat Lorwongam
 * License: GPL v2 or later
 * Text Domain: security-breach
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('SECURITY_BREACH_VERSION', '1.0.0');
define('SECURITY_BREACH_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SECURITY_BREACH_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SECURITY_BREACH_PLUGIN_FILE', __FILE__);

// Main plugin class
class SecurityBreachPlugin {
    
    private static $instance = null;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        add_action('init', array($this, 'init'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_run_security_scan', array($this, 'ajax_run_security_scan'));
        add_action('wp_ajax_mark_vulnerability_resolved', array($this, 'ajax_mark_resolved'));
        add_action('wp_ajax_security_breach_cleanup', array($this, 'ajax_cleanup_old_scans'));
        add_action('admin_notices', array($this, 'admin_notices'));
        
        // Register activation and deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }
    
    public function init() {
        load_plugin_textdomain('security-breach', false, dirname(plugin_basename(__FILE__)) . '/languages/');
    }
    
    public function activate() {
        // Create necessary database tables if needed
        $this->create_scan_results_table();
        
        // Schedule daily security scans
        if (!wp_next_scheduled('security_breach_daily_scan')) {
            wp_schedule_event(time(), 'daily', 'security_breach_daily_scan');
        }
    }
    
    public function deactivate() {
        wp_clear_scheduled_hook('security_breach_daily_scan');
    }
    
    private function create_scan_results_table() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'security_breach_scans';
        
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE $table_name (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            scan_date datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            vulnerability_type varchar(100) NOT NULL,
            severity varchar(20) NOT NULL,
            description text NOT NULL,
            suggestion text NOT NULL,
            status varchar(20) DEFAULT 'pending' NOT NULL,
            PRIMARY KEY (id)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    public function add_admin_menu() {
        add_menu_page(
            __('Security Breach', 'security-breach'),
            __('Security Breach', 'security-breach'),
            'manage_options',
            'security-breach',
            array($this, 'admin_page'),
            'dashicons-shield-alt',
            30
        );
        
        add_submenu_page(
            'security-breach',
            __('Scan Results', 'security-breach'),
            __('Scan Results', 'security-breach'),
            'manage_options',
            'security-breach-results',
            array($this, 'scan_results_page')
        );
        
        add_submenu_page(
            'security-breach',
            __('Settings', 'security-breach'),
            __('Settings', 'security-breach'),
            'manage_options',
            'security-breach-settings',
            array($this, 'settings_page')
        );
    }
    
    public function enqueue_admin_scripts($hook) {
        if (strpos($hook, 'security-breach') !== false) {
            wp_enqueue_script('security-breach-admin', SECURITY_BREACH_PLUGIN_URL . 'assets/admin.js', array('jquery'), SECURITY_BREACH_VERSION, true);
            wp_enqueue_style('security-breach-admin', SECURITY_BREACH_PLUGIN_URL . 'assets/admin.css', array(), SECURITY_BREACH_VERSION);
            
            wp_localize_script('security-breach-admin', 'securityBreachAjax', array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('security_breach_nonce'),
                'scanning_text' => __('Scanning...', 'security-breach'),
                'scan_complete_text' => __('Scan Complete', 'security-breach')
            ));
        }
    }
    
    public function admin_page() {
        include SECURITY_BREACH_PLUGIN_DIR . 'includes/admin-page.php';
    }
    
    public function scan_results_page() {
        include SECURITY_BREACH_PLUGIN_DIR . 'includes/scan-results-page.php';
    }
    
    public function settings_page() {
        include SECURITY_BREACH_PLUGIN_DIR . 'includes/settings-page.php';
    }
    
    public function ajax_run_security_scan() {
        check_ajax_referer('security_breach_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }
        
        $scanner = new SecurityBreachScanner();
        $results = $scanner->run_full_scan();
        
        // Send email notification if enabled
        $this->maybe_send_notification($results);
        
        wp_send_json_success($results);
    }
    
    public function ajax_mark_resolved() {
        check_ajax_referer('security_breach_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions'));
        }
        
        $vulnerability_id = intval($_POST['vulnerability_id']);
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'security_breach_scans';
        
        $result = $wpdb->update(
            $table_name,
            array('status' => 'resolved'),
            array('id' => $vulnerability_id),
            array('%s'),
            array('%d')
        );
        
        if ($result !== false) {
            wp_send_json_success();
        } else {
            wp_send_json_error('Failed to update vulnerability status');
        }
    }
    
    public function ajax_cleanup_old_scans() {
        check_ajax_referer('security_breach_cleanup', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die(__('Insufficient permissions'));
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'security_breach_scans';
        
        $result = $wpdb->query("DELETE FROM $table_name WHERE scan_date < DATE_SUB(NOW(), INTERVAL 30 DAY)");
        
        wp_send_json_success(array('deleted' => $result));
    }
    
    public function admin_notices() {
        // Check if this is our plugin page
        $screen = get_current_screen();
        if (strpos($screen->id, 'security-breach') === false) {
            return;
        }
        
        // Check for critical vulnerabilities
        global $wpdb;
        $table_name = $wpdb->prefix . 'security_breach_scans';
        
        $critical_count = $wpdb->get_var(
            "SELECT COUNT(*) FROM $table_name 
             WHERE severity = 'critical' AND status = 'pending' 
             AND scan_date > DATE_SUB(NOW(), INTERVAL 1 DAY)"
        );
        
        if ($critical_count > 0) {
            echo '<div class="notice notice-error">';
            echo '<p><strong>' . __('Security Alert:', 'security-breach') . '</strong> ';
            echo sprintf(
                _n('You have %d critical security vulnerability that requires immediate attention.',
                   'You have %d critical security vulnerabilities that require immediate attention.',
                   $critical_count, 'security-breach'),
                $critical_count
            );
            echo ' <a href="' . admin_url('admin.php?page=security-breach-results&severity=critical') . '">';
            echo __('View Details', 'security-breach') . '</a></p>';
            echo '</div>';
        }
    }
    
    private function maybe_send_notification($vulnerabilities) {
        if (!get_option('security_breach_email_notifications', 1)) {
            return;
        }
        
        $threshold = get_option('security_breach_severity_threshold', 'medium');
        $severity_levels = array('low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4);
        $threshold_level = $severity_levels[$threshold];
        
        $critical_vulns = array_filter($vulnerabilities, function($vuln) use ($severity_levels, $threshold_level) {
            return $severity_levels[$vuln['severity']] >= $threshold_level;
        });
        
        if (empty($critical_vulns)) {
            return;
        }
        
        $email = get_option('security_breach_notification_email', get_option('admin_email'));
        $subject = sprintf(__('[%s] Security Vulnerabilities Detected', 'security-breach'), get_bloginfo('name'));
        
        $message = sprintf(__('Security scan completed on %s', 'security-breach'), get_bloginfo('name')) . "\n\n";
        $message .= sprintf(__('Found %d vulnerabilities requiring attention:', 'security-breach'), count($critical_vulns)) . "\n\n";
        
        foreach ($critical_vulns as $vuln) {
            $message .= sprintf("[%s] %s: %s\n", strtoupper($vuln['severity']), $vuln['type'], $vuln['description']) . "\n";
        }
        
        $message .= "\n" . __('Please log in to your WordPress admin panel to review and address these security issues.', 'security-breach') . "\n";
        $message .= admin_url('admin.php?page=security-breach-results');
        
        wp_mail($email, $subject, $message);
    }
}

// Security Scanner Class
class SecurityBreachScanner {
    
    private $vulnerabilities = array();
    
    public function run_full_scan() {
        $this->vulnerabilities = array();
        
        // Run all security checks
        $this->check_wordpress_version();
        $this->check_plugin_vulnerabilities();
        $this->check_theme_vulnerabilities();
        $this->check_file_permissions();
        $this->check_database_security();
        $this->check_user_security();
        $this->check_login_security();
        $this->check_ssl_configuration();
        $this->check_security_headers();
        $this->check_wp_config_security();
        $this->check_directory_browsing();
        $this->check_debug_mode();
        $this->check_file_editing();
        $this->check_xmlrpc_security();
        $this->check_admin_user();
        $this->check_weak_passwords();
        $this->check_brute_force_protection();
        $this->check_malware_signatures();
        
        // Save results to database
        $this->save_scan_results();
        
        return $this->vulnerabilities;
    }
    
    private function add_vulnerability($type, $severity, $description, $suggestion) {
        $this->vulnerabilities[] = array(
            'type' => $type,
            'severity' => $severity,
            'description' => $description,
            'suggestion' => $suggestion,
            'timestamp' => current_time('mysql')
        );
    }
    
    private function check_wordpress_version() {
        global $wp_version;
        
        // Get latest WordPress version from API
        $response = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/');
        if (!is_wp_error($response)) {
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true);
            
            if (isset($data['offers'][0]['version'])) {
                $latest_version = $data['offers'][0]['version'];
                
                if (version_compare($wp_version, $latest_version, '<')) {
                    $this->add_vulnerability(
                        'WordPress Version',
                        'high',
                        sprintf(__('WordPress version %s is outdated. Latest version is %s.', 'security-breach'), $wp_version, $latest_version),
                        __('Update WordPress to the latest version immediately. Go to Dashboard > Updates and click "Update Now".', 'security-breach')
                    );
                }
            }
        }
    }
    
    private function check_plugin_vulnerabilities() {
        $plugins = get_plugins();
        
        foreach ($plugins as $plugin_file => $plugin_data) {
            // Check if plugin is active but outdated
            if (is_plugin_active($plugin_file)) {
                // Check for known vulnerable plugins (this would typically query a vulnerability database)
                $this->check_plugin_updates($plugin_file, $plugin_data);
            }
        }
    }
    
    private function check_plugin_updates($plugin_file, $plugin_data) {
        $updates = get_site_transient('update_plugins');
        
        if (isset($updates->response[$plugin_file])) {
            $this->add_vulnerability(
                'Plugin Update',
                'medium',
                sprintf(__('Plugin "%s" has available updates. Current version: %s', 'security-breach'), $plugin_data['Name'], $plugin_data['Version']),
                sprintf(__('Update the plugin "%s" to the latest version. Go to Dashboard > Plugins and update the plugin.', 'security-breach'), $plugin_data['Name'])
            );
        }
    }
    
    private function check_theme_vulnerabilities() {
        $themes = wp_get_themes();
        $current_theme = wp_get_theme();
        
        // Check current theme for updates
        $updates = get_site_transient('update_themes');
        $current_theme_slug = $current_theme->get_stylesheet();
        
        if (isset($updates->response[$current_theme_slug])) {
            $this->add_vulnerability(
                'Theme Update',
                'medium',
                sprintf(__('Current theme "%s" has available updates. Current version: %s', 'security-breach'), $current_theme->get('Name'), $current_theme->get('Version')),
                sprintf(__('Update the theme "%s" to the latest version. Go to Dashboard > Appearance > Themes and update the theme.', 'security-breach'), $current_theme->get('Name'))
            );
        }
    }
    
    private function check_file_permissions() {
        $critical_files = array(
            ABSPATH . 'wp-config.php' => 0644,
            ABSPATH . '.htaccess' => 0644,
            ABSPATH . 'wp-content/' => 0755,
            ABSPATH . 'wp-content/uploads/' => 0755,
        );
        
        foreach ($critical_files as $file => $recommended_permission) {
            if (file_exists($file)) {
                $current_permission = substr(sprintf('%o', fileperms($file)), -4);
                $current_octal = octdec($current_permission);
                
                if ($current_octal > $recommended_permission) {
                    $this->add_vulnerability(
                        'File Permissions',
                        'high',
                        sprintf(__('File %s has overly permissive permissions (%s). Recommended: %s', 'security-breach'), $file, $current_permission, decoct($recommended_permission)),
                        sprintf(__('Change file permissions for %s to %s using: chmod %s %s', 'security-breach'), $file, decoct($recommended_permission), decoct($recommended_permission), $file)
                    );
                }
            }
        }
    }
    
    private function check_database_security() {
        global $wpdb;
        
        // Check for default table prefix
        if ($wpdb->prefix === 'wp_') {
            $this->add_vulnerability(
                'Database Security',
                'medium',
                __('Using default WordPress table prefix "wp_" makes your database more vulnerable to SQL injection attacks.', 'security-breach'),
                __('Change the database table prefix to something unique. This requires modifying wp-config.php and updating all existing tables.', 'security-breach')
            );
        }
        
        // Check database version
        $mysql_version = $wpdb->get_var('SELECT VERSION()');
        if (version_compare($mysql_version, '5.7.0', '<')) {
            $this->add_vulnerability(
                'Database Version',
                'medium',
                sprintf(__('MySQL/MariaDB version %s may have security vulnerabilities. Consider upgrading.', 'security-breach'), $mysql_version),
                __('Upgrade your MySQL/MariaDB to a more recent version. Contact your hosting provider for assistance.', 'security-breach')
            );
        }
    }
    
    private function check_user_security() {
        // Check for admin user with username "admin"
        $admin_user = get_user_by('login', 'admin');
        if ($admin_user && user_can($admin_user, 'administrator')) {
            $this->add_vulnerability(
                'User Security',
                'high',
                __('Default admin username "admin" detected. This makes brute force attacks easier.', 'security-breach'),
                __('Create a new administrator user with a unique username and delete the "admin" user.', 'security-breach')
            );
        }
        
        // Check for users with weak passwords (this is limited due to password hashing)
        $users = get_users(array('role' => 'administrator'));
        foreach ($users as $user) {
            // Check if user has set a display name same as username
            if ($user->display_name === $user->user_login) {
                $this->add_vulnerability(
                    'User Security',
                    'low',
                    sprintf(__('Administrator user "%s" is using username as display name, which exposes the login username.', 'security-breach'), $user->user_login),
                    sprintf(__('Change the display name for user "%s" to something different from the username.', 'security-breach'), $user->user_login)
                );
            }
        }
    }
    
    private function check_login_security() {
        // Check if login attempts are being logged/limited
        if (!defined('LIMIT_LOGIN_ATTEMPTS') && !is_plugin_active('limit-login-attempts/limit-login-attempts.php')) {
            $this->add_vulnerability(
                'Login Security',
                'medium',
                __('No brute force protection detected. Login attempts are not being limited.', 'security-breach'),
                __('Install and activate a login security plugin like "Limit Login Attempts" or "Wordfence Security".', 'security-breach')
            );
        }
    }
    
    private function check_ssl_configuration() {
        if (!is_ssl()) {
            $this->add_vulnerability(
                'SSL Configuration',
                'high',
                __('Website is not using HTTPS. All data transmitted is unencrypted and vulnerable to interception.', 'security-breach'),
                __('Install an SSL certificate and configure WordPress to use HTTPS. Update wp-config.php and set FORCE_SSL_ADMIN to true.', 'security-breach')
            );
        }
        
        // Check if mixed content exists
        if (is_ssl()) {
            $home_url = get_home_url();
            if (strpos($home_url, 'https://') !== 0) {
                $this->add_vulnerability(
                    'SSL Configuration',
                    'medium',
                    __('Site URL is not configured for HTTPS, which may cause mixed content warnings.', 'security-breach'),
                    __('Update your Site URL and WordPress URL to use HTTPS in Settings > General.', 'security-breach')
                );
            }
        }
    }
    
    private function check_security_headers() {
        $url = home_url();
        $response = wp_remote_head($url);
        
        if (!is_wp_error($response)) {
            $headers = wp_remote_retrieve_headers($response);
            
            $security_headers = array(
                'X-Frame-Options' => 'Prevents clickjacking attacks',
                'X-Content-Type-Options' => 'Prevents MIME type sniffing',
                'X-XSS-Protection' => 'Enables XSS filtering',
                'Strict-Transport-Security' => 'Forces HTTPS connections',
                'Content-Security-Policy' => 'Prevents XSS and injection attacks'
            );
            
            foreach ($security_headers as $header => $description) {
                if (!isset($headers[$header]) && !isset($headers[strtolower($header)])) {
                    $this->add_vulnerability(
                        'Security Headers',
                        'medium',
                        sprintf(__('Missing security header: %s. %s', 'security-breach'), $header, $description),
                        sprintf(__('Add the %s header to your server configuration or use a security plugin.', 'security-breach'), $header)
                    );
                }
            }
        }
    }
    
    private function check_wp_config_security() {
        $wp_config_path = ABSPATH . 'wp-config.php';
        
        if (file_exists($wp_config_path)) {
            $wp_config_content = file_get_contents($wp_config_path);
            
            // Check for security keys
            $security_keys = array('AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT');
            
            foreach ($security_keys as $key) {
                if (strpos($wp_config_content, "define('$key'") === false || strpos($wp_config_content, 'put your unique phrase here') !== false) {
                    $this->add_vulnerability(
                        'WordPress Configuration',
                        'high',
                        sprintf(__('Security key %s is not properly configured in wp-config.php.', 'security-breach'), $key),
                        __('Generate new security keys from https://api.wordpress.org/secret-key/1.1/salt/ and update wp-config.php.', 'security-breach')
                    );
                    break; // Only report once for all missing keys
                }
            }
            
            // Check for debug mode in production
            if (strpos($wp_config_content, "define('WP_DEBUG', true)") !== false) {
                $this->add_vulnerability(
                    'WordPress Configuration',
                    'medium',
                    __('WordPress debug mode is enabled. This can expose sensitive information.', 'security-breach'),
                    __('Set WP_DEBUG to false in wp-config.php for production sites.', 'security-breach')
                );
            }
            
            // Check for file editing
            if (strpos($wp_config_content, "define('DISALLOW_FILE_EDIT', true)") === false) {
                $this->add_vulnerability(
                    'WordPress Configuration',
                    'medium',
                    __('File editing is not disabled. Attackers could modify files through the admin panel.', 'security-breach'),
                    __('Add define("DISALLOW_FILE_EDIT", true); to wp-config.php to disable file editing.', 'security-breach')
                );
            }
        }
    }
    
    private function check_directory_browsing() {
        $test_dirs = array(
            '/wp-content/',
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/'
        );
        
        foreach ($test_dirs as $dir) {
            $url = home_url() . $dir;
            $response = wp_remote_get($url);
            
            if (!is_wp_error($response)) {
                $body = wp_remote_retrieve_body($response);
                if (strpos($body, 'Index of') !== false) {
                    $this->add_vulnerability(
                        'Directory Browsing',
                        'medium',
                        sprintf(__('Directory browsing is enabled for %s. This exposes your file structure.', 'security-breach'), $dir),
                        sprintf(__('Add an index.html file to %s or configure your server to deny directory listing.', 'security-breach'), $dir)
                    );
                }
            }
        }
    }
    
    private function check_debug_mode() {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $this->add_vulnerability(
                'Debug Configuration',
                'medium',
                __('WordPress debug mode is enabled. Error messages may expose sensitive information.', 'security-breach'),
                __('Disable WP_DEBUG in wp-config.php for production sites.', 'security-breach')
            );
        }
        
        if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            $log_file = WP_CONTENT_DIR . '/debug.log';
            if (file_exists($log_file) && is_readable($log_file)) {
                $this->add_vulnerability(
                    'Debug Configuration',
                    'high',
                    __('Debug log file is accessible and may contain sensitive information.', 'security-breach'),
                    __('Disable WP_DEBUG_LOG or ensure debug.log is not accessible via web browser.', 'security-breach')
                );
            }
        }
    }
    
    private function check_file_editing() {
        if (!defined('DISALLOW_FILE_EDIT') || !DISALLOW_FILE_EDIT) {
            $this->add_vulnerability(
                'File Editing',
                'medium',
                __('WordPress file editing is enabled. This allows editing PHP files from the admin panel.', 'security-breach'),
                __('Add define("DISALLOW_FILE_EDIT", true); to wp-config.php to disable file editing.', 'security-breach')
            );
        }
    }
    
    private function check_xmlrpc_security() {
        $xmlrpc_url = home_url('/xmlrpc.php');
        $response = wp_remote_post($xmlrpc_url, array(
            'body' => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
        ));
        
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
            $this->add_vulnerability(
                'XML-RPC Security',
                'medium',
                __('XML-RPC is enabled and responding. This can be exploited for brute force attacks and DDoS.', 'security-breach'),
                __('Disable XML-RPC if not needed by adding code to functions.php or using a security plugin.', 'security-breach')
            );
        }
    }
    
    private function check_admin_user() {
        $admin_users = get_users(array(
            'role' => 'administrator',
            'number' => 1
        ));
        
        if (count($admin_users) === 1) {
            $this->add_vulnerability(
                'User Management',
                'low',
                __('Only one administrator user exists. This creates a single point of failure.', 'security-breach'),
                __('Consider creating a backup administrator account for redundancy.', 'security-breach')
            );
        }
    }
    
    private function check_weak_passwords() {
        // This is a basic check - in reality, you cannot check actual passwords due to hashing
        // We can only check password policies and encourage strong passwords
        
        if (!function_exists('wp_check_password')) {
            $this->add_vulnerability(
                'Password Security',
                'low',
                __('No password strength enforcement detected.', 'security-breach'),
                __('Consider implementing password strength requirements using a security plugin.', 'security-breach')
            );
        }
    }
    
    private function check_brute_force_protection() {
        // Check if there are any brute force protection mechanisms
        $protection_plugins = array(
            'wordfence/wordfence.php',
            'limit-login-attempts-reloaded/limit-login-attempts-reloaded.php',
            'jetpack/jetpack.php'
        );
        
        $has_protection = false;
        foreach ($protection_plugins as $plugin) {
            if (is_plugin_active($plugin)) {
                $has_protection = true;
                break;
            }
        }
        
        if (!$has_protection) {
            $this->add_vulnerability(
                'Brute Force Protection',
                'high',
                __('No brute force protection detected. Your login page is vulnerable to automated attacks.', 'security-breach'),
                __('Install a security plugin like Wordfence, Limit Login Attempts, or enable Jetpack\'s brute force protection.', 'security-breach')
            );
        }
    }
    
    private function check_malware_signatures() {
        // Basic malware signature detection
        $suspicious_patterns = array(
            'eval\s*\(',
            'base64_decode\s*\(',
            'gzinflate\s*\(',
            'str_rot13\s*\(',
            'shell_exec\s*\(',
            'system\s*\(',
            'exec\s*\(',
            'passthru\s*\(',
            'file_get_contents\s*\(\s*["\']https?://'
        );
        
        $scan_dirs = array(
            WP_CONTENT_DIR . '/themes/',
            WP_CONTENT_DIR . '/plugins/',
            WP_CONTENT_DIR . '/uploads/'
        );
        
        foreach ($scan_dirs as $dir) {
            if (is_dir($dir)) {
                $this->scan_directory_for_malware($dir, $suspicious_patterns);
            }
        }
    }
    
    private function scan_directory_for_malware($dir, $patterns) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        $scanned_files = 0;
        foreach ($iterator as $file) {
            if ($file->isFile() && preg_match('/\.(php|js|html|htm)$/i', $file->getFilename())) {
                $scanned_files++;
                if ($scanned_files > 1000) break; // Limit to prevent timeout
                
                $content = file_get_contents($file->getPathname());
                foreach ($patterns as $pattern) {
                    if (preg_match('/' . $pattern . '/i', $content)) {
                        $this->add_vulnerability(
                            'Malware Detection',
                            'critical',
                            sprintf(__('Suspicious code pattern detected in file: %s', 'security-breach'), $file->getPathname()),
                            sprintf(__('Review the file %s for malicious code. Consider restoring from a clean backup.', 'security-breach'), $file->getPathname())
                        );
                        break;
                    }
                }
            }
        }
    }
    
    private function save_scan_results() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'security_breach_scans';
        
        // Clear previous results (optional - you might want to keep history)
        $wpdb->query("DELETE FROM $table_name WHERE scan_date < DATE_SUB(NOW(), INTERVAL 7 DAY)");
        
        foreach ($this->vulnerabilities as $vulnerability) {
            $wpdb->insert(
                $table_name,
                array(
                    'vulnerability_type' => $vulnerability['type'],
                    'severity' => $vulnerability['severity'],
                    'description' => $vulnerability['description'],
                    'suggestion' => $vulnerability['suggestion'],
                    'scan_date' => $vulnerability['timestamp']
                ),
                array('%s', '%s', '%s', '%s', '%s')
            );
        }
    }
}

// Initialize the plugin
add_action('plugins_loaded', function() {
    SecurityBreachPlugin::get_instance();
});

// Schedule daily scans
add_action('security_breach_daily_scan', function() {
    $scanner = new SecurityBreachScanner();
    $scanner->run_full_scan();
});
