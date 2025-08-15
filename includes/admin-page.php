<?php
// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}
?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    
    <div class="security-breach-dashboard">
        <div class="postbox-container" style="width: 70%;">
            <div class="postbox">
                <h2 class="hndle"><span><?php _e('Security Scan', 'security-breach'); ?></span></h2>
                <div class="inside">
                    <div id="scan-progress" style="display: none;">
                        <div class="security-breach-progress">
                            <div class="progress-bar"></div>
                        </div>
                        <p id="scan-status"><?php _e('Initializing scan...', 'security-breach'); ?></p>
                    </div>
                    
                    <div id="scan-controls">
                        <p><?php _e('Run a comprehensive security scan to identify vulnerabilities and get recommendations for fixing them.', 'security-breach'); ?></p>
                        <button id="run-scan" class="button-primary button-large">
                            <?php _e('Run Security Scan', 'security-breach'); ?>
                        </button>
                        <p class="description">
                            <?php _e('This scan will check for common security vulnerabilities including outdated software, weak configurations, and potential security threats.', 'security-breach'); ?>
                        </p>
                    </div>
                    
                    <div id="scan-results" style="display: none;">
                        <h3><?php _e('Scan Results', 'security-breach'); ?></h3>
                        <div id="results-summary"></div>
                        <div id="results-details"></div>
                    </div>
                </div>
            </div>
            
            <div class="postbox">
                <h2 class="hndle"><span><?php _e('Quick Security Overview', 'security-breach'); ?></span></h2>
                <div class="inside">
                    <div class="security-overview-grid">
                        <div class="security-metric">
                            <h4><?php _e('WordPress Version', 'security-breach'); ?></h4>
                            <p class="metric-value"><?php echo get_bloginfo('version'); ?></p>
                            <p class="metric-status <?php echo version_compare(get_bloginfo('version'), '6.0', '>=') ? 'status-good' : 'status-warning'; ?>">
                                <?php echo version_compare(get_bloginfo('version'), '6.0', '>=') ? __('Up to date', 'security-breach') : __('Needs update', 'security-breach'); ?>
                            </p>
                        </div>
                        
                        <div class="security-metric">
                            <h4><?php _e('SSL Status', 'security-breach'); ?></h4>
                            <p class="metric-value"><?php echo is_ssl() ? 'HTTPS' : 'HTTP'; ?></p>
                            <p class="metric-status <?php echo is_ssl() ? 'status-good' : 'status-critical'; ?>">
                                <?php echo is_ssl() ? __('Secure', 'security-breach') : __('Not secure', 'security-breach'); ?>
                            </p>
                        </div>
                        
                        <div class="security-metric">
                            <h4><?php _e('Admin Users', 'security-breach'); ?></h4>
                            <?php $admin_count = count(get_users(array('role' => 'administrator'))); ?>
                            <p class="metric-value"><?php echo $admin_count; ?></p>
                            <p class="metric-status <?php echo $admin_count > 1 ? 'status-good' : 'status-warning'; ?>">
                                <?php echo $admin_count > 1 ? __('Multiple admins', 'security-breach') : __('Single admin', 'security-breach'); ?>
                            </p>
                        </div>
                        
                        <div class="security-metric">
                            <h4><?php _e('File Editing', 'security-breach'); ?></h4>
                            <p class="metric-value"><?php echo defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT ? __('Disabled', 'security-breach') : __('Enabled', 'security-breach'); ?></p>
                            <p class="metric-status <?php echo defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT ? 'status-good' : 'status-warning'; ?>">
                                <?php echo defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT ? __('Secure', 'security-breach') : __('Vulnerable', 'security-breach'); ?>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="postbox-container" style="width: 30%;">
            <div class="postbox">
                <h2 class="hndle"><span><?php _e('Security Tips', 'security-breach'); ?></span></h2>
                <div class="inside">
                    <ul class="security-tips">
                        <li><?php _e('Keep WordPress, themes, and plugins updated', 'security-breach'); ?></li>
                        <li><?php _e('Use strong, unique passwords', 'security-breach'); ?></li>
                        <li><?php _e('Enable two-factor authentication', 'security-breach'); ?></li>
                        <li><?php _e('Regular security scans and backups', 'security-breach'); ?></li>
                        <li><?php _e('Limit login attempts', 'security-breach'); ?></li>
                        <li><?php _e('Use HTTPS/SSL encryption', 'security-breach'); ?></li>
                        <li><?php _e('Hide WordPress version information', 'security-breach'); ?></li>
                        <li><?php _e('Disable file editing in admin', 'security-breach'); ?></li>
                    </ul>
                </div>
            </div>
            
            <div class="postbox">
                <h2 class="hndle"><span><?php _e('Recent Scans', 'security-breach'); ?></span></h2>
                <div class="inside">
                    <?php
                    global $wpdb;
                    $table_name = $wpdb->prefix . 'security_breach_scans';
                    $recent_scans = $wpdb->get_results(
                        "SELECT DISTINCT scan_date, COUNT(*) as vulnerability_count 
                         FROM $table_name 
                         GROUP BY DATE(scan_date) 
                         ORDER BY scan_date DESC 
                         LIMIT 5"
                    );
                    
                    if ($recent_scans) {
                        echo '<ul class="recent-scans">';
                        foreach ($recent_scans as $scan) {
                            $date = date('M j, Y', strtotime($scan->scan_date));
                            echo '<li>';
                            echo '<strong>' . $date . '</strong><br>';
                            echo sprintf(_n('%d vulnerability found', '%d vulnerabilities found', $scan->vulnerability_count, 'security-breach'), $scan->vulnerability_count);
                            echo '</li>';
                        }
                        echo '</ul>';
                    } else {
                        echo '<p>' . __('No scans performed yet.', 'security-breach') . '</p>';
                    }
                    ?>
                    
                    <p>
                        <a href="<?php echo admin_url('admin.php?page=security-breach-results'); ?>" class="button">
                            <?php _e('View All Results', 'security-breach'); ?>
                        </a>
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
