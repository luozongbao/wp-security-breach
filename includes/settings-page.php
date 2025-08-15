<?php
// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Handle settings save
if (isset($_POST['submit']) && wp_verify_nonce($_POST['security_breach_settings_nonce'], 'security_breach_settings')) {
    update_option('security_breach_scan_frequency', sanitize_text_field($_POST['scan_frequency']));
    update_option('security_breach_email_notifications', isset($_POST['email_notifications']) ? 1 : 0);
    update_option('security_breach_notification_email', sanitize_email($_POST['notification_email']));
    update_option('security_breach_auto_scan', isset($_POST['auto_scan']) ? 1 : 0);
    update_option('security_breach_scan_plugins', isset($_POST['scan_plugins']) ? 1 : 0);
    update_option('security_breach_scan_themes', isset($_POST['scan_themes']) ? 1 : 0);
    update_option('security_breach_scan_core', isset($_POST['scan_core']) ? 1 : 0);
    update_option('security_breach_scan_malware', isset($_POST['scan_malware']) ? 1 : 0);
    update_option('security_breach_severity_threshold', sanitize_text_field($_POST['severity_threshold']));
    
    echo '<div class="notice notice-success"><p>' . __('Settings saved successfully.', 'security-breach') . '</p></div>';
}

// Get current settings
$scan_frequency = get_option('security_breach_scan_frequency', 'daily');
$email_notifications = get_option('security_breach_email_notifications', 1);
$notification_email = get_option('security_breach_notification_email', get_option('admin_email'));
$auto_scan = get_option('security_breach_auto_scan', 1);
$scan_plugins = get_option('security_breach_scan_plugins', 1);
$scan_themes = get_option('security_breach_scan_themes', 1);
$scan_core = get_option('security_breach_scan_core', 1);
$scan_malware = get_option('security_breach_scan_malware', 1);
$severity_threshold = get_option('security_breach_severity_threshold', 'medium');
?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    
    <form method="post" action="">
        <?php wp_nonce_field('security_breach_settings', 'security_breach_settings_nonce'); ?>
        
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e('Scan Frequency', 'security-breach'); ?></th>
                <td>
                    <select name="scan_frequency">
                        <option value="hourly" <?php selected($scan_frequency, 'hourly'); ?>><?php _e('Hourly', 'security-breach'); ?></option>
                        <option value="daily" <?php selected($scan_frequency, 'daily'); ?>><?php _e('Daily', 'security-breach'); ?></option>
                        <option value="weekly" <?php selected($scan_frequency, 'weekly'); ?>><?php _e('Weekly', 'security-breach'); ?></option>
                        <option value="monthly" <?php selected($scan_frequency, 'monthly'); ?>><?php _e('Monthly', 'security-breach'); ?></option>
                        <option value="never" <?php selected($scan_frequency, 'never'); ?>><?php _e('Never (Manual only)', 'security-breach'); ?></option>
                    </select>
                    <p class="description"><?php _e('How often should automatic security scans be performed?', 'security-breach'); ?></p>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php _e('Enable Automatic Scanning', 'security-breach'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="auto_scan" value="1" <?php checked($auto_scan, 1); ?>>
                        <?php _e('Enable automatic security scans', 'security-breach'); ?>
                    </label>
                    <p class="description"><?php _e('When enabled, scans will run automatically based on the frequency setting above.', 'security-breach'); ?></p>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php _e('Email Notifications', 'security-breach'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="email_notifications" value="1" <?php checked($email_notifications, 1); ?>>
                        <?php _e('Send email notifications when vulnerabilities are found', 'security-breach'); ?>
                    </label>
                    <p class="description"><?php _e('Receive email alerts when new security vulnerabilities are detected.', 'security-breach'); ?></p>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php _e('Notification Email', 'security-breach'); ?></th>
                <td>
                    <input type="email" name="notification_email" value="<?php echo esc_attr($notification_email); ?>" class="regular-text">
                    <p class="description"><?php _e('Email address to receive security notifications.', 'security-breach'); ?></p>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php _e('Minimum Severity for Notifications', 'security-breach'); ?></th>
                <td>
                    <select name="severity_threshold">
                        <option value="low" <?php selected($severity_threshold, 'low'); ?>><?php _e('Low and above', 'security-breach'); ?></option>
                        <option value="medium" <?php selected($severity_threshold, 'medium'); ?>><?php _e('Medium and above', 'security-breach'); ?></option>
                        <option value="high" <?php selected($severity_threshold, 'high'); ?>><?php _e('High and above', 'security-breach'); ?></option>
                        <option value="critical" <?php selected($severity_threshold, 'critical'); ?>><?php _e('Critical only', 'security-breach'); ?></option>
                    </select>
                    <p class="description"><?php _e('Only send notifications for vulnerabilities at or above this severity level.', 'security-breach'); ?></p>
                </td>
            </tr>
        </table>
        
        <h2><?php _e('Scan Components', 'security-breach'); ?></h2>
        <p><?php _e('Choose which components to include in security scans:', 'security-breach'); ?></p>
        
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e('WordPress Core', 'security-breach'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="scan_core" value="1" <?php checked($scan_core, 1); ?>>
                        <?php _e('Scan WordPress core files and version', 'security-breach'); ?>
                    </label>
                    <p class="description"><?php _e('Check for WordPress version vulnerabilities and core file integrity.', 'security-breach'); ?></p>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php _e('Plugins', 'security-breach'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="scan_plugins" value="1" <?php checked($scan_plugins, 1); ?>>
                        <?php _e('Scan installed plugins for vulnerabilities', 'security-breach'); ?>
                    </label>
                    <p class="description"><?php _e('Check for plugin vulnerabilities, outdated versions, and security issues.', 'security-breach'); ?></p>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php _e('Themes', 'security-breach'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="scan_themes" value="1" <?php checked($scan_themes, 1); ?>>
                        <?php _e('Scan installed themes for vulnerabilities', 'security-breach'); ?>
                    </label>
                    <p class="description"><?php _e('Check for theme vulnerabilities and outdated versions.', 'security-breach'); ?></p>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php _e('Malware Detection', 'security-breach'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="scan_malware" value="1" <?php checked($scan_malware, 1); ?>>
                        <?php _e('Scan for malware and suspicious code patterns', 'security-breach'); ?>
                    </label>
                    <p class="description"><?php _e('Detect potential malware, backdoors, and suspicious code in files.', 'security-breach'); ?></p>
                </td>
            </tr>
        </table>
        
        <h2><?php _e('Advanced Settings', 'security-breach'); ?></h2>
        
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e('Database Cleanup', 'security-breach'); ?></th>
                <td>
                    <p><?php _e('Scan results older than 30 days are automatically cleaned up to save database space.', 'security-breach'); ?></p>
                    <button type="button" id="cleanup-old-scans" class="button">
                        <?php _e('Clean Up Old Scan Results Now', 'security-breach'); ?>
                    </button>
                </td>
            </tr>
            
            <tr>
                <th scope="row"><?php _e('Export/Import Settings', 'security-breach'); ?></th>
                <td>
                    <p>
                        <button type="button" id="export-settings" class="button">
                            <?php _e('Export Settings', 'security-breach'); ?>
                        </button>
                        <button type="button" id="import-settings" class="button">
                            <?php _e('Import Settings', 'security-breach'); ?>
                        </button>
                    </p>
                    <input type="file" id="import-file" style="display: none;" accept=".json">
                    <p class="description"><?php _e('Export your current settings or import settings from another site.', 'security-breach'); ?></p>
                </td>
            </tr>
        </table>
        
        <?php submit_button(); ?>
    </form>
    
    <!-- System Information -->
    <div class="postbox" style="margin-top: 20px;">
        <h2 class="hndle"><span><?php _e('System Information', 'security-breach'); ?></span></h2>
        <div class="inside">
            <table class="widefat">
                <tr>
                    <td><strong><?php _e('WordPress Version:', 'security-breach'); ?></strong></td>
                    <td><?php echo get_bloginfo('version'); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('PHP Version:', 'security-breach'); ?></strong></td>
                    <td><?php echo PHP_VERSION; ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('MySQL Version:', 'security-breach'); ?></strong></td>
                    <td><?php global $wpdb; echo $wpdb->get_var('SELECT VERSION()'); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('Server Software:', 'security-breach'); ?></strong></td>
                    <td><?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('SSL Enabled:', 'security-breach'); ?></strong></td>
                    <td><?php echo is_ssl() ? __('Yes', 'security-breach') : __('No', 'security-breach'); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('WP Debug Mode:', 'security-breach'); ?></strong></td>
                    <td><?php echo defined('WP_DEBUG') && WP_DEBUG ? __('Enabled', 'security-breach') : __('Disabled', 'security-breach'); ?></td>
                </tr>
                <tr>
                    <td><strong><?php _e('File Editing:', 'security-breach'); ?></strong></td>
                    <td><?php echo defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT ? __('Disabled', 'security-breach') : __('Enabled', 'security-breach'); ?></td>
                </tr>
            </table>
        </div>
    </div>
</div>

<script>
jQuery(document).ready(function($) {
    $('#cleanup-old-scans').on('click', function() {
        if (confirm('<?php _e('Are you sure you want to delete old scan results?', 'security-breach'); ?>')) {
            $.post(ajaxurl, {
                action: 'security_breach_cleanup',
                nonce: '<?php echo wp_create_nonce('security_breach_cleanup'); ?>'
            }, function(response) {
                if (response.success) {
                    alert('<?php _e('Old scan results cleaned up successfully.', 'security-breach'); ?>');
                } else {
                    alert('<?php _e('Error cleaning up scan results.', 'security-breach'); ?>');
                }
            });
        }
    });
    
    $('#export-settings').on('click', function() {
        var settings = {
            scan_frequency: $('select[name="scan_frequency"]').val(),
            email_notifications: $('input[name="email_notifications"]').is(':checked'),
            notification_email: $('input[name="notification_email"]').val(),
            auto_scan: $('input[name="auto_scan"]').is(':checked'),
            scan_plugins: $('input[name="scan_plugins"]').is(':checked'),
            scan_themes: $('input[name="scan_themes"]').is(':checked'),
            scan_core: $('input[name="scan_core"]').is(':checked'),
            scan_malware: $('input[name="scan_malware"]').is(':checked'),
            severity_threshold: $('select[name="severity_threshold"]').val()
        };
        
        var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(settings, null, 2));
        var downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", "security-breach-settings.json");
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    });
    
    $('#import-settings').on('click', function() {
        $('#import-file').click();
    });
    
    $('#import-file').on('change', function(e) {
        var file = e.target.files[0];
        if (file) {
            var reader = new FileReader();
            reader.onload = function(e) {
                try {
                    var settings = JSON.parse(e.target.result);
                    
                    // Apply settings to form
                    $('select[name="scan_frequency"]').val(settings.scan_frequency);
                    $('input[name="email_notifications"]').prop('checked', settings.email_notifications);
                    $('input[name="notification_email"]').val(settings.notification_email);
                    $('input[name="auto_scan"]').prop('checked', settings.auto_scan);
                    $('input[name="scan_plugins"]').prop('checked', settings.scan_plugins);
                    $('input[name="scan_themes"]').prop('checked', settings.scan_themes);
                    $('input[name="scan_core"]').prop('checked', settings.scan_core);
                    $('input[name="scan_malware"]').prop('checked', settings.scan_malware);
                    $('select[name="severity_threshold"]').val(settings.severity_threshold);
                    
                    alert('<?php _e('Settings imported successfully. Click "Save Changes" to apply.', 'security-breach'); ?>');
                } catch (error) {
                    alert('<?php _e('Error importing settings. Please check the file format.', 'security-breach'); ?>');
                }
            };
            reader.readAsText(file);
        }
    });
});
</script>
