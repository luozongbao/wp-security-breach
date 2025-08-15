<?php
// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

global $wpdb;
$table_name = $wpdb->prefix . 'security_breach_scans';

// Handle bulk actions
if (isset($_POST['action']) && $_POST['action'] === 'mark_resolved' && isset($_POST['vulnerability_ids'])) {
    check_admin_referer('security_breach_bulk_action');
    $ids = array_map('intval', $_POST['vulnerability_ids']);
    if (!empty($ids)) {
        $ids_string = implode(',', $ids);
        $wpdb->query("UPDATE $table_name SET status = 'resolved' WHERE id IN ($ids_string)");
        echo '<div class="notice notice-success"><p>' . __('Selected vulnerabilities marked as resolved.', 'security-breach') . '</p></div>';
    }
}

// Get filter parameters
$severity_filter = isset($_GET['severity']) ? sanitize_text_field($_GET['severity']) : '';
$status_filter = isset($_GET['status']) ? sanitize_text_field($_GET['status']) : 'pending';
$type_filter = isset($_GET['type']) ? sanitize_text_field($_GET['type']) : '';

// Build query
$where_conditions = array("1=1");
$query_params = array();

if ($severity_filter) {
    $where_conditions[] = "severity = %s";
    $query_params[] = $severity_filter;
}

if ($status_filter) {
    $where_conditions[] = "status = %s";
    $query_params[] = $status_filter;
}

if ($type_filter) {
    $where_conditions[] = "vulnerability_type = %s";
    $query_params[] = $type_filter;
}

$where_clause = implode(' AND ', $where_conditions);

// Get results
$query = "SELECT * FROM $table_name WHERE $where_clause ORDER BY 
          FIELD(severity, 'critical', 'high', 'medium', 'low'), 
          scan_date DESC";

if (!empty($query_params)) {
    $results = $wpdb->get_results($wpdb->prepare($query, $query_params));
} else {
    $results = $wpdb->get_results($query);
}

// Get filter options
$severity_options = $wpdb->get_col("SELECT DISTINCT severity FROM $table_name ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low')");
$type_options = $wpdb->get_col("SELECT DISTINCT vulnerability_type FROM $table_name ORDER BY vulnerability_type");
?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
    
    <!-- Filters -->
    <div class="tablenav top">
        <form method="get" id="vulnerability-filter">
            <input type="hidden" name="page" value="security-breach-results">
            
            <select name="severity">
                <option value=""><?php _e('All Severities', 'security-breach'); ?></option>
                <?php foreach ($severity_options as $severity): ?>
                    <option value="<?php echo esc_attr($severity); ?>" <?php selected($severity_filter, $severity); ?>>
                        <?php echo ucfirst(esc_html($severity)); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            
            <select name="status">
                <option value=""><?php _e('All Statuses', 'security-breach'); ?></option>
                <option value="pending" <?php selected($status_filter, 'pending'); ?>><?php _e('Pending', 'security-breach'); ?></option>
                <option value="resolved" <?php selected($status_filter, 'resolved'); ?>><?php _e('Resolved', 'security-breach'); ?></option>
            </select>
            
            <select name="type">
                <option value=""><?php _e('All Types', 'security-breach'); ?></option>
                <?php foreach ($type_options as $type): ?>
                    <option value="<?php echo esc_attr($type); ?>" <?php selected($type_filter, $type); ?>>
                        <?php echo esc_html($type); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            
            <input type="submit" class="button" value="<?php _e('Filter', 'security-breach'); ?>">
            
            <?php if ($severity_filter || $status_filter || $type_filter): ?>
                <a href="<?php echo admin_url('admin.php?page=security-breach-results'); ?>" class="button">
                    <?php _e('Clear Filters', 'security-breach'); ?>
                </a>
            <?php endif; ?>
        </form>
    </div>
    
    <?php if ($results): ?>
        <form method="post">
            <?php wp_nonce_field('security_breach_bulk_action'); ?>
            
            <div class="tablenav top">
                <div class="alignleft actions bulkactions">
                    <select name="action">
                        <option value=""><?php _e('Bulk Actions', 'security-breach'); ?></option>
                        <option value="mark_resolved"><?php _e('Mark as Resolved', 'security-breach'); ?></option>
                    </select>
                    <input type="submit" class="button action" value="<?php _e('Apply', 'security-breach'); ?>">
                </div>
            </div>
            
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <td class="manage-column column-cb check-column">
                            <input type="checkbox" id="cb-select-all">
                        </td>
                        <th class="manage-column"><?php _e('Severity', 'security-breach'); ?></th>
                        <th class="manage-column"><?php _e('Type', 'security-breach'); ?></th>
                        <th class="manage-column"><?php _e('Description', 'security-breach'); ?></th>
                        <th class="manage-column"><?php _e('Suggestion', 'security-breach'); ?></th>
                        <th class="manage-column"><?php _e('Date', 'security-breach'); ?></th>
                        <th class="manage-column"><?php _e('Status', 'security-breach'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($results as $vulnerability): ?>
                        <tr class="vulnerability-row severity-<?php echo esc_attr($vulnerability->severity); ?>">
                            <th class="check-column">
                                <input type="checkbox" name="vulnerability_ids[]" value="<?php echo esc_attr($vulnerability->id); ?>">
                            </th>
                            <td class="severity-column">
                                <span class="severity-badge severity-<?php echo esc_attr($vulnerability->severity); ?>">
                                    <?php echo ucfirst(esc_html($vulnerability->severity)); ?>
                                </span>
                            </td>
                            <td class="type-column">
                                <strong><?php echo esc_html($vulnerability->vulnerability_type); ?></strong>
                            </td>
                            <td class="description-column">
                                <p><?php echo esc_html($vulnerability->description); ?></p>
                            </td>
                            <td class="suggestion-column">
                                <div class="suggestion-box">
                                    <strong><?php _e('Solution:', 'security-breach'); ?></strong>
                                    <p><?php echo esc_html($vulnerability->suggestion); ?></p>
                                </div>
                            </td>
                            <td class="date-column">
                                <?php echo date('M j, Y g:i A', strtotime($vulnerability->scan_date)); ?>
                            </td>
                            <td class="status-column">
                                <span class="status-badge status-<?php echo esc_attr($vulnerability->status); ?>">
                                    <?php echo ucfirst(esc_html($vulnerability->status)); ?>
                                </span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </form>
        
        <!-- Summary Statistics -->
        <div class="security-summary">
            <h3><?php _e('Vulnerability Summary', 'security-breach'); ?></h3>
            <?php
            $summary = $wpdb->get_results(
                "SELECT severity, COUNT(*) as count 
                 FROM $table_name 
                 WHERE status = 'pending'
                 GROUP BY severity 
                 ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low')"
            );
            
            if ($summary): ?>
                <div class="summary-grid">
                    <?php foreach ($summary as $item): ?>
                        <div class="summary-item severity-<?php echo esc_attr($item->severity); ?>">
                            <div class="summary-count"><?php echo esc_html($item->count); ?></div>
                            <div class="summary-label"><?php echo ucfirst(esc_html($item->severity)); ?></div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
        
    <?php else: ?>
        <div class="notice notice-info">
            <p><?php _e('No vulnerabilities found. Run a security scan to check for issues.', 'security-breach'); ?></p>
            <p>
                <a href="<?php echo admin_url('admin.php?page=security-breach'); ?>" class="button-primary">
                    <?php _e('Run Security Scan', 'security-breach'); ?>
                </a>
            </p>
        </div>
    <?php endif; ?>
</div>

<script>
jQuery(document).ready(function($) {
    // Select all checkbox functionality
    $('#cb-select-all').on('change', function() {
        $('input[name="vulnerability_ids[]"]').prop('checked', this.checked);
    });
    
    // Update select all when individual checkboxes change
    $('input[name="vulnerability_ids[]"]').on('change', function() {
        var total = $('input[name="vulnerability_ids[]"]').length;
        var checked = $('input[name="vulnerability_ids[]"]:checked').length;
        $('#cb-select-all').prop('checked', total === checked);
    });
});
</script>
