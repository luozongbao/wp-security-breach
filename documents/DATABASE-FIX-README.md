# Security Breach Plugin - Database Table Fix

## Problem Description
After uninstalling and reinstalling the WordPress Security Breach plugin, the database table (`wp_security_breach_scans`) was not being recreated automatically. This caused the plugin to malfunction because it couldn't store or retrieve scan results.

## Root Cause
The issue occurred because WordPress doesn't always trigger the plugin activation hook when a plugin is reinstalled, especially if certain conditions aren't met. The original plugin only created the database table during activation, so if the activation hook wasn't triggered, the table remained missing.

## Solution Implemented

### 1. Automatic Database Check (Primary Fix)
- Added `check_database_setup()` function that runs on every admin page load
- Checks if the database table exists and if the stored version matches the plugin version
- Automatically recreates the table if it's missing or outdated
- Added version tracking with `security_breach_db_version` option

### 2. Enhanced Table Creation Function
- Improved `create_scan_results_table()` with better error handling
- Added logging of database errors to WordPress error log
- Added verification that table was created successfully
- Added admin notices for database creation failures

### 3. Manual Table Recreation (Backup Solution)
- Added "Database Diagnostics" section to admin page
- Shows current table status and version information
- Provides "Recreate Database Table" button for manual fix
- Added AJAX handler for table recreation with user feedback

### 4. Improved Uninstall Process
- Updated `uninstall.php` to properly clean up the version option

## Files Modified

### Core Plugin File (`security-breach.php`)
- Added `check_database_setup()` and `table_exists()` methods
- Enhanced `create_scan_results_table()` with error handling
- Added `ajax_recreate_table()` method for manual table recreation
- Added database version tracking in `activate()` method

### Admin Interface (`includes/admin-page.php`)
- Added "Database Diagnostics" section with status indicators
- Enhanced "Recent Scans" section to handle missing table gracefully
- Added manual table recreation button with user-friendly interface

### JavaScript (`assets/admin.js`)
- Added `recreateTable()` function for AJAX table recreation
- Added user confirmation and progress feedback
- Added automatic page refresh after successful recreation

### CSS (`assets/admin.css`)
- Added status indicator styles for database diagnostics
- Added error and success state styling

### Cleanup (`uninstall.php`)
- Added removal of `security_breach_db_version` option

## Usage Instructions

### Automatic Fix
1. Simply access any Security Breach plugin page in WordPress admin
2. The plugin will automatically check and recreate the table if needed
3. No user action required - works in the background

### Manual Fix (if needed)
1. Go to WordPress Admin → Security Breach
2. Scroll down to "Database Diagnostics" section
3. Check the table status - it will show "✗ Table missing" if there's an issue
4. Click "Recreate Database Table" button
5. Confirm the action (this will delete any existing scan data)
6. The page will refresh automatically after successful recreation

### Verification
1. Use the diagnostic script at `/debug-db.php` (access via browser)
2. Check the "Database Diagnostics" section in the admin
3. Look for "✓ Table exists" status

## Prevention
This fix ensures the database table issue won't happen again because:
- The plugin checks for table existence on every admin load
- Version tracking prevents compatibility issues
- Manual recreation option provides a backup solution
- Better error logging helps with troubleshooting

## Testing
To test the fix:
1. Manually delete the table: `DROP TABLE wp_security_breach_scans;`
2. Access the Security Breach admin page
3. Verify the table is automatically recreated
4. Run a security scan to confirm functionality

## Technical Details
- Table name: `{wp_prefix}security_breach_scans`
- Version option: `security_breach_db_version`
- Hook used: `admin_init` for automatic checking
- AJAX action: `security_breach_recreate_table` for manual recreation
