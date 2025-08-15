jQuery(document).ready(function($) {
    'use strict';
    
    // Initialize the Security Breach plugin
    var SecurityBreach = {
        init: function() {
            this.bindEvents();
            this.initTooltips();
        },
        
        bindEvents: function() {
            $('#run-scan').on('click', this.runSecurityScan);
            $(document).on('click', '.vulnerability-header', this.toggleVulnerabilityDetails);
            $(document).on('click', '.mark-resolved', this.markAsResolved);
            this.setupProgressAnimation();
        },
        
        runSecurityScan: function(e) {
            e.preventDefault();
            
            var $button = $(this);
            var $controls = $('#scan-controls');
            var $progress = $('#scan-progress');
            var $results = $('#scan-results');
            
            // Reset UI
            $results.hide();
            $controls.hide();
            $progress.show();
            
            // Start progress animation
            SecurityBreach.animateProgress();
            
            // Update status messages during scan
            var statusMessages = [
                securityBreachAjax.scanning_text,
                'Checking WordPress version...',
                'Scanning plugins...',
                'Scanning themes...',
                'Checking file permissions...',
                'Analyzing database security...',
                'Checking user accounts...',
                'Scanning for malware...',
                'Validating SSL configuration...',
                'Checking security headers...',
                'Analyzing configuration files...',
                'Finalizing scan results...'
            ];
            
            var currentMessage = 0;
            var messageInterval = setInterval(function() {
                if (currentMessage < statusMessages.length) {
                    $('#scan-status').text(statusMessages[currentMessage]);
                    currentMessage++;
                } else {
                    clearInterval(messageInterval);
                }
            }, 2000);
            
            // Run the actual scan
            $.ajax({
                url: securityBreachAjax.ajax_url,
                type: 'POST',
                data: {
                    action: 'run_security_scan',
                    nonce: securityBreachAjax.nonce
                },
                success: function(response) {
                    clearInterval(messageInterval);
                    
                    if (response.success) {
                        SecurityBreach.displayScanResults(response.data);
                        SecurityBreach.showNotification('Scan completed successfully!', 'success');
                    } else {
                        SecurityBreach.showNotification('Scan failed: ' + (response.data || 'Unknown error'), 'error');
                        $controls.show();
                    }
                    
                    $progress.hide();
                },
                error: function(xhr, status, error) {
                    clearInterval(messageInterval);
                    SecurityBreach.showNotification('Scan failed due to server error: ' + error, 'error');
                    $progress.hide();
                    $controls.show();
                },
                timeout: 120000 // 2 minute timeout
            });
        },
        
        animateProgress: function() {
            var $progressBar = $('.progress-bar');
            var progress = 0;
            
            var progressInterval = setInterval(function() {
                progress += Math.random() * 15;
                if (progress > 95) {
                    progress = 95;
                    clearInterval(progressInterval);
                }
                $progressBar.css('width', progress + '%');
            }, 1000);
            
            // Store interval for cleanup
            window.securityBreachProgressInterval = progressInterval;
        },
        
        displayScanResults: function(vulnerabilities) {
            var $results = $('#scan-results');
            var $summary = $('#results-summary');
            var $details = $('#results-details');
            
            // Complete progress bar
            $('.progress-bar').css('width', '100%');
            $('#scan-status').text(securityBreachAjax.scan_complete_text);
            
            setTimeout(function() {
                // Generate summary
                var summary = SecurityBreach.generateSummary(vulnerabilities);
                $summary.html(summary);
                
                // Generate detailed results
                var details = SecurityBreach.generateDetails(vulnerabilities);
                $details.html(details);
                
                $results.show();
                
                // Scroll to results
                $('html, body').animate({
                    scrollTop: $results.offset().top - 50
                }, 500);
            }, 1000);
        },
        
        generateSummary: function(vulnerabilities) {
            var counts = {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                total: vulnerabilities.length
            };
            
            vulnerabilities.forEach(function(vuln) {
                if (counts.hasOwnProperty(vuln.severity)) {
                    counts[vuln.severity]++;
                }
            });
            
            var html = '<div class="results-summary-grid">';
            
            html += '<div class="result-summary-item total">';
            html += '<span class="result-summary-count">' + counts.total + '</span>';
            html += '<div class="result-summary-label">Total Issues</div>';
            html += '</div>';
            
            if (counts.critical > 0) {
                html += '<div class="result-summary-item critical">';
                html += '<span class="result-summary-count">' + counts.critical + '</span>';
                html += '<div class="result-summary-label">Critical</div>';
                html += '</div>';
            }
            
            if (counts.high > 0) {
                html += '<div class="result-summary-item high">';
                html += '<span class="result-summary-count">' + counts.high + '</span>';
                html += '<div class="result-summary-label">High</div>';
                html += '</div>';
            }
            
            if (counts.medium > 0) {
                html += '<div class="result-summary-item medium">';
                html += '<span class="result-summary-count">' + counts.medium + '</span>';
                html += '<div class="result-summary-label">Medium</div>';
                html += '</div>';
            }
            
            if (counts.low > 0) {
                html += '<div class="result-summary-item low">';
                html += '<span class="result-summary-count">' + counts.low + '</span>';
                html += '<div class="result-summary-label">Low</div>';
                html += '</div>';
            }
            
            html += '</div>';
            
            if (counts.total === 0) {
                html = '<div class="notice notice-success"><p><strong>Great news!</strong> No security vulnerabilities were found during the scan.</p></div>';
            } else {
                var message = counts.total === 1 ? 
                    'Found 1 security vulnerability that needs attention.' : 
                    'Found ' + counts.total + ' security vulnerabilities that need attention.';
                    
                var noticeClass = counts.critical > 0 ? 'notice-error' : 
                                 counts.high > 0 ? 'notice-warning' : 'notice-info';
                                 
                html = '<div class="notice ' + noticeClass + '"><p><strong>' + message + '</strong></p></div>' + html;
            }
            
            return html;
        },
        
        generateDetails: function(vulnerabilities) {
            if (vulnerabilities.length === 0) {
                return '<p>No vulnerabilities detected. Your site appears to be secure!</p>';
            }
            
            var html = '<div class="vulnerability-list">';
            
            vulnerabilities.forEach(function(vuln, index) {
                html += '<div class="vulnerability-item severity-' + vuln.severity + '">';
                html += '<div class="vulnerability-header" data-toggle="' + index + '">';
                html += '<div class="vulnerability-title">';
                html += '<span class="severity-badge severity-' + vuln.severity + '">' + vuln.severity.toUpperCase() + '</span> ';
                html += vuln.type;
                html += '</div>';
                html += '<span class="dashicons dashicons-arrow-down-alt2"></span>';
                html += '</div>';
                html += '<div class="vulnerability-content" id="vuln-content-' + index + '" style="display: none;">';
                html += '<div class="vulnerability-description">' + vuln.description + '</div>';
                html += '<div class="suggestion-box">';
                html += '<strong>Recommended Solution:</strong>';
                html += '<p>' + vuln.suggestion + '</p>';
                html += '</div>';
                html += '</div>';
                html += '</div>';
            });
            
            html += '</div>';
            
            return html;
        },
        
        toggleVulnerabilityDetails: function(e) {
            var $header = $(this);
            var $content = $header.next('.vulnerability-content');
            var $arrow = $header.find('.dashicons');
            
            if ($content.is(':visible')) {
                $content.slideUp();
                $arrow.removeClass('dashicons-arrow-up-alt2').addClass('dashicons-arrow-down-alt2');
            } else {
                $content.slideDown();
                $arrow.removeClass('dashicons-arrow-down-alt2').addClass('dashicons-arrow-up-alt2');
            }
        },
        
        markAsResolved: function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            var $button = $(this);
            var vulnerabilityId = $button.data('id');
            
            if (!confirm('Mark this vulnerability as resolved?')) {
                return;
            }
            
            $.ajax({
                url: securityBreachAjax.ajax_url,
                type: 'POST',
                data: {
                    action: 'mark_vulnerability_resolved',
                    vulnerability_id: vulnerabilityId,
                    nonce: securityBreachAjax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $button.closest('.vulnerability-item').fadeOut();
                        SecurityBreach.showNotification('Vulnerability marked as resolved', 'success');
                    } else {
                        SecurityBreach.showNotification('Failed to update vulnerability status', 'error');
                    }
                },
                error: function() {
                    SecurityBreach.showNotification('Server error occurred', 'error');
                }
            });
        },
        
        showNotification: function(message, type) {
            type = type || 'info';
            
            var $notification = $('<div class="security-breach-notification ' + type + '">' + message + '</div>');
            $('body').append($notification);
            
            // Slide in from right
            $notification.css({
                'right': '-400px',
                'opacity': '0'
            }).animate({
                'right': '20px',
                'opacity': '1'
            }, 300);
            
            // Auto-remove after 5 seconds
            setTimeout(function() {
                $notification.animate({
                    'right': '-400px',
                    'opacity': '0'
                }, 300, function() {
                    $notification.remove();
                });
            }, 5000);
        },
        
        initTooltips: function() {
            // Add tooltips for severity badges
            $(document).on('mouseenter', '.severity-badge', function() {
                var severity = $(this).text().toLowerCase();
                var tooltips = {
                    'critical': 'Immediate action required - high risk of compromise',
                    'high': 'Should be addressed soon - significant security risk',
                    'medium': 'Moderate security concern - address when possible',
                    'low': 'Minor security improvement - low priority'
                };
                
                if (tooltips[severity]) {
                    $(this).attr('title', tooltips[severity]);
                }
            });
        },
        
        setupProgressAnimation: function() {
            // Clean up any existing intervals
            if (window.securityBreachProgressInterval) {
                clearInterval(window.securityBreachProgressInterval);
            }
        }
    };
    
    // Initialize the plugin
    SecurityBreach.init();
    
    // Handle page visibility change to pause/resume scans
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            // Page is hidden, could pause intensive operations
        } else {
            // Page is visible, resume operations
        }
    });
    
    // Cleanup on page unload
    $(window).on('beforeunload', function() {
        if (window.securityBreachProgressInterval) {
            clearInterval(window.securityBreachProgressInterval);
        }
    });
    
    // Auto-refresh scan results every 30 seconds if scan is running
    setInterval(function() {
        if ($('#scan-progress').is(':visible')) {
            // Could add periodic status checks here
        }
    }, 30000);
    
    // Enhanced keyboard navigation
    $(document).on('keydown', function(e) {
        // ESC key to close vulnerability details
        if (e.key === 'Escape') {
            $('.vulnerability-content:visible').slideUp();
            $('.dashicons-arrow-up-alt2').removeClass('dashicons-arrow-up-alt2').addClass('dashicons-arrow-down-alt2');
        }
    });
    
    // Add keyboard accessibility to vulnerability items
    $(document).on('keydown', '.vulnerability-header', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            $(this).click();
        }
    });
    
    // Make vulnerability headers focusable
    $('.vulnerability-header').attr('tabindex', '0');
});
