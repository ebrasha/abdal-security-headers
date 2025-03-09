/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal Security Headers
 * File Name    : admin.js
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2024-03-19 12:00:00
 * Description  : Admin interface JavaScript for security headers plugin
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

jQuery(document).ready(function($) {
    // Handle form submission with SweetAlert2
    $('#ash-settings-form').on('submit', function(e) {
        e.preventDefault();
        const $spinner = $('.ash-spinner');
        const $submitButton = $('#ash-submit-button');

        Swal.fire({
            title: ashStrings.confirmSave,
            icon: 'question',
            showCancelButton: true,
            confirmButtonText: ashStrings.yes,
            cancelButtonText: ashStrings.no,
            confirmButtonColor: '#3085d6',
            cancelButtonColor: '#d33',
            customClass: {
                popup: 'rtl-alert'
            }
        }).then((result) => {
            if (result.isConfirmed) {
                var form = $(this);
                
                // Show spinner and disable submit button
                $spinner.show();
                $submitButton.prop('disabled', true);

                $.ajax({
                    url: form.attr('action'),
                    type: 'POST',
                    data: form.serialize(),
                    success: function(response) {
                        // Hide spinner and enable submit button
                        $spinner.hide();
                        $submitButton.prop('disabled', false);

                        Swal.fire({
                            title: ashStrings.success,
                            icon: 'success',
                            confirmButtonText: ashStrings.ok,
                            customClass: {
                                popup: 'rtl-alert'
                            }
                        });
                    },
                    error: function() {
                        // Hide spinner and enable submit button on error
                        $spinner.hide();
                        $submitButton.prop('disabled', false);

                        Swal.fire({
                            title: ashStrings.error,
                            text: ashStrings.errorMessage,
                            icon: 'error',
                            confirmButtonText: ashStrings.ok,
                            customClass: {
                                popup: 'rtl-alert'
                            }
                        });
                    }
                });
            }
        });
    });

    // Handle CSP toggle
    $('#content_security_policy').on('change', function() {
        $('#csp-directives').toggle(this.checked);
        if (this.checked) {
            updateCSPPreview();
        }
    });

    // Handle CSP directive changes
    $('input[data-csp-directive]').on('input', function() {
        if ($('#content_security_policy').is(':checked')) {
            updateCSPPreview();
        }
    });

    // Handle accordion toggle
    $('.csp-accordion-header').on('click', function() {
        var $content = $(this).next('.csp-accordion-content');
        var $arrow = $(this).find('.accordion-arrow');
        
        $content.slideToggle(300);
        $arrow.toggleClass('active');
        
        if ($content.is(':visible')) {
            updateCSPPreview();
        }
    });

    // Handle show preview button
    $('#show-csp-preview').on('click', function() {
        var $preview = $('.csp-preview');
        var $button = $(this);
        
        if ($preview.is(':visible')) {
            $preview.slideUp();
            $button.text(wp.i18n.__('Show CSP Preview', 'abdal-security-headers'));
        } else {
            updateCSPPreview();
            $preview.slideDown();
            $button.text(wp.i18n.__('Hide CSP Preview', 'abdal-security-headers'));
        }
    });

    // Update CSP preview
    function updateCSPPreview() {
        if (!$('#content_security_policy').is(':checked')) {
            return;
        }

        var directives = [];
        
        // Collect all non-empty directives
        $('input[data-csp-directive]').each(function() {
            var directive = $(this).data('csp-directive').replace(/_/g, '-');
            var value = $(this).val().trim();
            
            if (value) {
                directives.push(directive + " " + value);
            }
        });

        // Build the preview
        var preview = '';
        if (directives.length > 0) {
            preview = "Content-Security-Policy: " + directives.join('; ');
        } else {
            preview = "Content-Security-Policy header is enabled but no directives are set.";
        }

        $('#csp-preview-content').text(preview);
    }

    // Initial preview update
    updateCSPPreview();

    // Add tooltips to CSP directives
    var tooltips = {
        'default-src': 'Default fallback for other resource types',
        'script-src': 'Valid sources for JavaScript files',
        'style-src': 'Valid sources for CSS files',
        'img-src': 'Valid sources for images',
        'connect-src': 'Valid sources for AJAX, WebSocket, or EventSource connections',
        'font-src': 'Valid sources for fonts',
        'object-src': 'Valid sources for plugins',
        'media-src': 'Valid sources for audio and video elements',
        'frame-src': 'Valid sources for iframes',
        'worker-src': 'Valid sources for web workers',
        'form-action': 'Valid targets for form submissions',
        'base-uri': 'Valid values for the base element',
        'sandbox': 'Enables sandbox for the requested resource',
        'report-uri': 'URI to send violation reports to',
        'report-to': 'Group name for violation reports'
    };

    // Add tooltips to labels
    $('.csp-directives label').each(function() {
        var directive = $(this).text().toLowerCase().replace(/\s+/g, '-');
        if (tooltips[directive]) {
            $(this).attr('title', tooltips[directive]);
        }
    });

    // Add common values quick-select buttons
    var commonValues = {
        'default-src': ["'self'", "'self' 'unsafe-inline' 'unsafe-eval'"],
        'script-src': ["'self'", "'self' 'unsafe-inline' 'unsafe-eval'"],
        'style-src': ["'self'", "'self' 'unsafe-inline'"],
        'img-src': ["'self'", "'self' data: https:"],
        'connect-src': ["'self'", "'self' https:"],
        'font-src': ["'self'", "'self' data:"],
        'object-src': ["'none'", "'self'"],
        'media-src': ["'self'", "'self' https:"],
        'frame-src': ["'none'", "'self'"],
        'worker-src': ["'self'", "'self' blob:"],
        'form-action': ["'self'", "'self' https:"],
        'base-uri': ["'self'", "'self' https:"]
    };

    // Add quick-select buttons
    $('.csp-directives .ash-field').each(function() {
        var input = $(this).find('input[type="text"]');
        var directive = input.attr('name').match(/\[(.*?)\]/)[1];
        
        if (commonValues[directive]) {
            var buttonGroup = $('<div class="quick-select-buttons"></div>');
            commonValues[directive].forEach(function(value) {
                var button = $('<button type="button" class="button button-small"></button>')
                    .text(value)
                    .click(function() {
                        input.val(value);
                    });
                buttonGroup.append(button);
            });
            $(this).append(buttonGroup);
        }
    });

    // Add validation for CSP directives
    $('.csp-directives input[type="text"]').on('input', function() {
        var value = $(this).val();
        var directive = $(this).attr('name').match(/\[(.*?)\]/)[1];
        
        // Basic validation for common directives
        if (directive === 'default-src' && !value.includes("'self'")) {
            $(this).addClass('error');
        } else {
            $(this).removeClass('error');
        }
    });
}); 