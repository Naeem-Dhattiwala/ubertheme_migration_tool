// Javascript on this tool
(function ($) {
    $(document).ready(function ($) {

        $(".numberOnly").keypress(function (e) {
            //if the letter is not digit then display error and don't type anything
            if (e.which != 8 && e.which != 0 && (e.which < 48 || e.which > 57)) {
                return false;
            }
        });

        //flag to run all steps or not
        var running = false;
        var runAllSteps = false;
        var resetAllSteps = false;
        var maxRunIndex = 1;
        var minResetIndex = 0;


        $.ubInitial = function() {
            //update maxRunIndex vairable
            $('.migrate-steps a.btn-run').each(function(i, el){
                if (!$(el).hasClass('disabled')) {
                    maxRunIndex++;
                }
            });
            //update minResetIndex variable
            minResetIndex = ($('.migrate-steps a.btn-reset').length) ? $('.migrate-steps a.btn-reset').first().data('step-index') : 0;
        }
        $.ubInitial();

        /**
         * Migrate data function
         * @param $step
         */
        $.ubMigrate = function ($step) {
            $.ajax({
                url: $step.attr('href'),
                dataType: 'json',
                beforeSend: function () {
                    if (!$step.hasClass('ub-migrating')) {
                        //update button status
                        $step.addClass('ub-migrating');
                        //update step status
                        $('#step-status-' + $step.data('step-index')).html('<span class="step-status ub-migrating animated fadeIn infinite">migrating...</span>');

                        //show process bar
                        $('#all-steps-process').show();

                        //show mask
                        $.showMask('migrate');
                    }
                },
                success: function (rs) {
                    if (rs.status == 'ok') {

                        if (typeof rs.percent_up != 'undefined') {
                            //update percent finished
                            $.updatePercent(rs.percent_up);
                        }

                        //process to continue on this step
                        $.ubMigrate($step);

                    } else if (rs.status == 'done') {
                        $step.removeClass('ub-migrating');

                        //update step status info
                        $.updateStepStatus(rs);

                        //update process bar info
                        $.updateProcessBar(rs);

                        if (runAllSteps) {
                            //process to migrate with next step if is migrate all step context
                            if (rs.step_index < maxRunIndex) {
                                $('#run-step-' + (parseInt(rs.step_index) + 1)).trigger('click');
                            } else {
                                //update run all button label
                                $('#run-all-steps').find('.btn-label').html('Delta all steps');

                                //disable run all mode
                                runAllSteps = false;

                                //show success message
                                $.showMessages("The data migration has been completed successfully. You still have a few more steps before your data is ready for use. Follow instructions in the Readme.html that came with your download package to complete, then you\'re done.", "success");

                                //hide mask
                                $.hideMask();
                            }
                        } else {
                            //update log
                            $.updateLog();

                            //hide loading mask
                            $.hideMask();
                        }
                    } else {
                        //disable run all mode
                        runAllSteps = false;

                        //alert errors/notice if has
                        if (typeof rs.errors != 'undefined' && rs.errors.length) {
                            $('#step-status-' + rs.step_index).addClass('error');
                            $.showMessages(rs.errors, 'error');
                        } else if (typeof rs.notice != 'undefined' && rs.notice.length) {
                            $.showMessages(rs.notice, 'notice');
                        }

                        //update button status
                        $step.removeClass('ub-migrating');

                        //update step status text
                        $('#step-status-' + rs.step_index).html(rs.step_status_text);

                        $.hideMask();
                    }
                }
            });
        }

        //bind event to cal migrate data function
        $('.migrate-steps a.btn-run').each(function () {
            var $step = $(this);
            $step.on('click', function (e) {
                e.preventDefault();
                if (!$step.hasClass('disabled')) {
                    $.ubMigrate($step);
                } else {
                    //run next step
                    var currentStepIndex = $step.data('step-index');
                    if (currentStepIndex < maxRunIndex) {
                        $('#run-step-' + (currentStepIndex + 1)).trigger('click');
                    }
                    else {
                        runAllSteps = false;
                        $.hideMask();
                    }
                }
            });
        });

        //bind event to call migrate data function after click to run all button
        $.runAllSteps = function () {
            //set run all steps mode
            runAllSteps = true;

            //get all steps
            var $steps =  $('.migrate-steps a.btn-run');
            var $startStep = $steps.first();

            //check has processing step
            $steps.each(function(i) {
                if ($(this).parent().parent().hasClass('migrating')) {
                    $startStep = $(this);
                }
            });

            //do migrate for start step
            $.ubMigrate($startStep);
        }

        $.updateStepStatus = function (rs) {
            if (typeof rs.step_status_text != 'undefined') {
                $('#step-status-' + rs.step_index).html(rs.step_status_text);
            }
            //update btn-label of current step
            if (rs.status == 'done') {
                $('#run-step-' + rs.step_index).find('.btn-label').html('Delta');
                if ($('#setting-step-' + rs.step_index).length) {
                    if (!$('#setting-step-' + rs.step_index).hasClass('finished')) {
                        $('#setting-step-' + rs.step_index).find('a').find('.step-status').removeClass('setting').addClass('finished').html('finished');
                        $('#setting-step-' + rs.step_index).removeClass('setting').addClass('finished');
                    }
                }
            }
        }

        /**
         * Update process bar function
         * @param rs
         */
        $.updateProcessBar = function (rs) {
            if (typeof rs.percent_done != 'undefined') {
                if ($('#percent-finished').length) {
                    $('#percent-finished').html(rs.percent_done + '%');
                }
                //update process bar info
                $('#all-steps-process').find('.progress-bar').css({"width": rs.percent_done + '%'}).attr('aria-valuenow', rs.percent_done).html('<span class="value">' + rs.percent_done + '</span>% Completed');
            }
        }

        /**
         * Update percent finished in process bar function
         * @param percentUp
         */
        $.updatePercent = function (percentUp) {
            //update process bar info
            var $processBar = $('#all-steps-process').find('.progress-bar');
            var cPercent = $processBar.attr('aria-valuenow');
            var cPercent = parseFloat(cPercent) + parseFloat(percentUp);
            var percent = cPercent.toFixed(3).replace(/(\d)(?=(\d{3})+\.)/g, '$1,');
            $processBar.css({"width": cPercent + '%'}).attr('aria-valuenow', cPercent).html('<span class="value">' + percent + '</span>% Completed');
        }

        /**
         * Reset data function
         * @param $step
         */
        $.ubReset = function ($step) {
            $.ajax({
                url: $step.attr('href'),
                dataType: 'json',
                beforeSend: function () {
                    if (!$step.hasClass('ub-resetting')) {

                        //update step status
                        $step.addClass('ub-resetting');

                        //update step status
                        $('#step-status-' + $step.data('step-index')).html('<span class="step-status ub-resetting animated fadeIn infinite">resetting...</span>');

                        //show mask loading
                        $.showMask('reset');
                    }
                },
                success: function (rs) {
                    if (rs.status == 'ok') {
                        //continue call reset on this step
                        $.ubReset($step);

                    } else if (rs.status == 'done') {
                        //update button status
                        $step.removeClass('ub-resetting');

                        //update step status text
                        if (rs.step_status_text != 'undefined') {
                            $('#step-status-' + rs.step_index).html(rs.step_status_text);
                        }

                        //process to reset next step if in reset all steps mode
                        if (resetAllSteps) {
                            if (rs.step_index > minResetIndex) {
                                $.ubReset($('#reset-step-' + (parseInt(rs.step_index) - 1)));
                            } else {
                                resetAllSteps = false;
                                $.hideMask();
                                //redirect to setting form of step #1
                                window.location = $('#setting-step-1').find('a').attr('href');
                            }
                        } else {
                            $.hideMask();
                            //redirect to setting form of current step
                            window.location = $('#setting-step-' + $step.data('step-index')).find('a').attr('href');
                        }
                    } else {
                        //disable resetAllSteps mode
                        resetAllSteps = false;

                        //alert errors/notice if has
                        if (typeof rs.errors != 'undefined' && rs.errors.length) {
                            $.showMessages(rs.errors, 'error');
                        } else if (typeof rs.notice != 'undefined' && rs.notice.length) {
                            $.showMessages(rs.notice, 'notice');
                        }

                        //update button status
                        $step.removeClass('ub-resetting');

                        //update step status text
                        $('#step-status-' + rs.step_index).html(rs.step_status_text);

                        $.hideMask();
                    }
                }
            });
        }

        //bind event to call reset data function
        $('.migrate-steps a.btn-reset').each(function () {
            var $step = $(this);
            $step.on('click', function (e) {
                e.preventDefault();
                $('#ub-migrate-modal').modal({
                    backdrop: 'static',
                    //keyboard: false
                }).one('click', '#btn-modal-ok', function(e) {

                    //do ajax reset
                    $.ubReset($step);

                    //close modal
                    $('#ub-migrate-modal').modal('hide');

                }).on('shown.bs.modal', function (e) {
                    $('#ub-migrate-modal').find('.modal-body').fadeOut('fast', function() {
                        $(this).html('<p>Reset this step?</p>').fadeIn('fast');
                    });
                });
            });
        });

        /**
         * Reset data in all steps function
         */
        $.resetAllSteps = function () {
            $('#ub-migrate-modal').modal({
                backdrop: 'static',
                //keyboard: false
            }).one('click', '#btn-modal-ok', function(e) {

                //set flag reset for all steps
                resetAllSteps = true;

                //do ajax reset
                $.ubReset($('.migrate-steps a.btn-reset').last());

                //close modal
                $('#ub-migrate-modal').modal('hide');

            }).on('shown.bs.modal', function (e) {
                $('#ub-migrate-modal').find('.modal-body').fadeOut('fast', function() {
                    $(this).html('<p>Reset all steps?</p>').fadeIn('fast');
                });
            });
        }

        /**
         * Show system message function
         * @param msg
         * @param type
         */
        $.showMessages = function(msg, type) {
            var $msgContainer = $('#step-content');
            var msgHtml = '<div id="message" class="message animated fadeIn flash-'+type+'">';
            msgHtml += '<i class="material-icons">'+(type == 'error' ? 'error' : 'error_outline')+'</i>';
            msgHtml += '<button class="btn btn-close">Dismiss</button>';
            msgHtml += '<p>' + msg + '</p></div>';
            $msgContainer.find('#message').remove();
            $msgContainer.prepend(msgHtml);

            //scroll to top content
            setTimeout(function () {
                $("html, body").stop().animate({scrollTop: $('.migration-steps').offset().top}, 400);
            }, 100);
        }

        /**
         * Hide system message function
         */
        $.hideMessage = function () {
            if ($('#message').length) {
                $('#message').removeClass("fadeIn").addClass("animated fadeOut");
                //hide message container
                setTimeout(function () {
                    $('#message').remove();
                }, 1000);
            }
        }

        //bind close message event
        $(document).delegate('#message .btn-close', 'click', function(e) {
            e.preventDefault();
            $.hideMessage();
        });

        /**
         * show processing mask function
         * @param maskType
         */
        $.showMask = function (maskType) {
            if (!running) {
                $('body').addClass('ub-migrating')
                running = true;
            }
        }
        /**
         * Hide processing mask function
         */
        $.hideMask = function () {
            $('body').removeClass('ub-migrating')
            running = false;
        }

        /**
         * Update migrating log function
         */
        $.updateLog = function () {
            var url = $('#log-url').val();
            if (url.length) {
                $.ajax({
                    url: url,
                    beforeSend: function () {
                        $('#migrate-log-content').html('loading...');
                    },
                    success: function (rs) {
                        if ($('#migrate-log-content').length) {
                            $('#migrate-log-content').html(rs);
                        }
                    }
                });
            }
        }
        if ($('#migrate-log-action').length) {
            $('#migrate-log-action').on('click', function () {
                if (!$(this).hasClass('loaded')) {
                    $.updateLog();
                    $(this).addClass('loaded');
                }
            });
        }

        /******************* JS for forms setting ***********************/
        //Common process
        $('.btn-expand').on('click', function(e) {
            e.preventDefault();
            //show/hide associated content
            if ($(this).parent().siblings('.panel-body').length) {
                $(this).parent().siblings('.panel-body').slideToggle(200);
            } else if ($(this).parent().siblings('.tree-body').length) {
                $(this).parent().siblings('.tree-body').slideToggle(200);
            } else {
                $(this).parent().siblings('.list-group').slideToggle(200);
            }
            //update button status
            if ($(this).hasClass('btn-expand-more')) {
                $(this).removeClass('btn-expand-more').addClass('btn-expand-less');
            } else {
                $(this).removeClass('btn-expand-less').addClass('btn-expand-more');
            }
        });

        //disable buttons after submit form
        $('.frm-settings').on('submit', function() {
            $(this).find('.step-controls .btn').addClass('disabled');
        });

        //allay collapse panel in step #3
        if ($('.panel-group.product-customer-attributes').length || $('.panel-group.stores-list').length) {
            $('.panel-heading .btn-expand').trigger('click');
        }

        //disable all events for elements has read-only class
        /*$('.read-only, .read-only input').on('click', function(e) {
            e.preventDefault();
            return false;
        });*/

        //view more/less note event
        $('.btn-more-less').on('click', function () {
            if ($(this).siblings('.keep-original-id-objects').hasClass('view')) {
                $(this).html('Less');
            } else {
                $(this).html('More...');
            }
        });

        //auto fill M2 verson info
        if ($('#mg2-version').length) {
            $('#mg2-version').val(parent.jQuery('.magento-version').html().replace(/<strong>/g, '').replace(/<\/strong>/g, '').replace(/  /g, " "));
        }

        //applied tooltip function
        $(function () {
            $('[data-toggle="tooltip"]').tooltip()
        })

        /*** Step 2 ***/
        //check/un-check website & stores on it
        $('INPUT[name="website_ids[]"]').on('change', function() {
            if (!$(this).hasClass('read-only')) {
                $('.store-group-' + this.value).on('change', function() {
                    $('.store-' + this.value).prop("checked", this.checked);
                });
                $('.store-group-' + this.value).prop("checked", this.checked).trigger('change');
            }
        });

        $('INPUT[name="select_all"]').on('change', function() {
            if (!$(this).hasClass('read-only')) {
                if ($('INPUT[name="website_ids[]"]').length) {
                    $('INPUT[name="website_ids[]"]').prop('checked', this.checked).trigger('change');
                }
                if ($('INPUT[name="product_types[]"]').length) {
                    $('INPUT[name="product_types[]"]').prop('checked', this.checked);
                }
                if ($('INPUT[name="customer_group_ids[]"]').length) {
                    $('INPUT[name="customer_group_ids[]"]').prop('checked', this.checked);
                }
                if ($('INPUT[name="objects[]"]').length) {
                    $('INPUT[name="objects[]"]').prop('checked', this.checked).trigger('change');
                }
                //we always select the simple products
                if ($('#product_type_simple').length) {
                    $('#product_type_simple').prop('checked', true);
                }
            }
        });

        /* Step 7 */
        $('#sales_object_sales_aggregated_data').on('change', function() {
            $('INPUT[name="sales_aggregated_tables[]"]').prop('checked', this.checked);
        });
        $('INPUT[name="sales_aggregated_tables[]"]').on('change', function() {
            if (this.checked) {
                $('#sales_object_sales_aggregated_data').prop('checked', this.checked);
            }
        });
        /* Step 8 */
        $('INPUT[name="objects[]"]').on('change', function() {
            $(this).parent().parent().siblings('ul.list-group').find('INPUT[name="child_objects[]"]').prop('checked', this.checked);
        });
        $('INPUT[name="child_objects[]"]').on('change', function(){
            if (this.checked) {
                $(this).parent().parent().parent().parent().siblings('.list-group-item-heading').find('INPUT[name="objects[]"]').prop('checked', this.checked);
            }
        });
    });

})(jQuery);
