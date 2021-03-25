<?php $this->pageTitle = 'Migrate Data - ' . Yii::app()->name; ?>

<h2 class="page-header"><?php echo Yii::t('frontend', 'Start Migrating Your Data');?></h2>

<div id="step-content">

    <?php $this->renderPartial('/base/_messages', array()); ?>

<table class="table table-hover migrate-steps">
    <thead>
        <tr>
            <th class="migrate-steps-task-th"><?php echo Yii::t('frontend', 'Task');?></th>
            <th class="migrate-steps-status-th"><?php echo Yii::t('frontend', 'Status');?></th>
            <th class="migrate-steps-action-th"><?php echo Yii::t('frontend', 'Action');?></th>
        </tr>
    </thead>
    <tbody>
        <?php foreach ($steps as $key => $step): ?>
        <tr class="step <?php echo $step->getStepStatusClassCSS(); ?>">
            <?php
                $stepTitle = ($step->sorder > 1) ? Yii::t('frontend', "Migrate %s", array('%s' => $step->title)) : $step->title ." ". Yii::t('frontend', 'Settings');
                $stepTitle = (++$key) . " - " . $stepTitle;
            ?>
            <td><?php echo  $stepTitle; ?></td>
            <td id="step-status-<?php echo $step->sorder; ?>" style="text-align: center;"><?php echo $step->getStepStatusText();?></td>
            <td style="text-align: right;">
                <?php if ($step->status != UBMigrate::STATUS_PENDING AND $step->sorder != 1): ?>
                    <?php
                        $actionClass = ($step->status == UBMigrate::STATUS_SKIPPING) ? "btn-run disabled" : (($step->status == UBMigrate::STATUS_FINISHED) ? 'btn-run delta' : 'btn-run');
                    ?>

                    <a id="run-step-<?php echo $step->sorder; ?>" class="btn btn-primary <?php echo $actionClass; ?>" data-step-index="<?php echo $step->sorder; ?>" title="<?php echo Yii::t('frontend', 'Click to run migrate data in this step'); ?>" href="<?php echo UBMigrate::getRunUrl($step->sorder); ?>">
                        <i class="material-icons icon-run">swap_horiz</i>
                        <i class="material-icons icon-delta">compare_arrows</i>
                        <span class="btn-label">
                            <?php echo ($step->status == UBMigrate::STATUS_FINISHED) ? Yii::t('frontend', 'Delta') : Yii::t('frontend', 'Run'); ?>
                        </span>
                    </a>

                    <?php $reset = UBMigrate::canReset($step->sorder); ?>
                    <a id="reset-step-<?php echo $step->sorder; ?>" class="btn btn-danger btn-reset<?php echo (!$reset['allowed']) ? ' disabled' : ''; ?>" title="<?php echo ($reset['allowed']) ? Yii::t('frontend', 'Click to reset this step') : Yii::t('frontend', 'You can\'t reset this step'); ?>" data-step-index="<?php echo $step->sorder; ?>" href="<?php echo UBMigrate::getResetUrl($step->sorder); ?>" ><i class="material-icons">refresh</i> <?php echo Yii::t('frontend', 'Reset'); ?></a>

                <?php endif; ?>
                <a id="setting-step-<?php echo $step->sorder; ?>" title="<?php echo Yii::t('frontend', 'Click to re-setting this step'); ?>" href="<?php echo UBMigrate::getSettingUrl($step->sorder); ?>" class="btn btn-default btn-setting"><i class="material-icons">settings</i> <?php echo Yii::t('frontend', 'Setting'); ?></a>
            </td>
        </tr>
        <?php endforeach; ?>
    </tbody>
    <tfoot>
        <tr>
            <td colspan="3">
                <!-- allow only run all steps when all step was setting/migrate processed. -->
                <?php $percentFinished = UBMigrate::getPercentByStatus(UBMigrate::STATUS_FINISHED, [1]); ?>
                <?php $percentPending = UBMigrate::getPercentByStatus([UBMigrate::STATUS_PENDING]); ?>

                <!-- process bar -->
                <?php if ( $percentPending == 0 ): ?>
                    <div id="all-steps-process" class="progress" style="display: <?php echo ($percentFinished) ? 'block' : 'none'?>;">
                        <div class="progress-bar progress-bar-success progress-bar-striped" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="width:0%">
                            <span class="value">0</span>% <?php echo Yii::t('frontend', 'Completed'); ?>
                        </div>
                        <script type="text/javascript">
                            var percentFinished = <?php echo $percentFinished; ?>;
                            $(document).ready(function(){
                                //update process bar info
                                $('#all-steps-process').find('.progress-bar').css({"width" : percentFinished + '%'}).attr('aria-valuenow', percentFinished).html('<span class="value">'+percentFinished + '</span>% Completed');
                            });
                        </script>
                    </div>
                <?php endif;?>
                <!--// process bar -->
                <div class="migrate-steps-actions">
                    <!-- reset all steps button -->
                    <?php $resetClass = ($percentPending == 0) ? "btn btn-danger btn-lg" : 'btn btn-danger btn-lg disabled'; ?>
                    <a href="javascript:void(0);" onclick="$.resetAllSteps();" title="<?php echo Yii::t('frontend', 'Click to reset all steps.'); ?>" class="<?php echo $resetClass; ?>">
                        <i class="material-icons">refresh</i> <?php echo Yii::t('frontend', 'Reset All Steps'); ?>
                    </a>
                    <!--// reset all steps button -->

                    <!-- run all steps button-->
                    <?php $label = ($percentFinished == 100) ? Yii::t('frontend', 'Delta') : Yii::t('frontend', 'Run'); ?>
                    <?php $runClass = ($percentPending == 0) ? "btn btn-primary btn-lg run-all" : "btn btn-primary btn-lg run-all disabled"; ?>
                    <a id="run-all-steps" onclick="$.runAllSteps();" title="<?php echo Yii::t('frontend', 'Click to %s all steps migrate data', array('%s'=>$label)); ?>" href="javascript:void(0);" class="<?php echo $runClass; ?>"><i class="material-icons icon-run">swap_horiz</i> <span class="btn-label"><?php echo Yii::t('frontend', '%s All Steps', array('%s'=>$label)); ?></span></a>
                    <!--// run all steps button-->
                </div>

            </td>
        </tr>
    </tfoot>
</table>

<!-- Migrate data by CLI commands guide lines -->
<fieldset class="migrate-log">
    <legend class="legend">
        <a href="javascript:void(0);" data-target="#migrate-cli-commands" data-toggle="collapse">
            <span class="text-uppercase">(Optional)</span>
            <?php echo Yii::t('frontend', 'Using Command Line Interface (CLI) Options')?>
        </a>
    </legend>
    <div id="migrate-cli-commands" class="collapse in">
        <div id="cli-commands">
            <div class="message tip">
                <i class="material-icons">info_outline</i>
                <h5>Note:</h5>
                <p>
                    - Make sure you complete all Pre-migration Setting (8) steps first. Then open your terminal, navigate to your Magento 2 folder and run one of following commands. Once done, please follow the step 6 guideline - REQUIRED STEPS TO COMPLETE MIGRATION PROCESS in our Readme.txt file.
                </p>
                <p>
                    - Use the UI to perform migration tasks. The command line mode is an effective alternative if you process a large volume of data. For more information, see the Readme.html included in your download package.
                </p>
            </div>
            <ul>
                <li>
                    <h5>Migrate Data All Steps:</h5>
                    <code>php bin/ubdatamigration run</code>
                </li>
                <li>
                    <h5>Migrate Single Step:</h5>
                    <span>Eg: The command to proceed migration in step #2 - Migrate Websites, Stores:</span>
                    <code>php bin/ubdatamigration run --step=2</code>
                </li>
                <li>
                    <h5>Migrate Data Single Step with a specific number of records per each batch runtime:</h5>
                    <span>Eg. The command to proceed migration in step #5 with 200 records:</span>
                    <code>php bin/ubdatamigration run --step=2 --limit=200</code>
                </li>
                <li>
                    <h5>Reset Migration All Steps:</h5>
                    <code>php bin/ubdatamigration reset</code>
                </li>
                <li>
                    <h5>Reset Migration Single Step:</h5>
                    <span>Eg. The command to reset migration in only step #2 - Migrate Websites, Stores:</span>
                    <code>php bin/ubdatamigration reset --step=2</code>
                </li>
            </ul>
        </div>
    </div>
</fieldset>
<!--// Migrate data by CLI commands guide lines -->

<!--Migrate log-->
<fieldset class="migrate-log">
    <legend class="legend">
        <a id="migrate-log-action" href="javascript:void(0);" data-target="#migrate-log" data-toggle="collapse">
            <?php echo Yii::t('frontend', 'Migration Log')?>
        </a>
    </legend>
    <input type="hidden" id="log-url" name="log-url" value="<?php echo UBMigrate::getLogUrl(); ?>"/>
    <div id="migrate-log" class="collapse">
        <blockquote>
            <p class="tip">Log file's location: <code>pub/ub-tool/protected/runtime/</code></p>
        </blockquote>
        <div id="migrate-log-content" class="log-content"></div>
    </div>
</fieldset>
<!--//Migrate log-->

<!-- Report list -->
<fieldset class="migrate-report" style="display: <?php echo (isset($percentFinished) AND $percentFinished) ? 'block' : 'none'?>;">
    <legend class="legend">
        <a id="migrate-report-action" href="javascript:void(0);" data-target="#migrate-report" data-toggle="collapse"><?php echo Yii::t('frontend', 'Migration Quick Report')?></a>
    </legend>
    <div id="migrate-report" class="collapse">
        <table id="report-content" class="table table-hover report-content">
            <thead>
            <tr>
                <th><?php echo Yii::t('frontend', '#');?></th>
                <th><?php echo Yii::t('frontend', 'Entity Name');?></th>
                <!--<th><?php /*echo Yii::t('frontend', 'Total in Magento 1 (items)');*/?></th>-->
                <th><?php echo Yii::t('frontend', 'Items Migrated');?></th>
            </tr>
            </thead>
            <tbody>
            <?php
                $reportItems = [
                    'core_website' => ['label' => Yii::t('frontend', 'Websites'), 'map_table' => 'ub_migrate_map_step_2'],
                    'core_store_group' => ['label' => Yii::t('frontend', 'Stores'), 'map_table' => 'ub_migrate_map_step_2'],
                    'core_store' => ['label' => Yii::t('frontend', 'Store Views'), 'map_table' => 'ub_migrate_map_step_2'],
                    'eav_attribute_set' => ['label' => Yii::t('frontend', 'Product Attribute Sets'), 'map_table' => 'ub_migrate_map_step_3'],
                    'eav_attribute_group' => ['label' => Yii::t('frontend', 'Product Attribute Groups'), 'map_table' => 'ub_migrate_map_step_3'],
                    'eav_attribute' => ['label' => Yii::t('frontend', 'Product Attributes'), 'map_table' => 'ub_migrate_map_step_3_attribute'],
                    'catalog_category_entity' => ['label' => Yii::t('frontend', 'Catalog Categories'), 'map_table' => 'ub_migrate_map_step_4'],
                    'catalog_product_entity' => ['label' => Yii::t('frontend', 'Catalog Products'), 'map_table' => 'ub_migrate_map_step_5'],
                    'customer_group' => ['label' => Yii::t('frontend', 'Customer Groups'), 'map_table' => 'ub_migrate_map_step_6'],
                    'customer_entity' => ['label' => Yii::t('frontend', 'Customers'), 'map_table' => 'ub_migrate_map_step_6'],
                    'salesrule' => ['label' => Yii::t('frontend', 'Cart Price Rules'), 'map_table' => 'ub_migrate_map_step_7'],
                    'sales_order_status' => ['label' => Yii::t('frontend', 'Sales Order Statuses'), 'map_table' => 'ub_migrate_map_step_7'],
                    'sales_flat_order' => ['label' => Yii::t('frontend', 'Sales Orders'), 'map_table' => 'ub_migrate_map_step_7_order'],
                    'catalogrule' => ['label' => Yii::t('frontend', 'Catalog Price Rule'), 'map_table' => 'ub_migrate_map_step_8'],
                    'review' => ['label' => Yii::t('frontend', 'Reviews'), 'map_table' => 'ub_migrate_map_step_8_review'],
                    'newsletter_subscriber' => ['label' => Yii::t('frontend', 'Newsletter Subscriber'), 'map_table' => 'ub_migrate_map_step_8_subscriber'],
                ];
                UBMigrate::makeMigrateReport($reportItems);
            ?>
            <?php $i=1; foreach ($reportItems as $entityName => $reportItem):?>
                <tr>
                    <td><?php echo ($i)?></td>
                    <td><?php echo $reportItem['label']; ?></td>
                    <!--<td><?php /*echo $reportItem['m1_total'];*/?></td>-->
                    <td><?php echo $reportItem['migrated_total'];?></td>
                </tr>
            <?php $i++; endforeach;?>
            </tbody>
        </table>
    </div>
</fieldset>
<!--// Report list -->

</div>

<?php $this->renderPartial('/base/_modal', array()); ?>

