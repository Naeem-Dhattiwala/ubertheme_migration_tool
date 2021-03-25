<?php
    $selectedSalesObjects = (isset($settingData['sales_objects'])) ? $settingData['sales_objects'] : [];
    $migratedSalesObjects = (isset($settingData['migrated_sales_objects'])) ? $settingData['migrated_sales_objects'] : [];

    $selectedSalesAggregatedTables = (isset($settingData['sales_aggregated_tables'])) ? $settingData['sales_aggregated_tables'] : [];
    $migratedSalesAggregatedTables = (isset($settingData['migrated_sales_aggregated_tables'])) ? $settingData['migrated_sales_aggregated_tables'] : [];
?>

<?php $this->pageTitle = $step->title . ' - ' . Yii::app()->name; ?>

<h2 class="page-header"><?php echo Yii::t('frontend', 'Migration Settings'); ?> <i class="material-icons">keyboard_arrow_right</i> <?php echo Yii::t('frontend', $step->title); ?> </h2>

<form class="frm-settings" role="form" method="post" action="<?php echo UBMigrate::getSettingUrl($step->sorder); ?>">
    <div id="step-content" class="step7">

        <?php $this->renderPartial('/base/_messages', array('step' => $step)); ?>

        <div class="message tip">
            <i class="material-icons">lightbulb_outline</i>
            <p>
                <?php echo Yii::t('frontend', 'Select the Sales data objects you want to migrate. All related data for each sales object will be automatically migrated.'); ?>
            </p>
        </div>

        <div class="panel-group sales-data-objects" role="tablist" aria-multiselectable="true">
            <div class="panel panel-default has-child">
                <div class="panel-heading" role="tab">
                    <span class="panel-title" title="<?php echo Yii::t('frontend', 'Sales Data')?>">
                        <?php echo Yii::t('frontend', 'Sales Data'); ?>
                    </span>
<!--                     <button class="btn-expand btn-expand-less">
                        <i class="material-icons expand-more">expand_more</i>
                        <i class="material-icons expand-less">expand_less</i>
                    </button> -->
                </div>
                <div class="panel-body">
                    <?php if ($salesObjects): ?>
                        <ul class="list-group ver-nav">
                            <?php foreach ($salesObjects as $object => $info): ?>
                                <?php
                                $checked = (($object != 'sales_aggregated_data' AND !sizeof($selectedSalesObjects)) OR in_array($object, $selectedSalesObjects)) ? 'checked' : '';
                                $disabled = (($object != 'sales_aggregated_data') || ($checked && in_array($object, $migratedSalesObjects))) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                                $hasChild = (isset($info['related']) AND $info['related']) ? 1 : 0;
                                ?>
                                <li class="list-group-item<?php echo ($hasChild) ? ' has-child' : ''; ?><?php echo ($disabled) ? ' read-only' : ''; ?>">
                                    <div class="list-group-item-heading">
                                        <?php if (in_array($object, $migratedSalesObjects)): ?>
                                            <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                        <?php endif; ?>

                                        <label for="sales_object_<?php echo $object; ?>" class="checkbox-inline">
                                            <input id="sales_object_<?php echo $object; ?>" name="sales_objects[]"
                                                   type="checkbox" <?php echo($checked) ?> <?php echo $disabled; ?>
                                                   value="<?php echo $object; ?>"/>
                                            <?php $suffix = ($object != 'sales_aggregated_data') ? " (" . UBMigrate::getTotalSalesChildObject($object, $strSelectedStoreIds, null) . ")" : ''; ?>
                                            <span> <?php echo $info['label'] . $suffix; ?> </span>
                                        </label>

                                        <?php if ($hasChild) :?>
                                            <button class="btn-expand btn-expand-more">
                                                <i class="material-icons expand-more">expand_more</i>
                                                <i class="material-icons expand-less">expand_less</i>
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                    <?php if ($hasChild) : ?>
                                        <ul class="list-group" style="display: none;">
                                            <?php foreach ($info['related'] as $relatedObject => $label) : ?>
                                                <?php
                                                $checked = ($object == 'order' OR in_array($relatedObject, $selectedSalesAggregatedTables)) ? 'checked' : '';
                                                $disabled = (($object == 'order') || ($checked && in_array($relatedObject, $migratedSalesAggregatedTables))) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                                                $keyName = ($object == 'order') ? 'related_order_objects' : 'sales_aggregated_tables';
                                                ?>
                                                <li class="list-group-item<?php echo ($disabled) ? ' read-only' : ''; ?>">
                                                    <div class="list-group-item-heading">
                                                        <label class="checkbox-inline<?php echo ($disabled) ? ' read-only' : ''; ?>" for="<?php echo $keyName ."_". $relatedObject; ?>">
                                                            <input id="<?php echo $keyName ."_". $relatedObject; ?>" name="<?php echo $keyName; ?>[]"
                                                                   type="checkbox" <?php echo($checked) ?> <?php echo $disabled; ?> value="<?php echo $relatedObject; ?>"/>
                                                            <span> <?php echo " {$label}" . " (" . UBMigrate::getTotalSalesChildObject($relatedObject, $strSelectedStoreIds, null) . ")"; ?> </span>
                                                        </label>
                                                        <?php if (in_array($relatedObject, $migratedSalesAggregatedTables)): ?>
                                                            <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                                        <?php endif; ?>
                                                    </div>
                                                </li>
                                            <?php endforeach; ?>
                                        </ul>
                                    <?php endif; ?>
                                </li>
                            <?php endforeach; ?>
                        </ul>

                        <?php
                        $keepOriginalId = isset($settingData['keep_original_id']) ? $settingData['keep_original_id'] : 0;
                        $disabled = (UBMigrate::isMigrated($step->sorder)) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                        ?>
                        <div class="checkbox<?php echo ($disabled) ? ' read-only' : ''; ?>">
                            <label for="keep_original_id"><?php echo Yii::t('frontend', 'Keep original IDs'); ?></label>
                            <input type="checkbox" id="keep_original_id" name="keep_original_id"
                                <?php echo ($keepOriginalId) ? "checked" : ""; ?> <?php echo $disabled; ?> value="1" />
                            <div class="help-block keep-id-note">
                                <?php echo Yii::t('frontend', 'Mark this checkbox if you want to keep original IDs of the following objects after migrating to Magento 2:'); ?>
                                <a href="javascript:void(0);" class="btn-more-less" onclick="$('.keep-original-id-objects').slideToggle('slow').toggleClass('view');"><?php echo Yii::t('frontend', 'More...')?></a>
                                <div class="keep-original-id-objects" style="display: none;">
                                    IMPORTANT: It's mandatory that your Magento 2 must be a fresh installation when selecting this option. Once you mark this checkbox and run migration, you can no longer update or cancel this setting, unless you Reset this step.
                                    <ul>
                                        <li>Sales Rules</li>
                                        <li>Sales Rule Coupons</li>
                                        <li>Sales Orders</li>
                                        <li>Sales Order Items</li>
                                        <li>Sales Order Addresses</li>
                                        <li>Sales Quotes</li>
                                        <li>Sales Quote Items</li>
                                        <li>Sales Quote Item Options</li>
                                        <li>Sales Quote Addresses</li>
                                        <li>Sales Quote Address Items</li>
                                        <li>Sales Quote Shipping Rates</li>
                                        <li>Sales Payments</li>
                                        <li>Sales Payment Transactions</li>
                                        <li>Sales Invoices</li>
                                        <li>Sales Shipment</li>
                                        <li>Sales Shipment Track</li>
                                        <li>Sales Shipment Item</li>
                                        <li>Sales Shipment Comment</li>
                                        <li>Sales Credit Memos</li>
                                        <li>Sales Order Taxes</li>
                                        <li>Sales Order Tax Items</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <?php $this->renderPartial('/base/_buttons', array('step' => $step)); ?>
    </div>
</form>
