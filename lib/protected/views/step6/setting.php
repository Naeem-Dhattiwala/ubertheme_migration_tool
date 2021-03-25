<?php
    //get selected website ids
    $selectedWebsiteIds = UBMigrate::getSetting(2, 'website_ids');
    $strSelectedWebsiteIds = implode(',', $selectedWebsiteIds);
    $selectedStoreIds = UBMigrate::getSetting(2, 'store_ids');
    $strSelectedStoreIds = implode(',', $selectedStoreIds);
    $selectedCustomerGroupIds = (isset($settingData['customer_group_ids'])) ? $settingData['customer_group_ids'] : [];
    $migratedCustomerGroupIds = (isset($settingData['migrated_customer_group_ids'])) ? $settingData['migrated_customer_group_ids'] : [];

    $isMigrated = UBMigrate::isMigrated($step->sorder);
?>
<?php $this->pageTitle = $step->title . ' - ' . Yii::app()->name; ?>

<h2 class="page-header"><?php echo Yii::t('frontend', 'Migration Settings');?> <i class="material-icons">keyboard_arrow_right</i> <?php echo Yii::t('frontend', $step->title); ?> </h2>

<form class="frm-settings" role="form" method="post" action="<?php echo UBMigrate::getSettingUrl($step->sorder); ?>">
    <div id="step-content">

        <?php $this->renderPartial('/base/_messages', array('step' => $step)); ?>

        <div class="message tip">
            <i class="material-icons">lightbulb_outline</i>
            <p>
                <?php echo Yii::t('frontend', ' Select customer groups you want to migrate. All related data for each customer group will be automatically migrated.'); ?>
            </p>
        </div>

        <div class="panel-group customer-groups" role="tablist" aria-multiselectable="true">
            <div class="panel panel-default has-child">
                <div class="panel-heading" role="tab">
                    <span class="panel-title" title="<?php echo Yii::t('frontend', 'Customer Groups')?>">
                        <?php echo Yii::t('frontend', 'Customer Groups'); ?> (<span><?php echo sizeof($customerGroups); ?></span>)
                    </span>
<!--                     <button class="btn-expand btn-expand-less">
                        <i class="material-icons expand-more">expand_more</i>
                        <i class="material-icons expand-less">expand_less</i>
                    </button> -->
                </div>
                <div class="panel-body">
                    <div class="checkbox<?php echo ($isMigrated) ? ' read-only' : ''; ?>">
                        <label for="select-all" title="<?php echo Yii::t('frontend', 'Click here to select all.')?>"><?php echo Yii::t('frontend', 'Select All');?></label>
                        <input type="checkbox" id="select-all" name="select_all"
                            <?php echo ($isMigrated) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : ''; ?>
                               value="1" <?php echo (sizeof($selectedCustomerGroupIds) == sizeof($customerGroups)) ? "checked" : ''; ?>
                               title="<?php echo Yii::t('frontend', 'Click here to select all.')?>" />
                        <ul class="help-block">
                            <li>
                                <?php echo Yii::t('frontend', 'Total: %s customers', array('%s' => UBMigrate::getTotalCustomers($strSelectedWebsiteIds, $strSelectedStoreIds))); ?>
                            </li>
                        </ul>
                    </div>

                    <?php if ($customerGroups): ?>
                        <ul class="list-group list-group-inline">
                            <?php foreach ($customerGroups as $customerGroup): ?>
                                <?php
                                $checked = (in_array($customerGroup->customer_group_id, $selectedCustomerGroupIds)) ? 'checked' : '';
                                $disabled = ($checked && in_array($customerGroup->customer_group_id, $migratedCustomerGroupIds)) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                                ?>
                                <li class="list-group-item<?php echo ($disabled) ? ' read-only' : ''; ?>">
                                    <div class="list-group-item-heading">
                                        <?php if (in_array($customerGroup->customer_group_id, $migratedCustomerGroupIds)): ?>
                                            <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                        <?php endif; ?>
                                        <label for="customer_group_<?php echo $customerGroup->customer_group_id; ?>" class="checkbox-inline<?php echo ($disabled) ? ' read-only' : ''; ?>">
                                            <input id="customer_group_<?php echo $customerGroup->customer_group_id; ?>"
                                                   name="customer_group_ids[]"
                                                   type="checkbox" <?php echo $checked; ?> <?php echo $disabled; ?> value="<?php echo $customerGroup->customer_group_id; ?>" />
                                            <?php echo $customerGroup->customer_group_code . " (". UBMigrate::getTotalCustomersByGroup($customerGroup->customer_group_id, $strSelectedWebsiteIds, $strSelectedStoreIds) .")"; ?>
                                        </label>
                                    </div>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                    <?php
                    $keepOriginalId = isset($settingData['keep_original_id']) ? $settingData['keep_original_id'] : 0;
                    $disabled = ($isMigrated) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
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
                                    <li>Customers</li>
                                    <li>
                                        Customer EAV Data Tables:
                                        <ul>
                                            <li>customer_entity_datetime</li>
                                            <li>customer_entity_decimal</li>
                                            <li>customer_entity_int</li>
                                            <li>customer_entity_text</li>
                                            <li>customer_entity_varchar</li>
                                        </ul>
                                    </li>
                                    <li>Customer Addresses</li>
                                    <li>
                                        Customer Address EAV Data Tables:
                                        <ul>
                                            <li>customer_address_entity_datetime</li>
                                            <li>customer_address_entity_decimal</li>
                                            <li>customer_address_entity_int</li>
                                            <li>customer_address_entity_text</li>
                                            <li>customer_address_entity_varchar</li>
                                        </ul>
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>

        <?php $this->renderPartial('/base/_buttons', array('step' => $step)); ?>
    </div>
</form>
