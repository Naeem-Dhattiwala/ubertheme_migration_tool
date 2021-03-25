<?php
    $settingData = $step->getSettingData();
    $selectedWebsiteIds = (isset($settingData['website_ids'])) ? $settingData['website_ids']  : [];
    $selectedStoreGroupIds = (isset($settingData['store_group_ids'])) ? $settingData['store_group_ids'] : [];
    $selectedStoreIds = (isset($settingData['store_ids'])) ? $settingData['store_ids'] : [];
    $totalWebsite = sizeof($websites);
    $totalStoreGroup = Mage1StoreGroup::model()->count("website_id > 0");
    $totalStores = Mage1Store::model()->count("website_id > 0");
    $isMigrated = UBMigrate::isMigrated($step->sorder);
?>

<?php $this->pageTitle = $step->title . ' - ' . Yii::app()->name; ?>

<h2 class="page-header"><?php echo Yii::t('frontend', 'Migration Settings');?> <i class="material-icons">keyboard_arrow_right</i> <?php echo Yii::t('frontend', $step->title); ?></h2>

<form class="frm-settings" role="form" method="post" action="<?php echo UBMigrate::getSettingUrl($step->sorder); ?>">

<div id="step-content">

    <?php $this->renderPartial('/base/_messages', array('step' => $step)); ?>

    <div class="message tip">
        <i class="material-icons">lightbulb_outline</i>
        <p><?php echo Yii::t('frontend', 'Select websites, store groups & store views you want to migrate. '); ?></p>
    </div>

    <?php
        $checkedAll = ((sizeof($selectedWebsiteIds) -1) == $totalWebsite
        AND (sizeof($selectedStoreGroupIds) -1) == $totalStoreGroup
        AND (sizeof($selectedStoreIds) -1) == $totalStores ) ? 'checked' : '';
    ?>
    <div class="checkbox<?php echo ($isMigrated) ? ' read-only' : ''; ?>">
        <label for="select-all" title="<?php echo Yii::t('frontend', 'Click here to select all websites and stores.')?>"><?php echo Yii::t('frontend', 'Select All');?></label>
        <input type="checkbox" id="select-all" name="select_all" <?php echo ($isMigrated) ? 'class="read-only" readonly="readonly"' : ''; ?> <?php echo $checkedAll; ?> value="1" title="<?php echo Yii::t('frontend', 'Click here to select all websites and Stores.')?>" />
        <ul class="help-block">
            <li><?php echo Yii::t('frontend', "Total Websites: <strong>%s</strong>", array('%s' => sizeof($websites))); ?></li>
            <li><?php echo Yii::t('frontend', "Total Stores: <strong>%s</strong>", array('%s' => $totalStoreGroup)); ?></li>
            <li><?php echo Yii::t('frontend', "Total Store Views: <strong>%s</strong>", array('%s' => $totalStores)); ?></li>
        </ul>
    </div>

    <div class="panel-group stores-list" role="tablist" aria-multiselectable="true">
        <div class="row">
            <?php foreach ($websites as $key => $website): ?>
            <?php
            //check has selected to migrate
            $checked = in_array($website->website_id, $selectedWebsiteIds);
            //check has migrated
            $m2Id = UBMigrate::getM2EntityId(2, $website->tableName(), $website->website_id);
            //check for disable
            $disable = ($isMigrated && $m2Id) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
            //get list store groups of current website
            $storeGroups = Mage1StoreGroup::model()->findAll("website_id = {$website->website_id}");
            ?>

            <div class="col-md-6">
                <div class="panel panel-default website<?php echo (sizeof($storeGroups) > 0) ? ' has-child' : ''; ?>">
                    <div class="panel-heading" role="tab">
                        <label class="checkbox-inline<?php echo ($disable) ? ' read-only' : ''; ?>">
                            <input type="checkbox" id="website-<?php echo $website->website_id; ?>" <?php echo ($checked) ? "{$disable} checked" : ''; ?> name="website_ids[]" value="<?php echo $website->website_id?>" />
                            <span class="panel-title"><?php echo $website->name; ?></span>
                            <?php if ($website->is_default): ?>
                                <span>(<?php echo Yii::t('frontend', 'default'); ?>)</span>
                            <?php endif; ?>
                        </label>
                        <?php if ($m2Id): ?>
                            <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                        <?php endif; ?>
                        <button class="btn-expand btn-expand-less">
                            <i class="material-icons expand-more">expand_more</i>
                            <i class="material-icons expand-less">expand_less</i>
                        </button>
                    </div>
                    <?php if ($storeGroups): ?>
                    <ul class="list-group ver-nav">
                        <?php foreach ($storeGroups as $storeGroup): ?>
                            <?php
                            //check has selected to migrate
                            $checked = in_array($storeGroup->group_id, $selectedStoreGroupIds);
                            //check has migrated
                            $m2Id = UBMigrate::getM2EntityId($step->sorder, $storeGroup->tableName(), $storeGroup->group_id);
                            //check for disable
                            $disable = ($isMigrated && $m2Id) ? 'readonly="readonly" onclick="event.preventDefault();return false;"' : '';
                            //get list stores of current store group
                            $stores = Mage1Store::model()->findAll("website_id = {$website->website_id} AND group_id = {$storeGroup->group_id}");
                            ?>
                            <li class="list-group-item store<?php echo (sizeof($stores) > 0) ? ' has-child' : ''; ?>">
                                <div class="list-group-item-heading">
                                    <label class="checkbox-inline<?php echo ($disable) ? ' read-only' : ''; ?>">
                                        <input type="checkbox" id="store-group-<?php echo $storeGroup->group_id; ?>" <?php echo ($checked) ? "{$disable} checked" : ''; ?> name="store_group_ids[]" class="store-group-<?php echo $website->website_id; ?><?php echo ($disable) ? ' read-only' : ''; ?>" value="<?php echo $storeGroup->group_id?>" />
                                        <span><?php echo $storeGroup->name; ?></span>
                                        <?php if ($storeGroup->group_id == $website->default_group_id): ?>
                                            <span>(<?php echo Yii::t('frontend', 'default'); ?>)</span>
                                        <?php endif; ?>
                                    </label>
                                    <?php if ($m2Id): ?>
                                        <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                    <?php endif; ?>
                                    <button class="btn-expand btn-expand-more">
                                        <i class="material-icons expand-more">expand_more</i>
                                        <i class="material-icons expand-less">expand_less</i>
                                    </button>
                                </div>
                                <?php if ($stores): ?>
                                    <ul class="list-group" style="display: none;">
                                        <?php foreach ($stores as $store): ?>
                                            <?php
                                            $checked = in_array($store->store_id, $selectedStoreIds);
                                            //check has migrated
                                            $m2Id = UBMigrate::getM2EntityId(2, $store->tableName(), $store->store_id);
                                            //check for disable
                                            $disable = ($isMigrated && $m2Id) ? 'readonly="readonly" onclick="event.preventDefault();return false;"' : '';
                                            ?>
                                            <li class="list-group-item store-view">
                                                <label class="checkbox-inline<?php echo ($disable) ? ' read-only' : ''; ?>">
                                                    <input type="checkbox" id="store-<?php echo $store->store_id; ?>" <?php echo ($checked) ? "{$disable} checked" : ''; ?> name="store_ids[]" class="store-<?php echo $storeGroup->group_id; ?><?php echo ($disable) ? ' read-only' : ''; ?>" value="<?php echo $store->store_id?>" />
                                                    <span><?php echo $store->name; ?></span>
                                                    <?php if ($store->store_id == $storeGroup->default_store_id): ?>
                                                        <span>(<?php echo Yii::t('frontend', 'default'); ?>)</span>
                                                    <?php endif; ?>
                                                </label>
                                                <?php if ($m2Id): ?>
                                                    <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                                <?php endif; ?>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                    <?php endif; ?>
                </div>
            </div>

            <?php if (($key+1) % 2 == 0):?>
                    </div><div class="row">
            <?php endif; ?>

            <?php endforeach; ?>
        </div>
    </div>
    <?php
        $isMergeDefaultWebsite = isset($settingData['is_merge_default_website']) ? $settingData['is_merge_default_website'] : 0;
        $disable = ($isMigrated) ? 'readonly="readonly" onclick="event.preventDefault();"' : '';
    ?>
    <div class="checkbox<?php echo ($disable) ? ' read-only' : ''; ?>">
        <label for="is_merge_default_website"><?php echo Yii::t('frontend', 'Merge default websites'); ?></label>
        <input type="checkbox" id="is_merge_default_website" name="is_merge_default_website" <?php echo $disable; ?> <?php echo ($isMergeDefaultWebsite) ? "checked" : ''; ?> value="1"/>
        <p class="help-block"><?php echo Yii::t('frontend', 'Mark this checkbox, if you want to merge your default Magento 1 website (including default store of default website and default store view of default Store) into existing default Magento 2 website'); ?></p>
    </div>

    <?php $this->renderPartial('/base/_buttons', array('step' => $step)); ?>
</div>

</form>