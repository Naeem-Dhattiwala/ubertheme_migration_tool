<?php
    //get selected store ids
    $selectedStoreIds = UBMigrate::getSetting(2, 'store_ids');
    $strSelectedStoreIds = implode(',', $selectedStoreIds);
    $migratedProductTypes = (isset($settingData['migrated_product_types'])) ? array_unique($settingData['migrated_product_types'])  : [];
    $selectedProductTypes = (isset($settingData['product_types'])) ? array_unique($settingData['product_types'])  : [];
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
                <?php echo Yii::t('frontend', 'Select the product types you want to migrate.'); ?>
            </p>
        </div>

        <div class="panel-group product-types" role="tablist" aria-multiselectable="true">
            <div class="panel panel-default has-child">
                <div class="panel-heading" role="tab">
                    <span class="panel-title" title="<?php echo Yii::t('frontend', 'Product Types')?>">
                        <?php echo Yii::t('frontend', 'Product Types'); ?> (<span><?php echo sizeof($productTypes); ?></span>)
                    </span>
<!--                     <button class="btn-expand btn-expand-less">
                        <i class="material-icons expand-more">expand_more</i>
                        <i class="material-icons expand-less">expand_less</i>
                    </button> -->
                </div>
                <div class="panel-body">

                    <div class="checkbox">
                        <label for="select-all" title="<?php echo Yii::t('frontend', 'Click here to select all product types')?>"><?php echo Yii::t('frontend', 'Select All');?></label>
                        <input type="checkbox" id="select-all" name="select_all"
                            <?php echo ($isMigrated) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : ''; ?>
                            <?php echo (sizeof($selectedProductTypes) == 6) ? "checked" : ''; ?>
                               value="1" title="<?php echo Yii::t('frontend', 'Click here to select all product types'); ?>" />
                        <ul class="help-block">
                            <li>
                                <?php echo Yii::t('frontend', 'Total: %s products', array('%s' => UBMigrate::getTotalProducts($strSelectedStoreIds, $productTypes))); ?>
                            </li>
                        </ul>
                    </div>

                    <?php if ($productTypes): ?>
                        <ul class="list-group list-group-inline">
                            <?php foreach ($productTypes as $productType): ?>
                                <?php
                                    //We always migrate the simple products
                                    $checked = ($productType == 'simple' || in_array($productType, $selectedProductTypes)) ? 'checked' : '';
                                    $disabled = (($productType == 'simple') || ($checked && in_array($productType, $migratedProductTypes))) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                                ?>
                                <li class="list-group-item<?php echo ($disabled) ? ' read-only' : ''?>">
                                    <div class="list-group-item-heading">
                                        <?php if ($productType == 'simple'): ?>
                                            <!-- we always migrated the simple products-->
                                            <input type="hidden" name="product_types[]" value="simple" />
                                        <?php endif; ?>
                                        <label for="product_type_<?php echo $productType; ?>" class="checkbox-inline<?php echo ($disabled) ? ' read-only' : ''?>">
                                            <input id="product_type_<?php echo $productType; ?>" name="product_types[]" type="checkbox"
                                                <?php echo ($checked) ?> <?php echo $disabled; ?> value="<?php echo $productType; ?>" />
                                            <?php echo Yii::t('frontend', '%s Products', array('%s'=> ucfirst($productType))) . " (". UBMigrate::getTotalProductsByType($productType, $strSelectedStoreIds) .")"; ?>
                                        </label>
                                        <?php if (in_array($productType, $migratedProductTypes)): ?>
                                            <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                        <?php endif; ?>
                                    </div>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>

                    <?php
                    $keepOriginalId = isset($settingData['keep_original_id']) ? $settingData['keep_original_id'] : 0;
                    $disabled = ($isMigrated) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                    ?>
                    <div class="checkbox<?php echo ($disabled) ? ' read-only' : ''?>">
                        <label for="keep_original_id"><?php echo Yii::t('frontend', 'Keep original IDs'); ?></label>
                        <input type="checkbox" id="keep_original_id" name="keep_original_id"
                            <?php echo ($keepOriginalId) ? "checked" : ""; ?> <?php echo $disabled; ?> value="1" />
                        <div class="help-block keep-id-note">
                            <?php echo Yii::t('frontend', 'Mark this checkbox if you want to keep original IDs of the following objects after migrating to Magento 2:'); ?>
                            <a href="javascript:void(0);" class="btn-more-less" onclick="$('.keep-original-id-objects').slideToggle('slow').toggleClass('view');"><?php echo Yii::t('frontend', 'More...')?></a>
                            <div class="keep-original-id-objects" style="display: none;">
                                IMPORTANT: It's mandatory that your Magento 2 must be a fresh installation when selecting this option. Once you mark this checkbox and run migration, you can no longer update or cancel this setting, unless you Reset this step.
                                <ul>
                                    <li>Catalog Products</li>
                                    <li>Catalog Product Galleries</li>
                                    <li>Catalog Product Options</li>
                                    <li>Catalog Product Option Type Values</li>
                                    <li>Catalog Product Option Type Titles</li>
                                    <li>Catalog Product Option Type Prices</li>
                                    <li>Catalog Product Option Prices</li>
                                    <li>Catalog Product Option Titles</li>
                                    <li>Catalog Product Stock Items</li>
                                    <li>Catalog Product Links</li>
                                    <li>Catalog Product Super Links</li>
                                    <li>Catalog Product Super Attributes</li>
                                    <li>Catalog Product Bundle Options</li>
                                    <li>Catalog Product Bundle Selections</li>
                                    <li>Catalog Product Download Links</li>
                                    <li>Catalog Product Download Samples</li>
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
