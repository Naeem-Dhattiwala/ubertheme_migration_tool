<?php
    $settingData = $step->getSettingData();
    $selectedAttrSetIds = (isset($settingData['attribute_set_ids'])) ? $settingData['attribute_set_ids']  : [];
    $selectedAttrGroupIds = (isset($settingData['attribute_group_ids'])) ? $settingData['attribute_group_ids']  : [];
    $selectedAttrIds = (isset($settingData['attribute_ids'])) ? $settingData['attribute_ids']  : [];
    $totalVars = 0;
?>

<?php $this->pageTitle = $step->title . ' - ' . Yii::app()->name; ?>

<h2 class="page-header"><?php echo Yii::t('frontend', 'Migration Settings');?> > <?php echo Yii::t('frontend', $step->title); ?> </h2>

<form class="frm-settings" role="form" method="post" action="<?php echo UBMigrate::getSettingUrl($step->sorder); ?>">

    <div id="step-content">
        <?php $this->renderPartial('/base/_messages', array('step' => $step)); ?>

        <div class="message tip">
            <i class="material-icons">lightbulb_outline</i>
            <p>
                <?php echo Yii::t('frontend', 'Select attribute sets you want to migrate'); ?> <br/>
                <?php echo Yii::t('frontend', 'Click attribute set’s title to show / hide the list of attribute groups / attributes.')?>
            </p>
        </div>

            <div class="panel-group product-customer-attributes" role="tablist" aria-multiselectable="true">

                <div class="row">

                    <div class="col-md-6">
                        <!-- Product Attribute Sets > Groups-->
                        <div class="panel panel-default attr-sets-groups has-child">
                            <div class="panel-heading" role="tab">
                                <span class="panel-title">
                                    <?php echo Yii::t('frontend', 'Attribute Sets > Attribute Groups'); ?> (<span class="sub-head-title"><?php echo sizeof($attributeSets); ?></span>)
                                </span>
                                <button class="btn-expand btn-expand-less">
                                    <i class="material-icons expand-more">expand_more</i>
                                    <i class="material-icons expand-less">expand_less</i>
                                </button>
                            </div>
                            <div class="panel-body">
                                <div class="message tip">
                                    <span class="head-tip">
                                        - <?php echo Yii::t('frontend', 'All Attribute Sets and Attribute Groups are selected by default and could not be removed.')?><br/>
                                    </span>
                                </div>
                                <?php if ($attributeSets): ?>
                                <ul class="list-group ver-nav">
                                    <?php foreach ($attributeSets as $key => $attributeSet): ?>
                                        <?php
                                        $totalVars++;
                                        //check has selected to migrate
                                        $checked = in_array($attributeSet->attribute_set_id, $selectedAttrSetIds);
                                        $checked = true; //we will always select
                                        //check has migrated
                                        $m2Id = UBMigrate::getM2EntityId(3, $attributeSet->tableName(), $attributeSet->attribute_set_id);

                                        $entityTypeCode1 = UBMigrate::getM1EntityTypeCode($attributeSet->attribute_set_id);
                                        if ($entityTypeCode1 == UBMigrate::PRODUCT_TYPE_CODE) {
                                            $setTypeName = 'product';
                                        } else if ($entityTypeCode1 == UBMigrate::CUSTOMER_TYPE_CODE) {
                                            $setTypeName = 'customer';
                                        } else if ($entityTypeCode1 == UBMigrate::CUSTOMER_ADDRESS_TYPE_CODE) {
                                            $setTypeName = 'customer address';
                                        }
                                        ?>
                                        <li class="list-group-item attribute-set has-child <?php echo strtolower(str_replace(' ', '-', $setTypeName))?> read-only">
                                            <div class="list-group-item-heading">
                                                <label class="checkbox-inline" for="attribute-set-<?php echo $attributeSet->attribute_set_id; ?>">
                                                    <input type="checkbox" id="attribute-set-<?php echo $attributeSet->attribute_set_id; ?>"
                                                           class="read-only" readonly="readonly"
                                                           onclick="event.preventDefault();" <?php echo ($checked) ? 'checked="checked"' : ''; ?>
                                                           name="attribute_set_ids[]"
                                                           value="<?php echo $attributeSet->attribute_set_id; ?>" />
                                                    <span>
                                                        <?php echo ($key+1) .' - '. $attributeSet->attribute_set_name; ?>
                                                        (<span style="font-size: 11px;"><?php echo $setTypeName;?></span>)
                                                    </span>
                                                </label>
                                                <?php if ($m2Id): ?>
                                                    <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                                <?php endif; ?>
                                                <button class="btn-expand btn-expand-more">
                                                    <i class="material-icons expand-more">expand_more</i>
                                                    <i class="material-icons expand-less">expand_less</i>
                                                </button>
                                            </div>
                                            <?php
                                            //get all attribute groups of current attribute set
                                            $condition = "attribute_set_id = {$attributeSet->attribute_set_id}";
                                            $attributeGroups = Mage1AttributeGroup::model()->findAll($condition);
                                            ?>
                                            <?php if ($attributeGroups): ?>
                                                <ul class="list-group" style="display: none;">
                                                    <?php foreach ($attributeGroups as $attributeGroup): ?>
                                                        <?php
                                                        $totalVars++;
                                                        //check has selected to migrate
                                                        $checked = in_array($attributeGroup->attribute_group_id, $selectedAttrGroupIds);
                                                        $checked = true; //we will always select
                                                        //check has migrated
                                                        $m2Id = UBMigrate::getM2EntityId(3, $attributeGroup->tableName(), $attributeGroup->attribute_group_id);
                                                        ?>
                                                        <li class="list-group-item attribute-group read-only">
                                                            <div class="list-group-item-heading">
                                                                <label class="checkbox-inline" for="attribute-group-<?php echo $attributeGroup->attribute_group_id; ?>">
                                                                    <input type="checkbox" id="attribute-group-<?php echo $attributeGroup->attribute_group_id; ?>" readonly="readonly"
                                                                           onclick="event.preventDefault();" <?php echo ($checked) ? "checked" : ''; ?>
                                                                           name="attribute_group_ids[]" class="attribute-group-<?php echo $attributeSet->attribute_set_id; ?> read-only"
                                                                           value="<?php echo $attributeGroup->attribute_group_id?>" />
                                                                    <?php echo $attributeGroup->attribute_group_name; ?>
                                                                </label>
                                                                <?php if ($m2Id): ?>
                                                                    <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                                                <?php endif; ?>
                                                            </div>
                                                        </li>
                                                    <?php endforeach; ?>
                                                </ul>
                                            <?php endif;?>
                                        </li>
                                    <?php endforeach; ?>
                                </ul>
                            <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Product Attributes -->
                    <div class="col-md-6">
                        <div class="panel panel-default attributes has-child">
                            <div class="panel-heading" role="tab">
                                <span class="panel-title">
                                    <?php echo Yii::t('frontend', 'Product Attributes'); ?> (<span class="sub-head-title"><?php echo sizeof($attributes);?></span>)
                                </span>
                                <button class="btn-expand btn-expand-less">
                                    <i class="material-icons expand-more">expand_more</i>
                                    <i class="material-icons expand-less">expand_less</i>
                                </button>
                            </div>
                            <div class="panel-body">
                                <?php if ($attributes): ?>
                                    <div class="message tip">
                                        <span class="head-tip">
                                            - <?php echo UBMigrate::getTotalVisibleProductsAttr(); ?> attributes are visible in the back-end.<br/>
                                            - <?php echo Yii::t('frontend', 'All system attributes are selected by default and could not be removed.')?><br/>
                                        </span>
                                    </div>
                                    <ul class="list-group ver-nav">
                                        <?php foreach ($attributes as $key => $attribute): ?>
                                            <?php
                                            $totalVars++;
                                            //check has selected to migrate
                                            $checked = in_array($attribute->attribute_id, $selectedAttrIds);
                                            //we will always select if has not custom settings yet
                                            $checked = ($step->status == UBMigrate::STATUS_PENDING || $step->status == UBMigrate::STATUS_SKIPPING) ? 'checked' : ($checked ? 'checked' : '');
                                            //check has migrated
                                            $m2Id = UBMigrate::getM2EntityId('3_attribute', $attribute->tableName(), $attribute->attribute_id);
                                            //check for disable
                                            $disable = ((!$attribute->is_user_defined) || (UBMigrate::isMigrated($step->sorder) && $m2Id)) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                                            ?>
                                            <li class="list-group-item attributes<?php echo ($disable) ? ' read-only' : ''; ?>">
                                                <div class="list-group-item-heading">
                                                    <label class="checkbox-inline">
                                                        <input type="checkbox" id="attribute-<?php echo $attribute->attribute_id; ?>"
                                                            <?php echo $checked; ?> <?php echo $disable; ?> name="attribute_ids[]"
                                                               value="<?php echo $attribute->attribute_id; ?>" />
                                                        <?php echo ($key+1) .' - '. $attribute->frontend_label . ' ('.$attribute->attribute_code.')'; ?>
                                                    </label>
                                                    <?php if ($m2Id): ?>
                                                        <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                                    <?php endif; ?>
                                                </div>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                </div>

                <div class="row">

                    <div class="col-md-6">
                        <!-- Customer Attributes -->
                        <div class="panel panel-default customer-attributes has-child">
                            <div class="panel-heading" role="tab">
                                <span class="panel-title">
                                    <?php echo Yii::t('frontend', 'Customer Attributes'); ?> (<span class="sub-head-title"><?php echo sizeof($customerAttributes);?></span>)
                                </span>
                                <button class="btn-expand btn-expand-less">
                                    <i class="material-icons expand-more">expand_more</i>
                                    <i class="material-icons expand-less">expand_less</i>
                                </button>
                            </div>
                            <div class="panel-body">
                                <?php if ($customerAttributes): ?>
                                    <div class="message tip">
                                        <span class="head-tip">
                                            - <?php echo Yii::t('frontend', 'All system attributes are selected by default and could not be removed.')?><br/>
                                        </span>
                                    </div>
                                    <ul class="list-group ver-nav">
                                        <?php foreach ($customerAttributes as $key => $attribute): ?>
                                            <?php
                                            //check has selected to migrate
                                            $checked = in_array($attribute->attribute_id, $selectedAttrIds);
                                            //we will always select if has not custom settings yet
                                            $checked = ($step->status == UBMigrate::STATUS_PENDING || $step->status == UBMigrate::STATUS_SKIPPING) ? 'checked' : ($checked ? 'checked' : '');
                                            //check has migrated
                                            $m2Id = UBMigrate::getM2EntityId('3_attribute', $attribute->tableName(), $attribute->attribute_id);
                                            //check for disable
                                            $disable = ((!$attribute->is_user_defined) || (UBMigrate::isMigrated($step->sorder) && $m2Id)) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                                            ?>
                                            <li class="list-group-item attributes<?php echo ($disable) ? ' read-only' : ''; ?>">
                                                <div class="list-group-item-heading">
                                                    <label class="checkbox-inline">
                                                        <input type="checkbox" id="attribute-<?php echo $attribute->attribute_id; ?>"
                                                            <?php echo $checked; ?> <?php echo $disable; ?>
                                                               name="attribute_ids[]" value="<?php echo $attribute->attribute_id; ?>" />
                                                        <?php echo ($key+1) .' - '. $attribute->frontend_label . ' ('.$attribute->attribute_code.')'; ?>
                                                    </label>
                                                    <?php if ($m2Id): ?>
                                                        <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                                    <?php endif; ?>
                                                </div>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-6">
                        <!-- Customer Address Attributes -->
                        <div class="panel panel-default customer-address-attributes has-child">
                            <div class="panel-heading" role="tab">
                                <span class="panel-title">
                                    <?php echo Yii::t('frontend', 'Customer Address Attributes'); ?> (<span class="sub-head-title"><?php echo sizeof($customerAddressAttributes);?></span>)
                                </span>
                                <button class="btn-expand btn-expand-less">
                                    <i class="material-icons expand-more">expand_more</i>
                                    <i class="material-icons expand-less">expand_less</i>
                                </button>
                            </div>
                            <div class="panel-body">
                                <?php if ($customerAddressAttributes): ?>
                                    <div class="message tip">
                                        <span class="head-tip">
                                            - <?php echo Yii::t('frontend', 'All system attributes are selected by default and could not be removed.')?><br/>
                                        </span>
                                    </div>
                                    <ul class="list-group ver-nav">
                                        <?php foreach ($customerAddressAttributes as $key => $attribute): ?>
                                            <?php
                                            //check has selected to migrate
                                            $checked = in_array($attribute->attribute_id, $selectedAttrIds);
                                            //we will always select if has not custom settings yet
                                            $checked = ($step->status == UBMigrate::STATUS_PENDING || $step->status == UBMigrate::STATUS_SKIPPING) ? 'checked' : ($checked ? 'checked' : '');
                                            //check has migrated
                                            $m2Id = UBMigrate::getM2EntityId('3_attribute', $attribute->tableName(), $attribute->attribute_id);
                                            //check for disable
                                            $disable = ((!$attribute->is_user_defined) || (UBMigrate::isMigrated($step->sorder) && $m2Id)) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                                            ?>
                                            <li class="list-group-item attributes<?php echo ($disable) ? ' read-only' : ''; ?>">
                                                <div class="list-group-item-heading">
                                                    <label class="checkbox-inline">
                                                        <input type="checkbox" id="attribute-<?php echo $attribute->attribute_id; ?>"
                                                            <?php echo $checked; ?> <?php echo $disable; ?> name="attribute_ids[]"
                                                               value="<?php echo $attribute->attribute_id; ?>" />
                                                        <?php echo ($key+1) .' - '. $attribute->frontend_label . ' ('.$attribute->attribute_code.')'; ?>
                                                    </label>
                                                    <?php if ($m2Id): ?>
                                                        <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                                    <?php endif; ?>
                                                </div>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>

        <?php $this->renderPartial('/base/_buttons', array('step' => $step, 'continue' => $continue)); ?>
    </div>
</form>

