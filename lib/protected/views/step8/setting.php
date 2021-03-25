<?php
    $selectedObjects = (isset($settingData['objects'])) ? $settingData['objects'] : [];
    $migratedObjects = (isset($settingData['migrated_objects'])) ? $settingData['migrated_objects'] : [];

    $selectedChildObjects = (isset($settingData['child_objects'])) ? $settingData['child_objects'] : [];
    $migratedChildObjects = (isset($settingData['migrated_child_objects'])) ? $settingData['migrated_child_objects'] : [];

    $isMigrated = UBMigrate::isMigrated($step->sorder);
?>
<?php $this->pageTitle = $step->title . ' - ' . Yii::app()->name; ?>

<h2 class="page-header"><?php echo Yii::t('frontend', 'Migration Settings'); ?> <i class="material-icons">keyboard_arrow_right</i> <?php echo Yii::t('frontend', $step->title); ?> </h2>

<form class="frm-settings" role="form" method="post" action="<?php echo UBMigrate::getSettingUrl($step->sorder); ?>">
    <div id="step-content" class="step7">

        <?php $this->renderPartial('/base/_messages', array('step' => $step)); ?>

        <div class="message tip">
            <i class="material-icons">lightbulb_outline</i>
            <p>
                <?php echo Yii::t('frontend', 'Other data refers to Reviews, Rating, Product Tier Prices, Product Group Prices, Download Link Purchased, Tax Data, Email Templates...'); ?>
            </p>
        </div>

        <div class="panel-group other-data-objects" role="tablist" aria-multiselectable="true">
            <div class="panel panel-default has-child">
                <div class="panel-heading" role="tab">

                    <span class="panel-title" title="<?php echo Yii::t('frontend', 'Other Data')?>">
                        <?php echo Yii::t('frontend', 'Other Data'); ?>
                    </span>

<!--                     <button class="btn-expand btn-expand-less">
                        <i class="material-icons expand-more">expand_more</i>
                        <i class="material-icons expand-less">expand_less</i>
                    </button> -->
                </div>
                <div class="panel-body">
                    <div class="checkbox">
                        <label for="select-all" title="<?php echo Yii::t('frontend', 'Click here to select all.')?>"><?php echo Yii::t('frontend', 'Select All');?></label>
                        <input type="checkbox" id="select-all" name="select_all" <?php echo ($isMigrated) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : ''; ?> value="1" <?php echo (sizeof($selectedObjects) == sizeof($objects)) ? "checked" : ''; ?> title="<?php echo Yii::t('frontend', 'Click here to select all.')?>" />
                    </div>
                    <?php if ($objects): ?>
                        <ul class="list-group ver-nav">
                            <?php foreach ($objects as $object => $info): ?>
                                <?php
                                $checked = (in_array($object, $selectedObjects)) ? 'checked' : '';
                                $hasChild = (isset($info['related']) AND $info['related']) ? 1 : 0;
                                $disabled = ($checked && $isMigrated) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';

                                $total = (in_array($object, array('tax_data', 'increment_ids', 'email_template_newsletter'))) ? null : UBMigrate::getTotalItemOfObject($object);
                                $suffix = (!is_null($total)) ?  " (". $total .")" : '';

                                $toolTip = ($object == 'catalog_product_entity_group_price' ? 'class="has-tooltip" data-toggle="tooltip" data-placement="right" title="'.Yii::t('frontend', 'All Product group prices will be convert to Product tier prices.').'"' : '');
                                ?>
                                <li class="list-group-item<?php echo ($hasChild) ? ' has-child' : ''; ?><?php echo ($disabled) ? ' read-only' : ''; ?>">
                                    <div class="list-group-item-heading">
                                        <?php if (in_array($object, $migratedObjects)): ?>
                                            <span class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></span>
                                        <?php endif; ?>
                                        <label for="object_<?php echo $object; ?>" class="checkbox-inline<?php echo ($disabled) ? ' read-only' : ''; ?>" <?php echo $toolTip; ?>>
                                            <input id="object_<?php echo $object; ?>" name="objects[]"
                                                   type="checkbox" <?php echo($checked) ?> <?php echo $disabled; ?>
                                                   value="<?php echo $object; ?>"/>
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
                                            <?php foreach ($info['related'] as $childObject => $label) : ?>
                                                <?php
                                                $checked = (in_array($childObject, $selectedChildObjects)) ? 'checked' : '';
                                                $disabled = ($checked && $isMigrated) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                                                $keyName = 'child_objects';
                                                ?>
                                                <li class="list-group-item<?php echo ($disabled) ? ' read-only' : ''; ?>">
                                                    <div class="list-group-item-heading">
                                                        <label class="checkbox-inline<?php echo ($disabled) ? ' read-only' : ''; ?>" for="<?php echo $keyName ."_". $childObject; ?>">
                                                            <input id="<?php echo $keyName ."_". $childObject; ?>" name="<?php echo $keyName; ?>[]"
                                                                   type="checkbox" <?php echo($checked) ?> <?php echo $disabled; ?>
                                                                   value="<?php echo $childObject; ?>"/>
                                                            <span><?php echo " {$label}" . " (" . UBMigrate::getTotalItemOfObject($childObject) . ")"; ?></span>
                                                        </label>
                                                        <?php if (in_array($childObject, $migratedChildObjects)): ?>
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
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <?php $this->renderPartial('/base/_buttons', array('step' => $step)); ?>
    </div>
</form>
