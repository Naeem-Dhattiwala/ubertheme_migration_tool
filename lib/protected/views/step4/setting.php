<?php
    $settingData = $step->getSettingData();
    $selectedCategoryIds = (isset($settingData['category_ids'])) ? $settingData['category_ids']  : [];
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
                <?php echo Yii::t('frontend', 'Select categories you want to migrate.'); ?><br/>
                <span><?php echo Yii::t('frontend', 'Click the category name to show / hide sub-categories. If you don\'t specify categories, all categories will be migrated.')?></span>
            </p>
        </div>

        <div class="panel panel-default has-child">

        <div class="panel-heading">
            <h3 class="panel-title">
                <?php echo Yii::t('frontend', 'Product Categories'); ?> (<?php echo $totalCategories; ?>)
            </h3>
        </div>

        <div class="panel-body">
            <div class="row">
                <div class="col-md-12">
                    <div class="checkbox">
                        <label title="<?php echo Yii::t('frontend', 'Click here to select all categories');?>" for="select_all_categories"> <?php echo Yii::t('frontend', 'Select All');?> </label>
                        <input type="checkbox" <?php echo ($totalCategories == sizeof($selectedCategoryIds)) ? "checked" : ''; ?>
                               id="select_all_categories" name="select_all_categories" value="1" />
                    </div>
                </div>
            </div>
            <div class="row">
            <?php if ($rootCategories): ?>
                <?php foreach ($rootCategories as $key => $rootCategory): ?>
                    <?php
                        //check has selected
                        $checked = in_array($rootCategory->entity_id, $selectedCategoryIds) ? true : false;
                        //check has migrated
                        $m2Id = UBMigrate::getM2EntityId($step->sorder, $rootCategory->tableName(), $rootCategory->entity_id);
                        //check for disable
                        $disable = ($isMigrated && $m2Id) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
                        //get child categories of this category
                        $categoryTree = UBMigrate::getMage1CategoryTree($rootCategory->entity_id);
                    ?>
                    <div class="col-md-6">
                        <div class="tree">
                            <div class="tree-heading<?php echo (!empty($disable) ? ' read-only' : ''); ?>">
                                <input type="checkbox" <?php echo ($checked) ? "{$disable} checked" : ''; ?>
                                       id="category_<?php echo $rootCategory->entity_id; ?>"
                                       name="category_ids[]" value="<?php echo $rootCategory->entity_id; ?>" />
                                <span class="root-category" title="<?php echo Yii::t('frontend', 'Click here to show/hide child categories'); ?>"><?php echo UBMigrate::getMage1CategoryName($rootCategory->entity_id); ?> (<span style="font-weight: normal;"><?php echo Yii::t('frontend', 'Root Category');?></span>)</span>
                                <?php if ($m2Id): ?>
                                    <i class="chip text-success"><?php echo Yii::t('frontend', 'Migrated'); ?></i>
                                <?php endif; ?>
                                <?php if ($categoryTree) :?>
                                    <button class="btn-expand btn-expand-more">
                                        <i class="material-icons expand-more">expand_more</i>
                                        <i class="material-icons expand-less">expand_less</i>
                                    </button>
                                <?php endif; ?>
                            </div>
                            <div class="tree-body" style="display: none;">
                            <?php
                                if ($categoryTree) {
                                    echo UBMigrate::generateCategoryTreeHtml($categoryTree, $selectedCategoryIds, 1);
                                }
                            ?>
                            </div>
                        </div>
                    </div>

                <?php if (($key+1) % 2 == 0):?>
                    </div><div class="row">
                <?php endif; ?>

                <?php endforeach; ?>
            <?php endif; ?>
            </div>
        </div>

        </div>

        <?php $this->renderPartial('/base/_buttons', array('step' => $step, 'continue' => $continue)); ?>
    </div>
</form>
<script type="text/javascript">
    //for category tree
    (function($) {
        $('.tree li:has(ul)').addClass('has-child').find(' > span').attr('title', 'Collapse this branch');
        $('.tree li.has-child > span').on('click', function (e) {
            var $children = $(this).parent('li.has-child').find(' > ul > li');
            if ($children.is(":visible")) {
                $children.hide('fast');
                $(this).attr('title', 'Expand this').find(' > i').addClass('icon-plus-sign').removeClass('icon-minus-sign');
            } else {
                $children.show('fast');
                $(this).attr('title', 'Collapse this').find(' > i').addClass('icon-minus-sign').removeClass('icon-plus-sign');
            }
            e.stopPropagation();
        });

        //check/un-check
        $('.tree INPUT[name="category_ids[]"]').on('change', function() {
            if (!$(this).hasClass('read-only')) {
                var value = this.checked;

                //update children status
                var $children = ($(this).siblings('ul').length) ? $(this).siblings('ul') : $(this).parent().siblings('.tree-body').children('ul');
                $children.children('li').each(function(i){
                    $(this).find('input').prop("checked", value);
                });

                //update parent status
                var $parent = $(this).parent().parent().siblings('input');
                if (!$parent.length) { //find to root level
                    $parent = $(this).parent().parent().parent().siblings('.tree-heading').children('input');
                }

                if (value) { //if checked
                    $parent.prop("checked", value);
                }
            }
        });
        $('INPUT[name="select_all_categories"]').on('change', function() {
            if (!$(this).hasClass('read-only')) {
                var value = this.checked;
                $('.tree INPUT[name="category_ids[]"]').each(function(i, el) {
                    if (!$(el).hasClass('read-only')) {
                        $(el).prop("checked", value).trigger('change');
                    }
                });
            }
        });

    })(jQuery);
</script>