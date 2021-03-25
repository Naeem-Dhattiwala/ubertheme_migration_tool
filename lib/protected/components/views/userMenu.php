<nav class="ub-migration-nav">
    <ul class="migration-steps">
        <?php foreach ($steps as $step): ?>
            <?php
            $stepClasses = ['setting-step'];
            if (Yii::app()->controller->id == $step->code) {
                $stepClasses[] = 'active';
            }
            $stepClasses[] = $step->getStepStatusClassCSS();
            $title = "<span class=\"step-index\"><span class='number-circle'>{$step->sorder}</span></span><span class=\"step-title\">{$step->title}</span>";
            $title .= $step->getStepStatusText();
            ?>
            <li id="setting-step-<?php echo $step->sorder;?>" class="<?php echo implode(' ', $stepClasses); ?>">
                <?php echo CHtml::link($title, UBMigrate::getSettingUrl($step->sorder)); ?>
            </li>
        <?php endforeach; ?>
        <li id="migrating-data-step" class="<?php echo (Yii::app()->controller->id == 'base') ? 'active' : ''; ?>">
            <?php echo CHtml::link('<span class="step-index"><span id="percent-finished" class="value">'.UBMigrate::getPercentByStatus(UBMigrate::STATUS_FINISHED, [1]).'%</span></span></span><span class="step-title">'.Yii::t('frontend', 'Migrating Data').'</span>', UBMigrate::getStartUrl(), array('class' => '')); ?>
        </li>
    </ul>
</nav>
