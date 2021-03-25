<!--  Form Buttons-->
<div class="step-controls">
    <a title="<?php echo Yii::t('frontend', 'Click to go previous step'); ?>" href="<?php echo UBMigrate::getSettingUrl(($step->sorder-1)) ?>" class="btn btn-default btn-lg btn-prev-step"><i class="material-icons">arrow_back</i> <span><?php echo Yii::t('frontend', 'Previous Step'); ?></span></a>

    <?php $btnSkipClasses = (in_array($step->sorder, UBMigrate::$allowSkipSteps) && !UBMigrate::isMigrated($step->sorder) && $step->status != UBMigrate::STATUS_SKIPPING) ? 'btn btn-lg' : 'btn btn-lg disabled'; ?>
    <a class="<?php echo $btnSkipClasses; ?>" title="<?php echo Yii::t('frontend', 'Skip migrate data in this step and continue with next step'); ?>" href="<?php echo UBMigrate::getSkipUrl($step->sorder); ?>" ><span><?php echo Yii::t('frontend', 'Skip this Step'); ?></span></a>

    <?php $btnContinueClasses = (isset($continue) && !$continue) ? 'btn btn-primary btn-lg disabled' : 'btn btn-primary btn-lg'; ?>
    <button title="<?php echo Yii::t('frontend', 'Click to save settings and go to next step'); ?>" type="submit" class="<?php echo $btnContinueClasses; ?>"><span><?php echo Yii::t('frontend', 'Next Step'); ?></span> <i class="material-icons">arrow_forward</i></button>
</div>
<!--// Form Buttons-->