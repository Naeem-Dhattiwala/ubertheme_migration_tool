<?php

/**
 * ResetCommand class - CLI
 */
class ResetCommand extends CConsoleCommand
{
    public function actionIndex($step = -1, $limit = 100)
    {
        if ($step > 0) {
            if ($step >= 2 AND $step <= UBMigrate::MAX_STEP_INDEX) {
                $this->_resetData($step, $limit);
            } else {
                echo "ATTENTION: You can run command lines for steps 2, 3, 4, 5, 6, 7, and 8 only.\n";
            }
        } else {
            $steps = [8, 7, 6, 5, 4, 3, 2];
            foreach ($steps as $stepIndex) {
                $this->_resetData($stepIndex, $limit);
            }
            echo "********** All STEPS WERE RESET SUCCESSFULLY **********\n";
        }
    }

    private function _resetData($stepIndex, $limit)
    {
        $step = UBMigrate::model()->findByPk($stepIndex);
        if ($step) {
            $ck = UBMigrate::canReset($step->sorder);
            if ($ck['allowed']) {
                echo "Start resetting data migration in step #{$stepIndex}...";
                $functionName = (in_array($stepIndex, array(3, 5, 6, 7, 8))) ? "resetDataStep{$stepIndex}" : "resetData";
                do {
                    $status = call_user_func(array($step, $functionName), $limit);
                } while ($status == 'ok');

                if ($status == 'done') {
                    //flush cached
                    Yii::app()->cache->flush();
                    $msg = Yii::t('frontend', "\nStep #%s was reset successfully.", array('%s' => $stepIndex));
                    Yii::log($msg, 'info', 'ub_data_migration');
                    echo "{$msg}\n";
                } else {
                    echo $status;
                }
            } else {
                $msg = Yii::t('frontend', "You can't reset this step. You have to reset step #%s first.", array('%s' => $ck['back_step_index']));
                echo "{$msg}\n";
            }
        } else {
            $msg = Yii::t('frontend', "Step #%s not found.", array('%s' => $stepIndex));
            echo "{$msg}\n";
        }
    }

}