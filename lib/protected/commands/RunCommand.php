<?php

/**
 * RunCommand class - CLI
 */
class RunCommand extends CConsoleCommand
{
    protected $stepIndex;
    protected $percent;

    public function actionIndex($step = -1, $limit = false, $mode = 'run')
    {
        Yii::app()->db->createCommand("SET FOREIGN_KEY_CHECKS=0")->execute();

        $this->percent = UBMigrate::getPercentByStatus(UBMigrate::STATUS_FINISHED, [1]);
        if ($step > 0) { //has specify step
            if ($step >= 2 AND $step <= UBMigrate::MAX_STEP_INDEX) {
                $this->stepIndex = $step;
                $controllerName = "Step{$this->stepIndex}Controller";
                $step = new $controllerName("{step{$this->stepIndex}}");
                $step->activeCLI();
                if ($limit > 0) {
                    $step->setLimit($limit);
                }
                if ($mode == 'update') {
                    $step->setRunMode('rerun');
                }
                $this->_migrateData($step);
            } else {
                echo "ATTENTION: You can run command lines for steps 2, 3, 4, 5, 6, 7, and 8 only.\n";
            }

        } else { //run all steps
            $steps = [2, 3, 4, 5, 6, 7, 8];
            foreach ($steps as $step) {
                $this->stepIndex = $step;
                $controllerName = "Step{$this->stepIndex}Controller";
                $step = new $controllerName("{step{$this->stepIndex}}");
                $step->activeCLI();
                if ($limit > 0) {
                    $step->setLimit($limit);
                }
                if ($mode == 'update') {
                    $step->setRunMode('rerun');
                }
                $this->_migrateData($step);
            }
            echo strtoupper("ATTENTION: Data migration has been completed successfully. You still have a few more steps to complete.\nFollow instructions in the Readme.html that came with your download package, then you're done.")."\n\n";
        }

        Yii::app()->db->createCommand("SET FOREIGN_KEY_CHECKS=1")->execute();
    }

    private function _migrateData($step)
    {
        do {
            echo "Processing in step #{$this->stepIndex}...";
            $result = $step->actionRun();
            $this->_respond($result);
            //reset run mode for next run
            $step->setRunMode('run');
        } while ($result['status'] == 'ok');

        if ($result['status'] == 'fail') {
            $msg = (isset($result['notice']) AND $result['notice']) ? $result['notice'] : (($result['errors']) ? $result['errors'] : '');
            echo "Status: {$result['status']}\n";
            echo "Message: {$msg}\n";
        } else { //done
            $value = UBMigrate::getPercentByStatus(UBMigrate::STATUS_FINISHED, [1]);
            echo "Total Data Migrated: {$value}%\n\n";
        }
    }

    private function _respond($result)
    {
        echo "{$result['message']}\n";
        //update percent finished
        /*if (isset ($result['percent_up']) AND $result['percent_up']) {
            $this->percent += (float)$result['percent_up'];
        }
        $value = round($this->percent);
        if ($result['status'] == 'ok') {
            echo "Total Data Migrated: {$value}%\n";
        }*/
    }

}