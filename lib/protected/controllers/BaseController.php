<?php

class BaseController extends Controller
{
    public $layout = '1column';
    public $limit = 100; //limit item to migrate in a step
    public $resetLimit = 100; //limit item to reset in a step
    public $errors = [];
    public $isCLI = false;
    public $runMode = 'run';

    /**
     * Init function
     */
    public function init()
    {
        //update limit value from config if exist
        $this->limit = (isset(Yii::app()->params['limit'])) ? Yii::app()->params['limit'] : 100;
        $this->resetLimit = (isset(Yii::app()->params['reset_limit'])) ? Yii::app()->params['reset_limit'] : 100;

        return parent::init();
    }

    protected function beforeAction($action)
    {
        if ($action->id == 'run') {
            //set un-check foreign key
            Yii::app()->db->createCommand("SET FOREIGN_KEY_CHECKS=0")->execute();
        }

        return parent::beforeAction($action);
    }

    /**
     * This method is invoked right after an action is executed.
     * You may override this method to do some postprocessing for the action.
     * @param CAction $action the action just executed.
     */
    protected function afterAction($action)
    {
        if ($action->id == 'run') {
            //set check foreign key
            Yii::app()->db->createCommand("SET FOREIGN_KEY_CHECKS=1")->execute();
        }

        return parent::afterAction($action);
    }

    /**
     * This is the action to handle external exceptions.
     */
    public function actionError()
    {
        if ($error = Yii::app()->errorHandler->error) {
            if (Yii::app()->request->isAjaxRequest)
                echo $error['message'];
            else
                $this->render('error', $error);
        }
    }

    /**
     * Displays the index page
     */
    public function actionIndex()
    {
        $percentFinished = UBMigrate::getPercentByStatus(UBMigrate::STATUS_FINISHED, [1]);
        if ($percentFinished) {
            $this->redirect(UBMigrate::getStartUrl());
        } else {
            $this->redirect(UBMigrate::getSettingUrl());
        }
    }

    /**
     * Start migrate data
     */
    public function actionStart()
    {
        if (UBMigrate::model()->count("sorder = 1 AND status =" . UBMigrate::STATUS_FINISHED)) { //has databases settings
            $steps = UBMigrate::model()->findAll();
            $this->render("start", array('steps' => $steps));
        } else {
            Yii::app()->user->setFlash('note', Yii::t('frontend', "You have to finish the databases settings first."));
            $this->redirect(UBMigrate::getSettingUrl());
        }
    }

    public function actionSkip()
    {
        $stepIndex = Yii::app()->request->getParam('step', null);
        $step = UBMigrate::model()->findByPk($stepIndex);
        if ($step) {
            //update step status
            $step->status = UBMigrate::STATUS_SKIPPING;
            $step->update();

            $msg = Yii::t('frontend', "Step #%s was skipped successfully.", array('%s' => $stepIndex));
            //log
            Yii::log($msg, 'info', 'ub_data_migration');

            //assign message
            Yii::app()->user->setFlash('success', $msg);

            //get next step index
            if ($stepIndex < UBMigrate::MAX_STEP_INDEX) {
                ++$stepIndex;
            } else {
                $this->redirect(UBMigrate::getStartUrl());
            }
        } else {
            Yii::app()->user->setFlash('error', Yii::t('frontend', "Step #%s not found.", array('%s' => $stepIndex)));
            $stepIndex = 1;
        }

        $this->redirect(UBMigrate::getSettingUrl($stepIndex));
    }

    public function actionAjaxReset()
    {
        $stepIndex = Yii::app()->request->getParam('step', 1);
        $step = UBMigrate::model()->findByPk($stepIndex);
        $rs = [
            'step_status_text' => $step->getStepStatusText(),
            'step_index' => (int)$step->sorder,
            'status' => 'fail',
        ];
        if ($step) {
            $ck = UBMigrate::canReset($step->sorder);
            if ($ck['allowed']) {
                $functionName = (in_array($stepIndex, array(3, 5, 6, 7, 8))) ? "resetDataStep{$stepIndex}" : "resetData";
                $rs['status'] = call_user_func(array($step, $functionName), $this->resetLimit);
                if ($rs['status'] == 'done') {
                    //flush cached
                    Yii::app()->cache->flush();
                    $msg = Yii::t('frontend', "Step #%s was reset successfully", array('%s' => $stepIndex));
                    $rs['message'] = $msg;
                    Yii::log($msg, 'info', 'ub_data_migration');
                    $rs['step_status_text'] = $step->getStepStatusText();
                } else {
                    Yii::log("Resetting data migration in the step #{$stepIndex}...", 'info', 'ub_data_migration');
                }
            } else {
                $rs['notice'] = Yii::t('frontend', "You can't reset this step. You must reset the step #%s first.", array('%s' => $ck['back_step_index']));
            }
        } else {
            $rs['errors'] = Yii::t('frontend', "Step #%s not found.", array('%s' => $stepIndex));
        }

        //respond result
        echo json_encode($rs);
        Yii::app()->end();
    }

    public function actionUpdateLog()
    {
        $logFilePath = Yii::app()->basePath . DIRECTORY_SEPARATOR . "runtime" . DIRECTORY_SEPARATOR . "ub_data_migration.log";
        $content = '';
        if (file_exists($logFilePath)) {
            if (is_readable($logFilePath)) {
                //$content = file_get_contents($logFilePath);
                try {
                    $lines = file($logFilePath);
                    $tmpLine = '';
                    // loop through each line
                    foreach ($lines as $line) {
                        $line = str_replace('[info] [ub_data_migration]', '-', $line);
                        $tmpLine = '<span class="row-log">' . $line . '</span>';
                        $content .= $tmpLine;
                        $tmpLine = '';
                    }
                } catch (Exception $e) {
                    throw $e;
                }
            } else {
                $content = Yii::t('frontend', 'Log file was not able to read.');
            }
        } else {
            $content = Yii::t('frontend', 'Log file was not found.');
        }

        echo $content;
        Yii::app()->end();
    }

    public function setLimit($limit)
    {
        $this->limit = $limit;
    }

    public function setResetLimit($limit)
    {
        $this->resetLimit = $limit;
    }

    public function setRunMode($mode)
    {
        $this->runMode = $mode;
    }

    public function getRunMode()
    {
        return $this->runMode;
    }

    public function activeCLI()
    {
        $this->isCLI = true;
    }

}
