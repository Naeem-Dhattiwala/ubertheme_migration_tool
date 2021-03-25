<?php

/**
 * @todo: Databases settings
 *
 * Class Step1Controller
 */
class Step1Controller extends Controller
{
    public $layout = '1column';

    protected $stepIndex = 1;

    /**
     * @todo: Setting
     */
    public function actionSetting()
    {
        //get step object
        $step = UBMigrate::model()->find("code = 'step{$this->stepIndex}'");

        if (Yii::app()->request->isPostRequest) {

            //validate databases
            mysqli_report(MYSQLI_REPORT_STRICT);
            $err_msg = array();
            $validate = true;

            //validate M1 database credentials
            $port1 = (!empty($_POST['mg1_db_port'])) ? $_POST['mg1_db_port'] : ini_get("mysqli.default_port");
            try {
                $connection = mysqli_connect($_POST['mg1_host'], $_POST['mg1_db_user'], $_POST['mg1_db_pass'], $_POST['mg1_db_name'], $port1);
                if ($connection) {
                    //validate magento2 database
                    $port2 = (!empty($_POST['mg2_db_port'])) ? $_POST['mg2_db_port'] : ini_get("mysqli.default_port");
                    try {
                        $connection = mysqli_connect($_POST['mg2_host'], $_POST['mg2_db_user'], $_POST['mg2_db_pass'], $_POST['mg2_db_name'], $port2);
                    } catch (Exception $e ) {
                        $err_msg[] = Yii::t('frontend', "Couldn't connected to Magento 2 database: ".$e->getMessage());
                        $validate = false;
                    }
                }
            } catch (Exception $e) {
                $err_msg[] = Yii::t('frontend', "Couldn't connect to Magento 1 database: " . $e->getMessage());
                $validate = false;
            }
            if (isset($connection) AND $connection) {
                mysqli_close($connection);
            }

            if ($validate) {
                //save to config file
                $configFilePath = Yii::app()->basePath . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "db.php";
                if (file_exists($configFilePath) && is_writable($configFilePath)) {
                    $configTplFilePath = Yii::app()->basePath . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "db.tpl";
                    $configs = file_get_contents($configTplFilePath);

                    //Update M1 database credentials submit from setting from
                    $configs = str_replace('{MG1_HOST}', $_POST['mg1_host'], $configs);
                    $configs = str_replace('{MG1_DB_PORT}', $port1, $configs);
                    $configs = str_replace('{MG1_DB_NAME}', $_POST['mg1_db_name'], $configs);
                    $configs = str_replace('{MG1_DB_USER}', $_POST['mg1_db_user'], $configs);
                    $configs = str_replace('{MG1_DB_PASS}', $_POST['mg1_db_pass'], $configs);
                    $configs = str_replace('{MG1_TABLE_PREFIX}', $_POST['mg1_db_prefix'], $configs);
                    $configs = str_replace('{MG1_VERSION}', $_POST['mg1_version'], $configs);

                    //Update M2 database credentials submit from setting from
                    $configs = str_replace('{MG2_HOST}', $_POST['mg2_host'], $configs);
                    $configs = str_replace('{MG2_DB_PORT}', $port2, $configs);
                    $configs = str_replace('{MG2_DB_NAME}', $_POST['mg2_db_name'], $configs);
                    $configs = str_replace('{MG2_DB_USER}', $_POST['mg2_db_user'], $configs);
                    $configs = str_replace('{MG2_DB_PASS}', $_POST['mg2_db_pass'], $configs);
                    $configs = str_replace('{MG2_TABLE_PREFIX}', $_POST['mg2_db_prefix'], $configs);

                    //save
                    if (file_put_contents($configFilePath, $configs)) {
                        //update new settings
                        $step->setting_data = json_encode($_POST);
                        //save settings to database
                        $step->status = UBMigrate::STATUS_FINISHED;
                        if ($step->save()) {
                            //alert message
                            Yii::app()->user->setFlash('success', Yii::t('frontend', "Your settings was saved successfully"));
                            //get next step index
                            $stepIndex = ($this->stepIndex < UBMigrate::MAX_STEP_INDEX) ? ++$this->stepIndex : 1;
                            sleep(3);
                            //go to next step
                            $this->redirect(UBMigrate::getSettingUrl($stepIndex));
                        }
                    }
                } else {
                    Yii::app()->user->setFlash('note', Yii::t('frontend', "The config file was not exists or not ablewrite permission.<br/>Please make writeable for config file and try again."));
                }
            } else {
                //update step status
                $step->updateStatus(UBMigrate::STATUS_ERROR);
                Yii::app()->user->setFlash('error', implode('</br>', $err_msg));
            }
        } else {

            //auto load database of magento 2 settings if exists
            $configFilePath = Yii::app()->basePath . "/../../../app/etc/env.php";
            if (file_exists($configFilePath)) {

                //get current M2 configuration
                $configData = require $configFilePath;

                //get current settings in migration tool from database
                $oldSettings = (object)json_decode($step->setting_data);
                $settings = $oldSettings;

                //update current M2 database credentials
                $settings->mg2_host = (isset($configData['db']['connection']['default']['host'])) ? $configData['db']['connection']['default']['host'] : '';
                $settings->mg2_db_user = (isset($configData['db']['connection']['default']['username'])) ? $configData['db']['connection']['default']['username'] : '';
                $settings->mg2_db_pass = (isset($configData['db']['connection']['default']['password'])) ? $configData['db']['connection']['default']['password'] : '';
                $settings->mg2_db_name = (isset($configData['db']['connection']['default']['dbname'])) ? $configData['db']['connection']['default']['dbname'] : '';
                $settings->mg2_db_prefix = (isset($configData['db']['table_prefix'])) ? $configData['db']['table_prefix'] : '';
                $hostInfo = explode(':', $settings->mg2_host);
                $settings->mg2_db_port = isset($hostInfo[1]) ? $hostInfo[1] : ini_get("mysqli.default_port");

                //check and alert when has changed in M2 database credentials
                if ($step->setting_data && ( ($settings->mg2_host != $oldSettings->mg2_host)
                    || ($settings->mg2_db_user != $oldSettings->mg2_db_user)
                    || ($settings->mg2_db_pass != $oldSettings->mg2_db_pass)
                    || ($settings->mg2_db_name != $oldSettings->mg2_db_name) )) //has changed M2 database credentials
                {
                    $step->setting_data = json_encode((array)$settings);

                    //update for config file of tool
                    $configFilePath = Yii::app()->basePath . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "db.php";
                    $configTplFilePath = Yii::app()->basePath . DIRECTORY_SEPARATOR . "config" . DIRECTORY_SEPARATOR . "db.tpl";
                    if (file_exists($configFilePath) && is_writable($configFilePath)) {
                        $configs = file_get_contents($configTplFilePath);
                        //Update M2 database credentials submit from setting from
                        $configs = str_replace('{MG2_HOST}', $settings->mg2_host, $configs);
                        $configs = str_replace('{MG2_DB_PORT}', $settings->mg2_db_port, $configs);
                        $configs = str_replace('{MG2_DB_NAME}', $settings->mg2_db_name, $configs);
                        $configs = str_replace('{MG2_DB_USER}', $settings->mg2_db_user, $configs);
                        $configs = str_replace('{MG2_DB_PASS}', $settings->mg2_db_pass, $configs);
                        $configs = str_replace('{MG2_TABLE_PREFIX}', $settings->mg2_db_prefix, $configs);

                        //save to config file
                        if (file_put_contents($configFilePath, $configs)) {
                            if ($step->save()) {
                                //alert message
                                Yii::app()->user->setFlash('note', Yii::t('frontend', "The latest Magento 2 database credentials have been automatically updated."));
                            }
                        }
                    }
                }

                //default set M1 host name as M2 database host name
                if (empty($settings->mg1_host)) { //if has not setting
                    $settings->mg1_host = $settings->mg2_host;
                }
            }
        }

        if (!isset($settings)) { //for other context
            $settings = (object)json_decode($step->setting_data);
        }

        $assignData = array(
            'step' => $step,
            'settings' => $settings
        );
        $this->render("setting", $assignData);
    }
}
