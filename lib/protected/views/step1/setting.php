<?php $this->pageTitle = $step->title . ' - ' . Yii::app()->name; ?>

<h2 class="page-header"><?php echo Yii::t('frontend', 'Migration Settings');?> <i class="material-icons">keyboard_arrow_right</i> <?php echo Yii::t('frontend', $step->title); ?> </h2>

<form class="frm-settings" data-toggle="validator" role="form" method="post" action="<?php echo UBMigrate::getSettingUrl($step->sorder); ?>">
    <div id="step-content">

        <?php $this->renderPartial('/base/_messages', array('step' => $step)); ?>

        <div class="message tip">
            <i class="material-icons">lightbulb_outline</i>
            <p><?php echo Yii::t('frontend', 'Specify source and target databases for the data migration.<br/>If you have a separate database host, you must enable a remote MySQL database connection to your Magento 1 database. See <a href="http://devdocs.magento.com/guides/v2.0/install-gde/prereq/mysql_remote.html" target="_blank"><strong>this guide</strong></a>.'); ?></p>
        </div>

        <div class="row">
            <div class="col-md-6">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title"><?php echo Yii::t('frontend', 'Source Database');?></h3>
                    </div>
                    <div class="panel-body">
                        <div class="form-group">
                            <select class="form-control" id="mg1-version" name="mg1_version">
                                <?php $options = UBMigrate::getMG1VersionOptions()?>
                                <?php foreach ($options as $value => $label):?>
                                    <option value="<?php echo $value; ?>" <?php echo (isset($settings->mg1_version) && $settings->mg1_version == $value) ? 'selected="selected"' : ''?>><?php echo $label; ?></option>
                                <?php endforeach; ?>
                            </select>
                            <label for="mg1-version" class="control-label"><?php echo Yii::t('frontend', 'Version');?></label>
                            <i class="material-icons">label</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control" id="mg1-host" name="mg1_host" value="<?php echo isset($settings->mg1_host) ? $settings->mg1_host : '' ?>" placeholder="localhost" required/>
                            <label for="mg1-host" class="control-label"><?php echo Yii::t('frontend', 'Host');?></label>
                            <i class="material-icons">language</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control numberOnly" id="mg1-db-port" name="mg1_db_port" value="<?php echo isset($settings->mg1_db_port) ? $settings->mg1_db_port : '' ?>" placeholder="Leave blank to use default port: <?php echo ini_get("mysqli.default_port"); ?>"/>
                            <label for="mg1-db-port" class="control-label"><?php echo Yii::t('frontend', 'Port');?></label>
                            <i class="material-icons">settings_ethernet</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control" id="mg1-db-user" name="mg1_db_user" value="<?php echo isset($settings->mg1_db_user) ? $settings->mg1_db_user : '' ?>" placeholder="username" required />
                            <label for="mg1-db-user" class="control-label"><?php echo Yii::t('frontend', 'Username');?></label>
                            <i class="material-icons">person</i>
                        </div>
                        <div class="form-group">
                            <input type="password" class="form-control" id="mg1-db-pass" name="mg1_db_pass" value="<?php echo isset($settings->mg1_db_pass) ? $settings->mg1_db_pass : '' ?>" placeholder="optional" />
                            <label for="mg1-db-pass" class="control-label"><?php echo Yii::t('frontend', 'Password');?></label>
                            <i class="material-icons">lock</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control" id="mg1-db-name" name="mg1_db_name" value="<?php echo isset($settings->mg1_db_name) ? $settings->mg1_db_name : '' ?>" placeholder="database name" required />
                            <label for="mg1-db-name" class="control-label"><?php echo Yii::t('frontend', 'Database Name');?></label>
                            <i class="material-icons">dns</i>
                        </div>
                        <div class="form-group">
                            <label for="mg1-db-prefix" class="control-label"><?php echo Yii::t('frontend', 'Table Prefix');?></label>
                            <input type="text" class="form-control" id="mg1-db-prefix" name="mg1_db_prefix" value="<?php echo isset($settings->mg1_db_prefix) ? $settings->mg1_db_prefix : '' ?>" placeholder="optional" />
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title"><?php echo Yii::t('frontend', 'Target Database');?></h3>
                    </div>
                    <div class="panel-body">
                        <div class="form-group">
                            <input type="text" class="form-control" readonly="readonly" onclick="event.preventDefault();return false;" id="mg2-version" name="mg2_version" value="Magento EE 2.0x" placeholder="Magento EE 2.0x" required/>
                            <label for="mg2-version" class="control-label"><?php echo Yii::t('frontend', 'Version');?></label>
                            <i class="material-icons">label</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control" readonly="readonly" onclick="event.preventDefault();return false;" id="mg2-host" name="mg2_host" value="<?php echo isset($settings->mg2_host) ? $settings->mg2_host : '' ?>" placeholder="localhost" required/>
                            <label for="mg2-host" class="control-label"><?php echo Yii::t('frontend', 'Host');?></label>
                            <i class="material-icons">language</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control numberOnly" readonly="readonly" onclick="event.preventDefault();return false;" id="mg2-db-port" name="mg2_db_port" value="<?php echo isset($settings->mg2_db_port) ? $settings->mg2_db_port : '' ?>" />
                             <label for="mg2-db-port" class="control-label"><?php echo Yii::t('frontend', 'Port');?></label>
                            <i class="material-icons">settings_ethernet</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control" readonly="readonly" onclick="event.preventDefault();return false;" id="mg2-db-user" name="mg2_db_user" value="<?php echo isset($settings->mg2_db_user) ? $settings->mg2_db_user : '' ?>" placeholder="username" required />
                            <label for="mg2-db-user" class="control-label"><?php echo Yii::t('frontend', 'Username');?></label>
                             <i class="material-icons">person</i>
                        </div>
                        <div class="form-group">
                            <input type="password" class="form-control" readonly="readonly" onclick="event.preventDefault();return false;" id="mg2-db-pass" name="mg2_db_pass" value="<?php echo isset($settings->mg2_db_pass) ? $settings->mg2_db_pass : '' ?>" placeholder="optional" />
                            <label for="mg2-db-pass" class="control-label"><?php echo Yii::t('frontend', 'Password');?></label>
                            <i class="material-icons">lock</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control" readonly="readonly" onclick="event.preventDefault();return false;" id="mg2-db-name" name="mg2_db_name" value="<?php echo isset($settings->mg2_db_name) ? $settings->mg2_db_name : '' ?>" placeholder="database name" required />
                            <label for="mg2-db-name" class="control-label"><?php echo Yii::t('frontend', 'Database Name');?></label>
                            <i class="material-icons">dns</i>
                        </div>
                        <div class="form-group">
                            <input type="text" class="form-control" readonly="readonly" onclick="event.preventDefault();return false;" id="mg2-db-prefix" name="mg2_db_prefix" value="<?php echo isset($settings->mg2_db_prefix) ? $settings->mg2_db_prefix : '' ?>" placeholder="optional" />
                            <label for="mg2-db-prefix" class="control-label"><?php echo Yii::t('frontend', 'Table Prefix');?></label>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Form Buttons-->
        <div class="step-controls">
            <?php if ($step->status == UBMigrate::STATUS_PENDING): ?>
                <button title="<?php echo Yii::t('frontend', 'Click to save settings and go to next step'); ?>" type="submit" id="step-<?php echo $step->sorder; ?>" class="btn btn-primary btn-lg need-validate-form"><span class="glyphicon glyphicon-save"></span> <?php echo Yii::t('frontend', 'Save & Continue'); ?></button>
            <?php else: ?>
                <button title="<?php echo Yii::t('frontend', 'Click to update settings and go to next step'); ?>" type="submit" id="step-<?php echo $step->sorder; ?>" class="btn btn-danger btn-lg need-validate-form"><span><?php echo Yii::t('frontend', 'Update & Continue'); ?></span> <i class="material-icons">arrow_forward</i></button>
                <!-- <a title="<?php echo Yii::t('frontend', 'Click to go next step'); ?>" href="<?php echo UBMigrate::getSettingUrl($step->sorder, true); ?>" class="btn btn-primary"><span class="glyphicon glyphicon-forward"></span> <?php echo Yii::t('frontend', 'Next'); ?></a> -->
            <?php endif; ?>
        </div>
        <!--// Form Buttons-->
    </div>
</form>
