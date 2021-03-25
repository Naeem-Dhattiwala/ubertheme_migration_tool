<?php

/**
 * This is the model class for table "{{ub_migrate_step}}".
 *
 * The followings are the available columns in table '{{ub_migrate_step}}':
 * @property string $id
 * @property string $title
 * @property string $code
 * @property integer $status
 * @property string $setting_data
 * @property string $start_at
 * @property string $end_at
 * @property string $descriptions
 * @property integer $sorder
 */
class UBMigrate extends CActiveRecord
{
    //step statuses
    const STATUS_PENDING = 0; //Pending
    const STATUS_SKIPPING = 1; //Skipping
    const STATUS_SETTING = 2; //Setting
    const STATUS_MIGRATING = 3; //Migrating data
    const STATUS_ERROR = 4; //Error
    const STATUS_FINISHED = 5; //Finished
    const STATUS_RESETTING = 6; //Resetting data

    //eav entity type const
    const CUSTOMER_TYPE_CODE = 'customer';
    const CUSTOMER_ADDRESS_TYPE_CODE = 'customer_address';
    const CATEGORY_TYPE_CODE = 'catalog_category';
    const PRODUCT_TYPE_CODE = 'catalog_product';
    const ORDER_TYPE_CODE = 'order';
    const INVOICE_TYPE_CODE = 'invoice';
    const CREDIT_MEMO_TYPE_CODE = 'creditmemo';
    const SHIPMENT_TYPE_CODE = 'shipment';

    //max step index
    const MAX_STEP_INDEX = 8;

    const SQL_COMMAND_DELIMETER = ';';

    const RESET_YES = 1;
    const RESET_NO = 0;

    const ATTR_SET_ENDFIX = " Migrated";
    const ATTR_GROUP_ENDFIX = " Migrated";

    public static $allowSkipSteps = [3, 4, 5, 6, 7, 8];

    public static $attributeFrontendModelMaps = [
        'eav/entity_attribute_backend_datetime' => 'Magento\Eav\Model\Entity\Attribute\Frontend\Datetime'
    ];

    public static $attributeBackendModelMaps = [
        'catalog/product_attribute_backend_boolean' => 'Magento\Catalog\Model\Product\Attribute\Backend\Boolean',
        'catalog/product_attribute_backend_price' => 'Magento\Catalog\Model\Product\Attribute\Backend\Price',
        'catalog/resource_eav_attribute' => 'Magento\Catalog\Model\ResourceModel\Eav\Attribute',
        'eav/entity_attribute_backend_array' => 'Magento\Eav\Model\Entity\Attribute\Backend\ArrayBackend',
        'eav/entity_attribute_backend_datetime' => 'Magento\Eav\Model\Entity\Attribute\Backend\Datetime'
    ];

    public static $attributeSourceModelMaps = [
        'eav/entity_attribute_source_table' => 'Magento\Eav\Model\Entity\Attribute\Source\Table',
        'eav/entity_attribute_source_boolean' => 'Magento\Eav\Model\Entity\Attribute\Source\Boolean'
    ];

    public static $frontendInputRenderer = [
        'giftmessage/adminhtml_product_helper_form_config' => 'Magento\GiftMessage\Block\Adminhtml\Product\Helper\Form\Config',
        'adminhtml/catalog_product_helper_form_msrp_price' => 'Magento\Msrp\Block\Adminhtml\Product\Helper\Form\Type\Price',
        'adminhtml/catalog_category_helper_sortby_default' => 'Magento\Catalog\Block\Adminhtml\Category\Helper\Sortby\DefaultSortby',
        'adminhtml/catalog_category_helper_sortby_available' => 'Magento\Catalog\Block\Adminhtml\Category\Helper\Sortby\Available',
        'adminhtml/catalog_category_helper_pricestep' => 'Magento\Catalog\Block\Adminhtml\Category\Helper\Pricestep'
    ];

    public static $promotionRuleModelMaps = [
        //salesrule
        'salesrule/rule_condition_product_found' => 'Magento\SalesRule\Model\Rule\Condition\Product\Found',
        'salesrule/rule_condition_product_subselect' => 'Magento\SalesRule\Model\Rule\Condition\Product\Subselect',
        'salesrule/rule_condition_product_combine' => 'Magento\SalesRule\Model\Rule\Condition\Product\Combine',
        'salesrule/rule_condition_product' => 'Magento\SalesRule\Model\Rule\Condition\Product',
        'salesrule/rule_condition_combine' => 'Magento\SalesRule\Model\Rule\Condition\Combine',
        'salesrule/rule_condition_address' => 'Magento\SalesRule\Model\Rule\Condition\Address',
        //catalogrule
        'catalogrule/rule_condition_combine' => 'Magento\CatalogRule\Model\Rule\Condition\Combine',
        'catalogrule/rule_condition_product' => 'Magento\CatalogRule\Model\Rule\Condition\Product',
        'catalogrule/rule_action_collection' => 'Magento\CatalogRule\Model\Rule\Action\Collection'
    ];

    /**
     * @return string the associated database table name
     */
    public function tableName()
    {
        return '{{ub_migrate_step}}';
    }

    /**
     * Returns the static model of the specified AR class.
     * Please note that you should have this exact method in all your CActiveRecord descendants!
     * @param string $className active record class name.
     * @return UBMigrate the static model class
     */
    public static function model($className = __CLASS__)
    {
        return parent::model($className);
    }

    public static function getToken()
    {
        $token = '';
        $configFile = Yii::app()->basePath . "/../../../app/etc/env.php";
        if (file_exists($configFile)) {
            $configData = require $configFile;
            $token = md5($configData['backend']['frontName'] . ":" . $configData['crypt']['key']);
        }

        return $token;
    }

    public static function getStartUrl()
    {
        return Yii::app()->createUrl("base/start", array('token' => self::getToken()));
    }

    public static function getSettingUrl($stepIndex = 1, $goNextStep = false)
    {
        if ($goNextStep) {
            if ($stepIndex < self::MAX_STEP_INDEX) {
                ++$stepIndex;
            } else {
                return self::getStartUrl();
            }
        }

        return Yii::app()->createUrl("step{$stepIndex}/setting", array('token' => self::getToken()));
    }

    public static function getRunUrl($stepIndex)
    {
        return Yii::app()->createUrl("step{$stepIndex}/run", array('token' => self::getToken()));
    }

    public static function getRerunUrl($stepIndex)
    {
        return Yii::app()->createUrl("step{$stepIndex}/run", array('rerun' => 1, 'token' => self::getToken()));
    }

    public static function getSkipUrl($stepIndex)
    {
        return Yii::app()->createUrl("base/skip/step/{$stepIndex}", array('token' => self::getToken()));
    }

    public static function getResetUrl($stepIndex)
    {
        return Yii::app()->createUrl("base/ajaxReset/step/{$stepIndex}", array('token' => self::getToken()));
    }

    public static function getResetAllUrl()
    {
        return Yii::app()->createUrl("base/resetAll", array('token' => self::getToken()));
    }

    public static function getLogUrl()
    {
        return Yii::app()->createUrl("base/updateLog", array('token' => self::getToken()));
    }

    public static function getPercentByStatus($statuses, $excludedIds = null)
    {
        $condition = '';
        if (!is_array($statuses) AND $statuses == self::STATUS_FINISHED) {
            $condition = 'status != ' . self::STATUS_SKIPPING;
        }
        if ($excludedIds) {
            $excludedIds = implode(',', $excludedIds);
            if ($condition)
                $condition .= " AND id NOT IN ({$excludedIds})";
            else
                $condition = " id NOT IN ({$excludedIds})";
        }
        //get total steps by statuses
        $totalSteps = self::model()->count($condition);

        if (is_array($statuses)) {
            $statuses = implode(',', $statuses);
            $condition = "status IN ({$statuses})";
        } else {
            $condition = "status = {$statuses}";
        }
        if ($excludedIds) {
            if ($condition)
                $condition .= " AND id NOT IN ({$excludedIds})";
            else
                $condition = " id NOT IN ({$excludedIds})";
        }
        //get total steps done by statuses
        $totalDone = self::model()->count($condition);
        //calculate percent done
        $percent = round(($totalDone / $totalSteps) * 100);

        return $percent;
    }

    public static function getNextSteps()
    {
        $step = null;
        $criteria = new CDbCriteria();
        $criteria->select = "t.sorder";
        $criteria->order = "t.sorder ASC";
        $criteria->condition = "status = " . self::STATUS_PENDING;
        $nextStep = self::model()->find($criteria);
        if ($nextStep) {
            $step = "step{$nextStep->sorder}";
        } else {
            $step = "step1";
        }

        return $step;
    }

    public static function checkStep($currentStepIndex = 1)
    {
        $result = array(
            'allowed' => true
        );
        $criteria = new CDbCriteria();
        $criteria->select = "t.sorder";
        $criteria->order = "t.sorder ASC";
        $criteria->condition = "t.sorder < {$currentStepIndex} AND status = " . self::STATUS_PENDING;
        $step = self::model()->find($criteria);
        if ($step) {
            $result['allowed'] = false;
            $result['back_step_index'] = $step->sorder;
            $result['back_step_url'] = self::getSettingUrl(($step->sorder));
        }

        return $result;
    }

    public function canRun()
    {
        $result = array(
            'allowed' => false
        );

        $requiredFinishedSteps = null;
        if ($this->sorder == 3 || $this->sorder == 4) { //attributes vs categories
            $requiredFinishedSteps = "2";
        } elseif ($this->sorder == 5) { //products
            $requiredFinishedSteps = "2, 3, 4";
        } elseif ($this->sorder == 6) { //customers
            $requiredFinishedSteps = "2, 3";
        } elseif ($this->sorder == 7) { //sales data
            $requiredFinishedSteps = "2, 3, 4, 5, 6";
        } elseif ($this->sorder == 8) { //other data
            $requiredFinishedSteps = "2, 3, 4, 5, 6";
        }
        $statusesCanRun = [self::STATUS_SETTING, self::STATUS_MIGRATING, self::STATUS_ERROR, self::STATUS_FINISHED];

        if (in_array($this->status, $statusesCanRun)) {
            $result['allowed'] = true;
            if ($requiredFinishedSteps) {
                $statuses = [self::STATUS_PENDING, self::STATUS_SETTING, self::STATUS_SKIPPING];
                $criteria = new CDbCriteria();
                $criteria->select = "t.sorder";
                $criteria->order = "t.sorder ASC";
                $criteria->condition = "t.sorder IN ({$requiredFinishedSteps}) AND status IN (".implode(',', $statuses).")";
                $step = self::model()->find($criteria);
                if ($step) {
                    $result['allowed'] = false;
                    $result['required_finished_step_index'] = $step->sorder;
                }
            }
        }

        return $result;
    }

    public static function canReset($currentStepIndex = 1)
    {
        $result = array(
            'allowed' => true
        );
        $criteria = new CDbCriteria();
        $criteria->select = "t.sorder";
        $criteria->order = "t.sorder DESC";
        $criteria->condition = "t.sorder > {$currentStepIndex} AND status = " . self::STATUS_FINISHED;
        $step = self::model()->find($criteria);
        if ($step) {
            $result['allowed'] = false;
            $result['back_step_index'] = $step->sorder;
            $result['back_step_url'] = self::getSettingUrl(($step->sorder));
        }

        return $result;
    }

    public function getStepStatusText()
    {
        $statuses = [
            self::STATUS_PENDING => '<span class="step-status pending">' . Yii::t('frontend', 'pending') . '</span>',
            self::STATUS_SKIPPING => '<span class="step-status skipped">' . Yii::t('frontend', 'skipped') . '</span>',
            self::STATUS_SETTING => '<span class="step-status setting">' . Yii::t('frontend', 'setting') . '</span>',
            self::STATUS_MIGRATING => '<span class="step-status processing">' . Yii::t('frontend', 'migrating...') . '</span>',
            self::STATUS_RESETTING => '<span class="step-status resetting">' . Yii::t('frontend', 'resetting...') . '</span>',
            self::STATUS_ERROR => '<span class="step-status error">' . Yii::t('frontend', 'error') . '</span>',
            self::STATUS_FINISHED => '<span class="step-status finished">' . Yii::t('frontend', 'finished') . '</span>'
        ];

        return $statuses[$this->status];
    }

    public function getStepStatusClassCSS()
    {
        $statuses = [
            self::STATUS_PENDING => 'pending',
            self::STATUS_SKIPPING => 'skipped',
            self::STATUS_SETTING => 'setting',
            self::STATUS_MIGRATING => 'migrating',
            self::STATUS_RESETTING => 'resetting',
            self::STATUS_ERROR => 'error',
            self::STATUS_FINISHED => 'finished'
        ];

        return $statuses[$this->status];
    }

    public function getSettingData()
    {
        $setting_data = null;
        if ($this->setting_data) {
            $setting_data = unserialize(base64_decode($this->setting_data));
        }

        return $setting_data;
    }

    public static function getSetting($stepIndex, $keyName)
    {
        $rs = [];
        if ($stepIndex) {
            $step = self::model()->find("sorder = {$stepIndex}");
            if ($step) {
                if ($step->setting_data){
                    $setting_data = unserialize(base64_decode($step->setting_data));
                    if (isset($setting_data[$keyName])) {
                        $rs = $setting_data[$keyName];
                    }
                }
            }
        }

        return $rs;
    }

    public static function updateSetting($stepIndex, $keyName, $data = array(), $replace = false)
    {
        $rs = false;
        if ($stepIndex) {
            $step = self::model()->find("sorder = {$stepIndex}");
            if ($step) {
                $settingData = unserialize(base64_decode($step->setting_data));

                if (!isset($settingData[$keyName])) $settingData[$keyName] = array();

                if ($replace) {
                    $settingData[$keyName] = $data;
                } else {
                    $settingData[$keyName] = array_merge($settingData[$keyName], $data);
                }
                //update
                $step->setting_data = base64_encode(serialize($settingData));
                $rs = $step->save();
            }
        }

        return $rs;
    }

    public function updateStatus($status)
    {
        $this->status = $status;
        if ($status == self::STATUS_MIGRATING) {
            $this->start_at = date('Y-m-d h:i:s');
        } else if ($status == self::STATUS_FINISHED) {
            $this->end_at = date('Y-m-d h:i:s');
        }

        return $this->update();
    }

    public static function getTotalStepCanRunMigrate()
    {
        return self::model()->count("code <> 'step1' AND status != " . self::STATUS_PENDING . " AND status != " . self::STATUS_SKIPPING);
    }

    public function resetData($limit = false)
    {
        $status = 'fail';
        $criteria = new CDbCriteria(array(
            'order' => 'id DESC',
        ));
        if ($limit) {
            $criteria->limit = $limit;
        }
        //get all entities was migrated in map log table of this step
        $className = "MappingStep{$this->sorder}";
        $list = $className::model()->findAll($criteria);
        if ($list) {
            //update step status
            if ($this->status != self::STATUS_RESETTING) {
                $this->updateStatus(self::STATUS_RESETTING);
            }

            foreach ($list as $model) {
                if ($model->can_reset == self::RESET_YES) {
                    //delete related magento 2 entity was migrated
                    $m2Model = new $model->m2_model_class();
                    $m2Model->deleteAll("{$model->m2_key_field} = {$model->m2_id}");
                    /**
                     * Because url_rewrite has not constraint with catalog_category_entity table and we don't mapping this table
                     */
                    if ($this->sorder == 4) { // if is categories migration step
                        if ($model->entity_name == 'catalog_category_entity') {
                            //delete related url rewrite
                            $con = "entity_type = 'category' AND entity_id = {$model->m2_id}";
                            Mage2UrlRewrite::model()->deleteAll($con);
                        }
                    }
                }

                //delete map model
                $model->delete();
                //only for trace in cli
                if (php_sapi_name() == "cli") {
                    echo ".";
                }
            }
            $status = 'ok';
        } else { // has done
            //we have to revert the old default website
            if ($this->sorder == 2) {
                //re-update default website
                $defaultWebsiteId = self::getSetting(2, 'default_website_id2');
                if ($defaultWebsiteId) {
                    $defaultWebsite = Mage2Website::model()->find("website_id = {$defaultWebsiteId}");
                    if ($defaultWebsite) {
                        $defaultWebsite->is_default = 1;
                        $defaultWebsite->update();
                        //re-update default root category id for default store group
                        $defaultStoreGroup = Mage2StoreGroup::model()->find("group_id = {$defaultWebsite->default_group_id}");
                        $oldRootCategoryId2 = self::getSetting(2, 'default_root_category_id2');
                        if ($defaultStoreGroup && $oldRootCategoryId2) {
                            $defaultStoreGroup->root_category_id = $oldRootCategoryId2;
                            $defaultStoreGroup->update();
                        }
                    }

                }
            }
            //reset step status and setting data
            $this->status = self::STATUS_PENDING;
            $this->start_at = null;
            $this->end_at = null;
            $this->setting_data = null;
            $this->update();
            $status = 'done';
        }

        return $status;
    }

    /**
     * Todo: For step 3 we have to special process
     * @param bool|false $limit
     * @return string
     * @throws CDbException
     */
    public function resetDataStep3($limit = false)
    {
        $status = 'fail';
        $criteria = new CDbCriteria(array(
            'order' => 'id DESC',
        ));
        if ($limit) {
            $criteria->limit = $limit;
        }
        //get all entities was migrated in map log table of this step
        $list = MappingStep3::model()->findAll($criteria);
        if (!$list) {
            $list = MappingStep3Attribute::model()->findAll($criteria);
            if (!$list) {
                $list = MappingStep3AttributeOption::model()->findAll($criteria);
            }
        }
        if (!$list) { //has done with all
            $status = 'done';
            //reset step status and setting data
            $this->status = self::STATUS_PENDING;
            $this->start_at = null;
            $this->end_at = null;
            $this->setting_data = null;
            $this->update();
        } else {
            if ($list) {
                //update step status
                if ($this->status != self::STATUS_RESETTING) {
                    $this->updateStatus(self::STATUS_RESETTING);
                }

                foreach ($list as $model) {
                    if ($model->can_reset == self::RESET_YES) {
                        //delete related magento 2 entity was migrated
                        $m2Model = new $model->m2_model_class();
                        $m2Model->deleteAll("{$model->m2_key_field} = {$model->m2_id}");
                    }
                    //delete map model
                    $model->delete();
                    //only for trace in cli
                    if (php_sapi_name() == "cli") {
                        echo ".";
                    }
                }
                $status = 'ok';
            }
        }

        return $status;
    }

    /**
     * Todo: For step 5 we have to special process
     * @param bool|false $limit
     * @return string
     * @throws CDbException
     */
    public function resetDataStep5($limit = false)
    {
        $status = 'fail';
        $criteria = new CDbCriteria(array(
            'order' => 'id DESC',
        ));
        if ($limit) {
            $criteria->limit = $limit;
        }
        //get all entities was migrated in map log table of this step
        $list = MappingStep5::model()->findAll($criteria);
        if (!$list) {
            $list = MappingStep5ProductDownload::model()->findAll($criteria);
            if (!$list) {
                $list = MappingStep5ProductOption::model()->findAll($criteria);
            }
        }
        if (!$list) { //has done with all
            $status = 'done';
            //reset step status and setting data
            $this->status = self::STATUS_PENDING;
            $this->start_at = null;
            $this->end_at = null;
            $this->setting_data = null;
            $this->update();
        } else {
            if ($list) {
                //update step status
                if ($this->status != self::STATUS_RESETTING) {
                    $this->updateStatus(self::STATUS_RESETTING);
                }

                foreach ($list as $model) {
                    if ($model->can_reset == self::RESET_YES) {
                        //delete related magento 2 entity was migrated
                        $m2Model = new $model->m2_model_class();
                        $m2Model->deleteAll("{$model->m2_key_field} = {$model->m2_id}");
                        /**
                         * Because some tables has not constraint with catalog_product_entity table and we don't mapping this table when migrating data
                         */
                        if ($model->entity_name == 'catalog_product_entity') {
                            //reset related url_rewrite
                            $con = "entity_type = 'product' AND entity_id = {$model->m2_id}";
                            Mage2UrlRewrite::model()->deleteAll($con);
                            //reset bestseller data
                            Mage2SalesBestsellersDaily::model()->deleteAll("product_id = {$model->m2_id}");
                            Mage2SalesBestsellersMonthly::model()->deleteAll("product_id = {$model->m2_id}");
                            Mage2SalesBestsellersYearly::model()->deleteAll("product_id = {$model->m2_id}");
                        }
                    }
                    //delete map model
                    $model->delete();
                    //only for trace in cli
                    if (php_sapi_name() == "cli") {
                        echo ".";
                    }
                }
                $status = 'ok';
            }
        }

        return $status;
    }

    /**
     * Todo: For step 6 we have to special process
     * @param bool|false $limit
     * @return string
     * @throws CDbException
     */
    public function resetDataStep6($limit = false)
    {
        $status = 'fail';
        $criteria = new CDbCriteria(array(
            'order' => 'id DESC',
        ));
        if ($limit) {
            $criteria->limit = $limit;
        }
        //get all entities was migrated in map log table of this step
        $list = MappingStep6::model()->findAll($criteria);
        if (!$list) {
            $list = MappingStep6CustomerAddress::model()->findAll($criteria);
        }
        if (!$list) { //has done with all
            $status = 'done';
            //reset step status and setting data
            $this->status = self::STATUS_PENDING;
            $this->start_at = null;
            $this->end_at = null;
            $this->setting_data = null;
            $this->update();
        } else {
            if ($list) {
                //update step status
                if ($this->status != self::STATUS_RESETTING) {
                    $this->updateStatus(self::STATUS_RESETTING);
                }

                foreach ($list as $model) {
                    if ($model->can_reset == self::RESET_YES) {
                        //delete related magento 2 entity was migrated
                        $m2Model = new $model->m2_model_class();
                        $m2Model->deleteAll("{$model->m2_key_field} = {$model->m2_id}");
                    }
                    //delete map model
                    $model->delete();
                    //only for trace in cli
                    if (php_sapi_name() == "cli") {
                        echo ".";
                    }
                }
                $status = 'ok';
            }
        }

        return $status;
    }

    /**
     * Todo: For step 6 we have to special process
     * @param bool|false $limit
     * @return string
     * @throws CDbException
     */
    public function resetDataStep7($limit = false)
    {
        $status = 'fail';
        $criteria = new CDbCriteria(array(
            'order' => 'id DESC',
        ));
        if ($limit) {
            $criteria->limit = $limit;
        }
        //get all entities was migrated in map log table of this step
        $list = MappingStep7::model()->findAll($criteria);
        if (!$list) {
            $list = MappingStep7Order::model()->findAll($criteria);
            if (!$list) {
                $list = MappingStep7OrderAddress::model()->findAll($criteria);
                if (!$list) {
                    $list = MappingStep7OrderItem::model()->findAll($criteria);
                    if (!$list) {
                        $list = MappingStep7Quote::model()->findAll($criteria);
                        if (!$list) {
                            $list = MappingStep7QuoteAddress::model()->findAll($criteria);
                            if (!$list) {
                                $list = MappingStep7QuoteItem::model()->findAll($criteria);
                                if (!$list) {
                                    $list = MappingStep7Invoice::model()->findAll($criteria);
                                    if (!$list) {
                                        $list = MappingStep7InvoiceItem::model()->findAll($criteria);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!$list) { //has done with all
            $status = 'done';
            //reset step status and setting data
            $this->status = self::STATUS_PENDING;
            $this->start_at = null;
            $this->end_at = null;
            $this->setting_data = null;
            $this->update();
        } else {
            if ($list) {
                //update step status
                if ($this->status != self::STATUS_RESETTING) {
                    $this->updateStatus(self::STATUS_RESETTING);
                }

                foreach ($list as $model) {
                    if ($model->can_reset == self::RESET_YES) {
                        //delete related magento 2 entity was migrated
                        $m2Model = new $model->m2_model_class();
                        $m2Model->deleteAll("{$model->m2_key_field} = {$model->m2_id}");

                        //because some tables has not constraint with main table and we have not mapping for these tables.
                        if ($model->entity_name == 'sales_flat_order') {
                            Mage2SalesOrderGrid::model()->deleteAll("entity_id = {$model->m2_id}");
                            Mage2SalesOrderTax::model()->deleteAll("order_id = {$model->m2_id}");
                            Mage2SalesInvoiceGrid::model()->deleteAll("order_id = {$model->m2_id}");
                            Mage2SalesShipmentGrid::model()->deleteAll("order_id = {$model->m2_id}");
                            Mage2SalesCreditmemoGrid::model()->deleteAll("order_id = {$model->m2_id}");
                        }
                    }
                    //delete map model
                    $model->delete();
                    //only for trace in cli
                    if (php_sapi_name() == "cli") {
                        echo ".";
                    }
                }
                $status = 'ok';
            }
        }

        return $status;
    }

    /**
     * Todo: For step 8 we have to special process
     * @param bool|false $limit
     * @return string
     * @throws CDbException
     */
    public function resetDataStep8($limit = false)
    {
        $status = 'fail';
        $criteria = new CDbCriteria(array(
            'order' => 'id DESC',
        ));
        if ($limit) {
            $criteria->limit = $limit;
        }
        //get all entities was migrated in map log table of this step
        $list = MappingStep8::model()->findAll($criteria);
        if (!$list) {
            $list = MappingStep8Review::model()->findAll($criteria);
            if (!$list) {
                $list = MappingStep8ReviewSummary::model()->findAll($criteria);
                if (!$list) {
                    $list = MappingStep8Rating::model()->findAll($criteria);
                    if (!$list) {
                        $list = MappingStep8Subscriber::model()->findAll($criteria);
                        if (!$list) {
                            $list = MappingStep8DownloadableLinkPurchased::model()->findAll($criteria);
                        }
                    }
                }
            }
        }
        if (!$list) { //has done with all
            $status = 'done';
            //reset step status and setting data
            $this->status = self::STATUS_PENDING;
            $this->start_at = null;
            $this->end_at = null;
            $this->setting_data = null;
            $this->update();
        } else {
            if ($list) {
                //update step status
                if ($this->status != self::STATUS_RESETTING) {
                    $this->updateStatus(self::STATUS_RESETTING);
                }
                foreach ($list as $model) {
                    if ($model->can_reset == self::RESET_YES) {
                        //delete related magento 2 entity was migrated
                        $m2Model = new $model->m2_model_class();
                        $m2Model->deleteAll("{$model->m2_key_field} = {$model->m2_id}");

                        //because some tables has not constraint with main table and we have not mapping for these tables.
                        if ($model->entity_name == 'catalogrule') {
                            Mage2CatalogruleProduct::model()->deleteAll("rule_id = {$model->m2_id}");
                        }
                    }
                    //delete map model
                    $model->delete();
                    //only for trace in cli
                    if (php_sapi_name() == "cli") {
                        echo ".";
                    }
                }
                $status = 'ok';
            }
        }

        return $status;
    }

    public static function getMage2AttributeSetId($mage1AttrSetId, $entityTypeCode = null)
    {
        $id = null;
        if (isset($mage1AttrSetId)) {
            $cacheId = "attribute_set_id2_{$mage1AttrSetId}_{$entityTypeCode}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $model1 = Mage1AttributeSet::model()->findByPk($mage1AttrSetId);
                if ($model1) {
                    if (!$entityTypeCode) {
                        $entityTypeCode = self::PRODUCT_TYPE_CODE;
                    }
                    $entityTypeId2 = self::getM2EntityTypeIdByCode($entityTypeCode);
                    if ($entityTypeCode == self::PRODUCT_TYPE_CODE) {
                        $attributeSetName2 = $model1->attribute_set_name . self::ATTR_SET_ENDFIX;
                    } else {
                        $attributeSetName2 = $model1->attribute_set_name;
                    }
                    $model2 = Mage2AttributeSet::model()->find("entity_type_id = {$entityTypeId2} AND attribute_set_name = '{$attributeSetName2}'");
                    if ($model2) {
                        $id = $model2->attribute_set_id;
                    }
                }
                //save to cache for later
                Yii::app()->cache->set($cacheId, $id, 86400); // one day
            } else {
                $id = $val;
            }
        }

        return $id;
    }

    public static function getMage2AttributeId($mage1AttrId, $entityTypeId = 3)
    {
        $id = null;
        if (isset($mage1AttrId)) {
            $cacheId = "attribute_id2_{$entityTypeId}_{$mage1AttrId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $attr1 = Mage1Attribute::model()->find("attribute_id = {$mage1AttrId}");
                if ($attr1) {
                    /**
                     * group_price and msrp_enabled attributes was removed in Magento 2
                     * and group_price data will convert to tier_price data
                     * so, we have to make this
                     */
                    if ($attr1->attribute_code == 'group_price')
                        $attribute_code2 = 'tier_price';
                    else
                        $attribute_code2 = $attr1->attribute_code;

                    $attr2 = Mage2Attribute::model()->find("entity_type_id = {$entityTypeId} AND attribute_code = '{$attribute_code2}'");
                    if ($attr2) {
                        $id = $attr2->attribute_id;
                    }
                }
                //save to cache for later
                Yii::app()->cache->set($cacheId, $id, 86400); // one day
            } else {
                $id = $val;
            }
        }

        return $id;
    }

    public static function getMage1AttributeCode($mage1AttrId)
    {
        $code = null;
        if (isset($mage1AttrId)) {
            $cacheId = "attribute_code1_{$mage1AttrId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $attr1 = Mage1Attribute::model()->findByPk($mage1AttrId);
                if ($attr1) {
                    $code = $attr1->attribute_code;
                }
                //save to cache for later
                Yii::app()->cache->set($cacheId, $code, 86400); // one day
            } else {
                $code = $val;
            }
        }

        return $code;
    }

    public static function getMage1AttributeId($mage1AttrCode, $entityTypeId)
    {
        $id = null;
        $attribute1 = self::getMage1Attribute($mage1AttrCode, $entityTypeId);
        if ($attribute1) {
            $id = $attribute1->attribute_id;
        }

        return $id;
    }

    public static function getMage1Attribute($attributeCode, $entityTypeId)
    {
        $attr1 = null;
        if ($attributeCode && $entityTypeId) {
            $cacheId = "m1_attribute_{$attributeCode}_{$entityTypeId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $attr1 = Mage1Attribute::model()->find("entity_type_id = {$entityTypeId} AND attribute_code = '{$attributeCode}'");
                //save to cache for later
                Yii::app()->cache->set($cacheId, $attr1, 86400); // one day
            } else {
                $attr1 = $val;
            }
        }

        return $attr1;
    }

    public static function getMage2Attribute($attributeCode, $entityTypeId)
    {
        $attr = null;
        if ($attributeCode && $entityTypeId) {
            $cacheId = "m2_attribute_{$attributeCode}_{$entityTypeId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $attr = Mage2Attribute::model()->find("entity_type_id = {$entityTypeId} AND attribute_code = '{$attributeCode}'");
                //save to cache for later
                Yii::app()->cache->set($cacheId, $attr, 86400); // one day
            } else {
                $attr = $val;
            }
        }

        return $attr;
    }

    public static function getMage1AttributeById($attributeId)
    {
        $attr1 = null;
        if ($attributeId) {
            $cacheId = "m1_attribute_id_{$attributeId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $attr1 = Mage1Attribute::model()->find("attribute_id = {$attributeId}");
                //save to cache for later
                Yii::app()->cache->set($cacheId, $attr1, 86400); // one day
            } else {
                $attr1 = $val;
            }
        }

        return $attr1;
    }

    public static function executeFile($filePath)
    {

        if (!isset($filePath)) return false;

        try {
            $tablePrefix = Yii::app()->db->tablePrefix;
            $tempLine = '';
            $lines = file($filePath);
            // Loop through each line
            foreach ($lines as $line) {
                // Skip it if it's a comment
                if (substr($line, 0, 2) == '--' || $line == '')
                    continue;
                // Add this line to the current segment
                $tempLine .= $line;
                // If it has a semicolon at the end, it's the end of the query
                if (substr(trim($line), -1, 1) == self::SQL_COMMAND_DELIMETER) {
                    //replace prefix
                    $tempLine = str_replace('#__', $tablePrefix, $tempLine);

                    // Perform the query
                    Yii::app()->db->createCommand($tempLine)->execute();

                    // Reset temp variable to empty
                    $tempLine = '';
                }
            }
        } catch (Exception $e) {
            throw $e;
        }

        return true;
    }

    public static function getMage1CategoryTree($parentId = 1)
    {
        $categories = array();
        $models = Mage1CatalogCategoryEntity::model()->findAll("parent_id = {$parentId}");
        if ($models) {
            foreach ($models as $model) {
                $category = array();
                $category['entity_id'] = $model->entity_id;
                $category['name'] = self::getMage1CategoryName($model->entity_id);
                $category['parent_id'] = $model->parent_id;
                $category['children'] = self::getMage1CategoryTree($category['entity_id']);
                $categories[$model->entity_id] = (object)$category;
            }
        }

        return $categories;
    }

    public static function generateCategoryTreeHtml($categoryTree, $selectedCategoryIds, $level = 1)
    {
        $gClass = ($level == 1) ? 'ver-nav' : '';
        $html = '<ul class="'.$gClass.'">';
        foreach ($categoryTree as $category) {
            //check has selected
            $checked = in_array($category->entity_id, $selectedCategoryIds) ? true : false;
            //check has migrated
            $m2Id = self::getM2EntityId(4, 'catalog_category_entity', $category->entity_id);
            //check for disable
            $disable = (UBMigrate::isMigrated(4) && $m2Id) ? 'class="read-only" readonly="readonly" onclick="event.preventDefault();"' : '';
            $html .= '<li class="'.(!empty($disable) ? 'read-only' : '').'">';
            $html .= '<input type="checkbox" ' . (($checked) ? "{$disable} checked" : '') . ' id="category_' . $category->entity_id . '" name="category_ids[]" value="' . $category->entity_id . '" /> ';
            $iconClass = ($level == 1 && $category->children) ? 'icon-folder-open' : (($category->children) ? 'icon-leaf' : '');
            $html .= '<span><i class="' . $iconClass . '"></i> ' . $category->name . '</span>';
            if ($m2Id) {
                $html .= '<i class="chip text-success">'.Yii::t('frontend', 'Migrated').'</i>';
            }
            if ($category->children) {
                $level++;
                $html .= self::generateCategoryTreeHtml($category->children, $selectedCategoryIds, $level);
            }
            $html .= '</li>';
        }
        $html .= '</ul>';

        return $html;
    }

    public static function getMage1CategoryName($categoryId)
    {
        $name = null;
        if ($categoryId) {
            $cacheId = "category_name1_{$categoryId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $entity_type_id = self::getM1EntityTypeIdByCode(self::CATEGORY_TYPE_CODE);
                $attribute_id = self::getMage1AttributeId('name', $entity_type_id);
                $model = Mage1CatalogCategoryEntityVarchar::model()->find("entity_id = {$categoryId} AND attribute_id = {$attribute_id}");
                if ($model) {
                    $name = $model->value;
                }
                //save to cache for later
                Yii::app()->cache->set($cacheId, $name, 86400); // one day
            } else {
                $name = $val;
            }
        }

        return $name;
    }

    public static function getM1EntityTypeCode($attributeSetId)
    {
        $entityTypeCode = null;
        $attributeSet1 = Mage1AttributeSet::model()->find("attribute_set_id = {$attributeSetId}");
        if ($attributeSet1) {
            $entityTypeCode = self::getM1EntityTypeCodeById($attributeSet1->entity_type_id);
        }

        return $entityTypeCode;
    }

    public static function getM1EntityTypeCodeById($entityTypeId)
    {
        $code = null;
        if ($entityTypeId) {
            $cacheId = "entity_type_code1_by_id_{$entityTypeId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db1;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT entity_type_code FROM {$tablePrefix}eav_entity_type WHERE entity_type_id = '{$entityTypeId}'";
                $code = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $code, 86400); // one day
            else:
                $code = $val;
            endif;
        }

        return $code;
    }

    public static function getM1EntityTypeIdByCode($entityTypeCode)
    {
        $id = null;
        if ($entityTypeCode) {
            $cacheId = "entity_type_id1_by_code_{$entityTypeCode}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db1;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT entity_type_id FROM {$tablePrefix}eav_entity_type WHERE entity_type_code = '{$entityTypeCode}'";
                $id = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $id, 86400); // one day
            else:
                $id = $val;
            endif;
        }

        return $id;
    }

    public static function getM2EntityTypeIdByCode($entityTypeCode)
    {
        $id = null;
        if ($entityTypeCode) {
            $cacheId = "entity_type_id2_by_code_{$entityTypeCode}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT entity_type_id FROM {$tablePrefix}eav_entity_type WHERE entity_type_code = '{$entityTypeCode}'";
                $id = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $id, 86400); // one day
            else:
                $id = $val;
            endif;
        }

        return $id;
    }

    public static function getM2EntityTypeIdById($entityTypeId1)
    {
        $id = null;
        if ($entityTypeId1) {
            $cacheId = "entity_type_id2_by_id1_{$entityTypeId1}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db1;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT entity_type_code FROM {$tablePrefix}eav_entity_type WHERE entity_type_id = {$entityTypeId1}";
                $entityTypeCode = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $entityTypeCode, 86400); // one day
            else:
                $entityTypeCode = $val;
            endif;

            if ($entityTypeCode) {
                $id = self::getM2EntityTypeIdByCode($entityTypeCode);
            }
        }

        return $id;
    }

    public static function getMage1ProductLinkTypeId($code)
    {
        $linkTypeId = null;
        $cacheId = "product_link_type_id1_by_code{$code}";
        $val = Yii::app()->cache->get($cacheId);
        if (!$val){
            $db = Yii::app()->db1;
            $tablePrefix = $db->tablePrefix;
            $query = "SELECT link_type_id FROM {$tablePrefix}catalog_product_link_type WHERE code = '{$code}'";
            $linkTypeId = $db->createCommand($query)->queryScalar();
            //save to cache for later
            Yii::app()->cache->set($cacheId, $linkTypeId, 86400); // one day
        } else {
            $linkTypeId = $val;
        }

        return $linkTypeId;
    }

    public static function getMage2ProductLinkTypeId($linkTypeId1)
    {
        $linkTypeId2 = null;
        $cacheId = "product_link_type_id2_by_id1_{$linkTypeId1}";
        $val = Yii::app()->cache->get($cacheId);
        if (!$val) {
            //get product link type form Magento 1
            $linkType1 = Mage1CatalogProductLinkType::model()->find("link_type_id = {$linkTypeId1}");
            if ($linkType1) {
                //get product link type in Magento 2 by code
                $linkType2 = Mage2CatalogProductLinkType::model()->find("code = '{$linkType1->code}'");
                if (!$linkType2) {
                    //add new
                    $linkType2 = new Mage2CatalogProductLinkType();
                    $linkType2->code = $linkType1->code;
                    $linkType2->save();
                }
                if ($linkType2->link_type_id) {
                    $linkTypeId2 = $linkType2->link_type_id;
                }
            }
            //save to cache for later
            Yii::app()->cache->set($cacheId, $linkTypeId2, 86400); // one day
        } else {
            $linkTypeId2 = $val;
        }

        return $linkTypeId2;
    }

    public static function getMage2ProductLinkAttrId($linkAttrId1)
    {
        $linkAttrId2 = null;
        $cacheId = "product_link_attr_id2_by_id1{$linkAttrId1}";
        $val = Yii::app()->cache->get($cacheId);
        if (!$val) {
            $model1 = Mage1CatalogProductLinkAttribute::model()->findByPk($linkAttrId1);
            if ($model1) {
                $linkTypeId2 = self::getMage2ProductLinkTypeId($model1->link_type_id);
                $condition = "link_type_id = {$linkTypeId2} AND product_link_attribute_code = '{$model1->product_link_attribute_code}'";
                $model2 = Mage2CatalogProductLinkAttribute::model()->find($condition);
                if (!$model2) {
                    //add more catalog_product_link_attribute
                    $model2 = new Mage2CatalogProductLinkAttribute();
                    $model2->link_type_id = $linkTypeId2;
                    $model2->product_link_attribute_code = $model1->product_link_attribute_code;
                    $model2->data_type = $model1->data_type;
                    $model2->save();
                }
                if ($model2->product_link_attribute_id) {
                    $linkAttrId2 = $model2->product_link_attribute_id;
                }
            }
            //save to cache for later
            Yii::app()->cache->set($cacheId, $linkAttrId2, 86400); // one day
        } else {
            $linkAttrId2 = $val;
        }

        return $linkAttrId2;
    }

    public static function getTotalProducts($strStoreIds, $productTypes)
    {
        $db = Yii::app()->db1;
        $tablePrefix = $db->tablePrefix;
        $strProductTypeIds = "'" . implode("','", $productTypes) . "'";

        $sql = "SELECT COUNT(DISTINCT e.entity_id) AS total FROM {$tablePrefix}catalog_product_entity e";
        $sql .= " LEFT JOIN {$tablePrefix}catalog_product_entity_int ei ON e.entity_id = ei.entity_id";
        $sql .= " WHERE ei.store_id IN ({$strStoreIds}) AND e.type_id IN ({$strProductTypeIds})";
        $total = $db->createCommand($sql)->queryScalar();

        return $total;
    }

    public static function getTotalProductsByType($type_id = 'simple', $strStoreIds)
    {
        $total = 0;
        if ($type_id) {
            $db = Yii::app()->db1;
            $tablePrefix = $db->tablePrefix;
            $sql = "SELECT COUNT(DISTINCT e.entity_id) AS total FROM {$tablePrefix}catalog_product_entity e";
            $sql .= " LEFT JOIN {$tablePrefix}catalog_product_entity_int ei ON e.entity_id = ei.entity_id";
            $sql .= " WHERE e.type_id = '{$type_id}' AND ei.store_id IN ({$strStoreIds})";
            $total = $db->createCommand($sql)->queryScalar();
        }

        return $total;
    }

    public static function getTotalCustomersByGroup($groupId = null, $strWebsiteIds, $strStoreIds)
    {
        $total = 0;
        if ($groupId) {
            $db = Yii::app()->db1;
            $tablePrefix = $db->tablePrefix;
            $sql = "SELECT COUNT(DISTINCT e.entity_id) AS total FROM {$tablePrefix}customer_entity e";
            $sql .= " WHERE e.group_id = {$groupId} AND (e.website_id IN ({$strWebsiteIds}) OR e.website_id IS NULL) AND e.store_id IN ({$strStoreIds})";
            $total = $db->createCommand($sql)->queryScalar();
        }

        return $total;
    }

    public static function getTotalCustomers($strWebsiteIds, $strStoreIds)
    {
        $db = Yii::app()->db1;
        $tablePrefix = $db->tablePrefix;
        $sql = "SELECT COUNT(DISTINCT e.entity_id) AS total FROM {$tablePrefix}customer_entity e";
        $sql .= " WHERE (e.website_id IN ({$strWebsiteIds}) OR e.website_id IS NULL) AND e.store_id IN ({$strStoreIds})";
        $total = $db->createCommand($sql)->queryScalar();

        return $total;
    }

    public static function getTotalVisibleProductsAttr()
    {
        $tablePrefix = Yii::app()->db1->tablePrefix;
        $entity_type_id = self::getM1EntityTypeIdByCode(self::PRODUCT_TYPE_CODE);
        $sql = "SELECT COUNT(*) FROM `{$tablePrefix}eav_attribute` e INNER JOIN `{$tablePrefix}catalog_eav_attribute` ce ON e.attribute_id = ce.attribute_id WHERE e.entity_type_id = {$entity_type_id} AND ce.is_visible = 1";
        $total = Yii::app()->db1->createCommand($sql)->queryScalar();

        return $total;
    }

    public static function getTotalSalesChildObject($objectId, $strStoreIds, $strCustomerIds)
    {
        $total = 0;
        $tablePrefix = Yii::app()->db1->tablePrefix;

        switch ($objectId) {
            case 'rule_coupon':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}salesrule`";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}salesrule_coupon`";
                $total2 = Yii::app()->db1->createCommand($sql)->queryScalar();
                $total = $total . " rules, " . $total2 . " coupons";
                break;
            case 'order_status':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_order_status`";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'order':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_flat_order` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                if ($strCustomerIds) {
                    $sql .= " AND (e.customer_id IN ({$strCustomerIds}) OR e.customer_id IS NULL)";
                }
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'quote':
                //$sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_flat_quote` e WHERE (e.store_id IN ({$str_store_ids}) OR e.store_id IS NULL) AND (e.customer_id IN ({$str_customer_ids}) OR e.customer_id IS NULL)";
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_flat_order` e INNER JOIN `{$tablePrefix}sales_flat_quote` sq ON  e.quote_id = sq.entity_id WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL) AND quote_id > 0";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'payment':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_flat_order_payment`";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'invoice':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_flat_invoice` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'shipment':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_flat_shipment` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                if ($strCustomerIds) {
                    $sql .= " AND (e.customer_id IN ({$strCustomerIds}) OR e.customer_id IS NULL)";
                }
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'credit':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_flat_creditmemo` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_order_aggregated_created':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_order_aggregated_created` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_order_aggregated_updated':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_order_aggregated_updated` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_refunded_aggregated':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_refunded_aggregated` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_refunded_aggregated_order':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_refunded_aggregated_order` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_invoiced_aggregated':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_invoiced_aggregated` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_invoiced_aggregated_order':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_invoiced_aggregated_order` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_shipping_aggregated':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_shipping_aggregated` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_shipping_aggregated_order':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_shipping_aggregated_order` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_bestsellers_aggregated_daily':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_bestsellers_aggregated_daily` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_bestsellers_aggregated_monthly':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_bestsellers_aggregated_monthly` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'sales_bestsellers_aggregated_yearly':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}sales_bestsellers_aggregated_yearly` e WHERE (e.store_id IN ({$strStoreIds}) OR e.store_id IS NULL)";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
        }

        return $total;
    }

    public static function getTotalItemOfObject($tableName)
    {
        $total = 0;
        $tablePrefix = Yii::app()->db1->tablePrefix;
        //build condition
        $con = [];
        if (!UBMigrate::getSetting(2, 'select_all_website')) {
            $selectedWebsiteIds = UBMigrate::getSetting(2, 'website_ids');
            $strWebsiteIds = implode(',', $selectedWebsiteIds);
            $con[] = "website_id IN ({$strWebsiteIds})";
        }
        if (!UBMigrate::getSetting(2, 'select_all_store')) {
            $selectedStoreIds = UBMigrate::getSetting(2, 'store_ids');
            $strStoreIds = implode(',', $selectedStoreIds);
        }
        /*if (!UBMigrate::getSetting(5, 'select_all_product')){
            $mappingProducts = UBMigrate::getMappingData('catalog_product_entity', 5);
            $strProductIds = implode(',', array_keys($mappingProducts));
            $con[] = "entity_id IN ({$strProductIds})";
        }*/
        if (!UBMigrate::getSetting(6, 'select_all_customer')) {
            $selectedCustomerGroupIds = UBMigrate::getSetting(6, 'customer_group_ids');
            if ($selectedCustomerGroupIds){
                $strCustomerGroupIds = implode(',', $selectedCustomerGroupIds);
                $con[] = "customer_group_id IN ({$strCustomerGroupIds})";
            }
        }
        $con = implode(' AND ', $con);

        switch ($tableName) {
            case 'core_email_template':
            case 'newsletter_template':
            case 'newsletter_queue':
            case 'newsletter_problem':
            case 'catalogrule':
            case 'review':
            case 'rating':
            case 'rating_option':
            case 'rating_option_vote':
            case 'rating_option_vote_aggregated':
            case 'tax_class':
            case 'tax_calculation_rule':
            case 'tax_calculation':
            case 'tax_calculation_rate':
            case 'tax_calculation_rate_title':
            case 'tax_order_aggregated_created':
            case 'tax_order_aggregated_updated':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}$tableName`";
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'newsletter_subscriber':
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}$tableName`";
                if (isset($strStoreIds)) {
                    $sql .= " WHERE store_id IN ({$strStoreIds}) OR store_id IS NULL";
                }
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
            case 'catalog_product_entity_group_price':
                $total = Mage1CatalogProductEntityGroupPrice::model()->count($con);
                break;
            case 'catalog_product_entity_tier_price':
                $total = Mage1CatalogProductEntityTierPrice::model()->count($con);
                break;
            case 'downloadable_link_purchased':
                $condition = null;
                if (!UBMigrate::getSetting(6, 'select_all_customer')) {
                    $mappingCustomers = UBMigrate::getMappingData('customer_entity', 6);
                    $strMigratedCustomerIds = implode(',', array_keys($mappingCustomers));
                    if ($strMigratedCustomerIds) {
                        $condition = "(customer_id IN ({$strMigratedCustomerIds}) OR customer_id IS NULL)";
                    }
                }
                $sql = "SELECT COUNT(*) FROM `{$tablePrefix}$tableName`";
                if ($condition) {
                    $sql .= " WHERE {$condition}";
                }
                $total = Yii::app()->db1->createCommand($sql)->queryScalar();
                break;
        }

        return $total;
    }

    public static function getMG1VersionOptions()
    {
        $options = array(
            'mage19x' => Yii::t('frontend', 'Magento ver.1.9.x'),
            'mage18x' => Yii::t('frontend', 'Magento ver.1.8.x'),
            'mage17x' => Yii::t('frontend', 'Magento ver.1.7.x'),
            'mage16x' => Yii::t('frontend', 'Magento ver.1.6.x')
        );
        return $options;
    }

    public static function getMG1Version()
    {
        $ver = NULL;
        $step = self::model()->findByPk(1);
        if ($step) {
            $settings = (object)json_decode($step->setting_data);
            $ver = $settings->mg1_version;
        }

        return $ver;
    }

    public static function getStringErrors($errors = array())
    {
        $strs = array();
        if ($errors) {
            foreach ($errors as $error) {
                foreach ($error as $strError) {
                    $strs[] = $strError;
                }
            }
        }
        $breakDownChar = (php_sapi_name() == "cli") ? "\n" : '<br/>';

        return implode("{$breakDownChar}- ", $strs);
    }

    public static function getListObjects($modelClass, $condition = '', $offset = -1, $limit = -1, $order = '') {
        $criteria = new CDbCriteria;
        $criteria->condition = $condition;
        $criteria->limit = $limit;
        $criteria->offset = $offset;
        $criteria->order = $order;

        return $modelClass::model()->findAll($criteria);
    }

    public static function makeMigrateReport(&$reportItems)
    {
        foreach ($reportItems as $entityName => $item) {
            $tablePrefix = Yii::app()->db->tablePrefix;
            $condition = "m1_id <> 0 AND m2_id <> 0";
            $condition .= " AND entity_name = '{$entityName}'";
            $tableName = "{$tablePrefix}{$item['map_table']}";
            $query = "SELECT count(DISTINCT `m1_id`) as total, `entity_name` FROM `{$tableName}` WHERE {$condition} GROUP BY `entity_name`";
            $totalMigrated = Yii::app()->db->createCommand($query)->queryScalar();
            $reportItems[$entityName]['migrated_total'] = (int)$totalMigrated;
            //get total in Magento 1
            /*$tablePrefix = Yii::app()->db1->tablePrefix;
            $tableName = "{$tablePrefix}{$entityName}";
            $query = "SELECT count(*) as total FROM `{$tableName}`";
            $totalMigrated = Yii::app()->db1->createCommand($query)->queryScalar();
            $reportItems[$entityName]['m1_total'] = $totalMigrated;*/
        }

        return true;
    }

    public static function getM2FrontendModel($m1Class)
    {
        return (isset(self::$attributeFrontendModelMaps[$m1Class])) ? self::$attributeFrontendModelMaps[$m1Class] : null;
    }

    public static function getM2BackendModel($m1Class)
    {
        return (isset(self::$attributeBackendModelMaps[$m1Class])) ? self::$attributeBackendModelMaps[$m1Class] : null;
    }

    public static function getM2SourceModel($m1Class)
    {
        return (isset(self::$attributeSourceModelMaps[$m1Class])) ? self::$attributeSourceModelMaps[$m1Class] : null;
    }

    public static function getM2FrontendInputRenderer($m1Class)
    {
        return (isset(self::$frontendInputRenderer[$m1Class])) ? self::$frontendInputRenderer[$m1Class] : null;
    }

    public static function log($data = [])
    {
        if ($data AND !is_null($data['m2_id'])) { //m1_id, m2_id can be 0
            $data['entity_name'] = str_replace(['{{', '}}'], ['', ''], $data['entity_name']);
            $className = "MappingStep{$data['step_index']}";
            $map = new $className();
            $map->entity_name = $data['entity_name'];
            $map->m1_id = $data['m1_id'];
            $map->m2_id = $data['m2_id'];
            $map->m2_model_class = $data['m2_model_class'];
            $map->m2_key_field = $data['m2_key_field'];
            $map->can_reset = $data['can_reset'];
            if (!$map->save()) {
                Yii::log(UBMigrate::getStringErrors($map->getErrors(),'error', 'ub_data_migration'));
            }
        }
    }

    public static function getM2EntityId($tableSuffix, $entityName, $m1Id)
    {
        if (!is_numeric($m1Id)) {
            return $m1Id;
        }
        $id = null;
        if (isset($tableSuffix) AND isset($entityName) AND isset($m1Id)) {
            $entityName = str_replace(['{{', '}}'], ['', ''], $entityName);
            $tablePrefix = Yii::app()->db->tablePrefix;
            $tableName = "{$tablePrefix}ub_migrate_map_step_{$tableSuffix}";
            //cache process
            $cacheId = "{$tableName}_{$entityName}_{$m1Id}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $query = "SELECT m2_id FROM {$tableName} WHERE m1_id = {$m1Id} AND entity_name = '{$entityName}' ORDER BY `id` DESC";
                $id = Yii::app()->db->createCommand($query)->queryScalar();
                if ($id !== FALSE) {
                    //save to cache for later
                    Yii::app()->cache->set($cacheId, $id, 86400); // 1 day
                } else {
                    $id = null;
                }
            } else {
                $id = $val;
            }
        }
        $id = (is_null($id)) ? $id : (int)$id;

        return $id;
    }

    public static function getM1EntityId($tableSuffix, $entityName, $m2Id)
    {
        $id = null;
        if (isset($tableSuffix) AND isset($entityName) AND isset($m2Id)) {
            $entityName = str_replace(['{{', '}}'], ['', ''], $entityName);
            $tablePrefix = Yii::app()->db->tablePrefix;
            $tableName = "{$tablePrefix}ub_migrate_map_step_{$tableSuffix}";
            //cache process
            $cacheId = "{$tableName}_{$entityName}_{$m2Id}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val) {
                $query = "SELECT m1_id FROM {$tableName} WHERE m2_id = {$m2Id} AND entity_name = '{$entityName}' ORDER BY `id` DESC";
                $id = Yii::app()->db->createCommand($query)->queryScalar();
                if ($id !== FALSE) {
                    //save to cache for later
                    Yii::app()->cache->set($cacheId, $id, 86400); // 1 day
                } else {
                    $id = null;
                }
            } else {
                $id = $val;
            }
        }
        $id = (is_null($id)) ? $id : (int)$id;

        return $id;
    }

    public static function getCurrentOffset($tableSuffix, $entityName)
    {
        $offset = 0;
        if (isset($tableSuffix) AND isset($entityName)) {
            $entityName = str_replace(['{{', '}}'], ['', ''], $entityName);
            $tablePrefix = Yii::app()->db->tablePrefix;
            $tableName = "{$tablePrefix}ub_migrate_map_step_{$tableSuffix}";
            $query = "SELECT MAX(offset) FROM {$tableName} WHERE entity_name = '{$entityName}'";
            $offset = Yii::app()->db->createCommand($query)->queryScalar();
        }

        return (int)$offset;
    }

    public static function updateCurrentOffset($entityName, $offset, $classEndfix = '')
    {
        if (isset($entityName) AND isset($offset) AND $classEndfix) {
            $entityName = str_replace(['{{', '}}'], ['', ''], $entityName);
            $className = "MappingStep{$classEndfix}";
            $map = $className::model()->find("entity_name = '{$entityName}'");
            if ($map) {
                $map->offset = $offset;
            } else {
                $map = new $className();
                $map->entity_name = $entityName;
                $map->m1_id = -1;
                $map->m2_id = -1;
                $map->m2_model_class = 'unknown';
                $map->m2_key_field = 'unknown';
                $map->can_reset = 0;
                $map->offset = $offset;
            }
            return $map->save();
        } else {
            return false;
        }
    }

    public static function getMappingData($entityName, $tableSuffix)
    {
        $data = [];
        if ($entityName AND $tableSuffix) {
            $tablePrefix = Yii::app()->db->tablePrefix;
            $tableName = "{$tablePrefix}ub_migrate_map_step_{$tableSuffix}";
            $query = "SELECT `m1_id`,`m2_id` FROM `{$tableName}` WHERE `entity_name` = '{$entityName}' ORDER BY `id` ASC";
            $command = Yii::app()->db->createCommand($query);
            $items = $command->queryAll();
            if ($items) {
                foreach ($items as $item) {
                    $data[$item['m1_id']] = $item['m2_id'];
                }
            }
        }

        return $data;
    }

    public static function getMigratedEntityIds($entityName, $tableSuffix)
    {
        $strIds = '';
        $mappingData = self::getMappingData($entityName, $tableSuffix);
        if ($mappingData) {
            $strIds = implode(',', array_keys($mappingData));
        }

        return $strIds;
    }

    public static function convertConditions(&$conditions)
    {
        foreach ($conditions as $key => $condition) {
            //convert type
            if (isset($condition['type']) AND $condition['type']) {
                self::convertConditionType($condition['type']);
            }
            //convert attribute
            if (isset($condition['attribute']) AND $condition['attribute']) {
                self::convertValueOfAttribute($condition['attribute'], $condition['value']);
            }
            //convert condition level 2 -> n
            if (isset($condition['conditions']) AND $condition['conditions']) {
                self::convertConditions($condition['conditions']);
            }
            //update
            $conditions[$key] = $condition;
        }

        return true;
    }

    public static function convertConditionType(&$conditionType)
    {
        if (isset(self::$promotionRuleModelMaps[$conditionType])) {
            $conditionType = self::$promotionRuleModelMaps[$conditionType];
        } else {
            Yii::log("Model class has not mapping in condition of promotion rule(salesrule/catalogrule): {$conditionType}", 'info', 'ub_data_migration');
        }

        return true;
    }

    public static function convertValueOfAttribute($attributeCode, &$value)
    {
        if ($attributeCode == 'category_ids') {
            $catIds = preg_split('/,\s*/', $value);
            foreach ($catIds as $key4 => $catId) {
                if ($catId) {
                    $catIds[$key4] = self::getM2EntityId(4, 'catalog_category_entity', $catId);
                }
            }
            $value = implode(',', $catIds);
        } elseif ($attributeCode == 'attribute_set_id') {
            if ($value) {
                $value = self::getM2EntityId(3, 'eav_attribute_set', $value);
            }
        } else {
            /**
             * check for case attribute with front-end input is 'select' options
             * we have convert value (attribute option_id)
             */
            $productEntityTypeId = self::getM1EntityTypeIdByCode(UBMigrate::PRODUCT_TYPE_CODE);
            $attribute1 = self::getMage1Attribute($attributeCode, $productEntityTypeId);
            if ($attribute1) {
                $find = Mage1AttributeOption::model()->count("attribute_id = {$attribute1->attribute_id}");
                if ($find AND $value) {
                    //get back new option_id
                    if (is_array($value)) {
                        foreach ($value as $k => $v) {
                            if (is_numeric($v)) {
                                $value[$k] = self::getM2EntityId('3_attribute_option', 'eav_attribute_option', $v);
                            }
                        }
                    } else {
                        $value = self::getM2EntityId('3_attribute_option', 'eav_attribute_option', $value);
                    }
                }
            }
        }

        return true;
    }

    public static function isSerialized($value, &$result = null)
    {
        // Bit of a give away this one
        if (!is_string($value))
        {
            return false;
        }
        // Serialized false, return true. unserialize() returns false on an
        // invalid string or it could return false if the string is serialized
        // false, eliminate that possibility.
        if ($value === 'b:0;')
        {
            $result = false;
            return true;
        }
        $length	= strlen($value);
        $end	= '';
        switch ($value[0])
        {
            case 's':
                if ($value[$length - 2] !== '"')
                {
                    return false;
                }
            case 'b':
            case 'i':
            case 'd':
                // This looks odd but it is quicker than isset()ing
                $end .= ';';
            case 'a':
            case 'O':
                $end .= '}';
                if ($value[1] !== ':')
                {
                    return false;
                }
                switch ($value[2])
                {
                    case 0:
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                    case 7:
                    case 8:
                    case 9:
                        break;
                    default:
                        return false;
                }
            case 'N':
                $end .= ';';
                if ($value[$length - 1] !== $end[0])
                {
                    return false;
                }
                break;
            default:
                return false;
        }
        if (($result = @unserialize($value)) === false)
        {
            $result = null;
            return false;
        }
        return true;
    }

    public static function getM1ReviewEntityCode($reviewEntityId)
    {
        $code = null;
        if ($reviewEntityId) {
            $cacheId = "review_entity_code_by_id_{$reviewEntityId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db1;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT entity_code FROM {$tablePrefix}review_entity WHERE entity_id = {$reviewEntityId}";
                $code = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $code, 86400); // one day
            else:
                $code = $val;
            endif;
        }

        return trim($code);
    }

    public static function getM2ReviewEntityId($reviewEntityCode)
    {
        $id = null;
        if ($reviewEntityCode) {
            $cacheId = "review_entity_id_by_code_{$reviewEntityCode}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT entity_id FROM {$tablePrefix}review_entity WHERE entity_code = '{$reviewEntityCode}'";
                $id = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $id, 86400); // one day
            else:
                $id = $val;
            endif;
        }

        return $id;
    }

    public static function getM1ReviewStatusCode($reviewStatusId)
    {
        $code = null;
        if ($reviewStatusId) {
            $cacheId = "review_status_code_by_id_{$reviewStatusId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db1;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT status_code FROM {$tablePrefix}review_status WHERE status_id = {$reviewStatusId}";
                $code = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $code, 86400); // one day
            else:
                $code = $val;
            endif;
        }

        return trim($code);
    }

    public static function getM2ReviewStatusId($reviewStatusCode)
    {
        $id = null;
        if ($reviewStatusCode) {
            $cacheId = "review_status_id_by_code_{$reviewStatusCode}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT status_id FROM {$tablePrefix}review_status WHERE status_code = '{$reviewStatusCode}'";
                $id = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $id, 86400); // one day
            else:
                $id = $val;
            endif;
        }

        return $id;
    }

    public static function getM1RatingEntityCode($ratingEntityId)
    {
        $code = null;
        if ($ratingEntityId) {
            $cacheId = "rating_entity_code_by_id_{$ratingEntityId}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db1;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT entity_code FROM {$tablePrefix}rating_entity WHERE entity_id = {$ratingEntityId}";
                $code = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $code, 86400); // one day
            else:
                $code = $val;
            endif;
        }

        return trim($code);
    }

    public static function getM2RatingEntityId($ratingEntityCode)
    {
        $id = null;
        if ($ratingEntityCode) {
            $cacheId = "rating_entity_id_by_code_{$ratingEntityCode}";
            $val = Yii::app()->cache->get($cacheId);
            if (!$val):
                $db = Yii::app()->db;
                $tablePrefix = $db->tablePrefix;
                $query = "SELECT entity_id FROM {$tablePrefix}rating_entity WHERE entity_code = '{$ratingEntityCode}'";
                $id = $db->createCommand($query)->queryScalar();
                //save to cache for later
                Yii::app()->cache->set($cacheId, $id, 86400); // one day
            else:
                $id = $val;
            endif;
        }

        return $id;
    }

    public static function isMigrated($stepIndex)
    {
        $isMigrated = false;
        if ($stepIndex) {
            $tablePrefix = Yii::app()->db->tablePrefix;
            $tableName = "{$tablePrefix}ub_migrate_map_step_{$stepIndex}";
            $query = "SELECT COUNT(`m2_id`) FROM `{$tableName}` WHERE `m2_id` > 0 ORDER BY `id` ASC";
            $count = Yii::app()->db->createCommand($query)->queryScalar();
            $isMigrated = ($count > 0) ? true : false;
        }

        return $isMigrated;
    }

    public static function getM2Version()
    {
        $version = '';
        $composerFile = Yii::app()->basePath . "/../../../composer.json";
        if (file_exists($composerFile)) {
            $data = @file_get_contents($composerFile);
            $data = json_decode($data);
            if (isset($data->version)) {
                $version = trim($data->version);
            }
        }

        return $version;
    }

    public static function encodeJson($value)
    {
        $storedPrecision = ini_get('precision');
        $storedSerializePrecision = ini_get('serialize_precision');

        if (PHP_VERSION_ID < 70100) {
            // In PHP version < 7.1.0 json_encode() uses EG(precision).
            ini_set('precision', 17);
        } else {
            // In PHP version >= 7.1.0 json_encode() uses PG(serialize_precision).
            ini_set('serialize_precision', 17);
        }

        $value = json_encode($value);

        ini_set('precision', $storedPrecision);
        ini_set('serialize_precision', $storedSerializePrecision);

        if (json_last_error()) {
            throw new Exception(json_last_error_msg());
        }

        return $value;
    }

    protected function isValidJsonValue($value)
    {
        if (in_array($value, ['null', 'false', '0', '""', '[]'])
            || (json_decode($value) !== null && json_last_error() === JSON_ERROR_NONE)
        ) {
            return true;
        }
        //JSON last error reset
        json_encode([]);
        return false;
    }

    public static function mb_unserialize($string)
    {
        $string = preg_replace_callback(
            '!s:(\d+):"(.*?)";!s',
            function ($matches) {
                if ( isset( $matches[2] ) )
                    return 's:'.strlen($matches[2]).':"'.$matches[2].'";';
            },
            $string
        );
        return @unserialize($string);
    }
}
