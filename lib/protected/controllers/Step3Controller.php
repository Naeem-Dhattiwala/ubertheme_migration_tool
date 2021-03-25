<?php

include_once('BaseController.php');

/**
 * @todo: Product Attribute sets, Product Attribute Groups, Product Attributes migration
 *
 * Class Step3Controller
 */
class Step3Controller extends BaseController
{
    protected $stepIndex = 3;

    /**
     * @todo: Setting
     */
    public function actionSetting()
    {
        //get step object
        $step = UBMigrate::model()->find("id = {$this->stepIndex}");
        $result = UBMigrate::checkStep($step->sorder);
        if ($result['allowed']) {
            //get product entity type id
            $productEntityTypeId = UBMigrate::getM1EntityTypeIdByCode(UBMigrate::PRODUCT_TYPE_CODE);
            //get customer entity type id
            $customerEntityTypeId = UBMigrate::getM1EntityTypeIdByCode(UBMigrate::CUSTOMER_TYPE_CODE);
            //get customer address entity type id
            $customerAddressEntityTypeId = UBMigrate::getM1EntityTypeIdByCode(UBMigrate::CUSTOMER_ADDRESS_TYPE_CODE);

            //get all attribute sets in magento1
            $strEntityTypeIds = "{$productEntityTypeId},{$customerEntityTypeId},{$customerAddressEntityTypeId}";
            $attributeSets = Mage1AttributeSet::model()->findAll("entity_type_id IN ({$strEntityTypeIds}) ORDER BY attribute_set_id ASC");

            //Magento2 was not used some attributes
            $ignoreAttributeCodes = "'group_price', 'msrp_enabled'";

            //get all product attributes with ignore condition
            $criteria = new CDbCriteria(array(
                "order" => "is_user_defined DESC, attribute_id ASC",
                "condition" => "entity_type_id = {$productEntityTypeId} AND attribute_code NOT IN ({$ignoreAttributeCodes})"
            ));
            $attributes = Mage1Attribute::model()->findAll($criteria);

            //get all customer attributes
            $criteria = new CDbCriteria(array(
                "order" => "is_user_defined DESC, attribute_id ASC",
                "condition" => "entity_type_id = {$customerEntityTypeId}"
            ));
            $customerAttributes = Mage1Attribute::model()->findAll($criteria);

            //get all customer address attributes
            $criteria = new CDbCriteria(array(
                "order" => "is_user_defined DESC, attribute_id ASC",
                "condition" => "entity_type_id = {$customerAddressEntityTypeId}"
            ));
            $customerAddressAttributes = Mage1Attribute::model()->findAll($criteria);

            //check over max_input_vars setting
            $maxVars = (int)ini_get('max_input_vars');
            //calculate total vars in form
            $totalVars = sizeof($attributeSets) + sizeof($attributes) + sizeof($customerAttributes) + sizeof($customerAddressAttributes);
            $continue = true;
            if ($totalVars > $maxVars) {
                $continue = false;
                $msgNotice = Yii::t('frontend', 'The migration tool detects that you have %s1 variables. Please increase the max_input_vars param in your PHP settings (New value must be bigger than %s1) before continuing this step.', array("%s1" => $totalVars));
                Yii::app()->user->setFlash('note', $msgNotice);
            }

            if (Yii::app()->request->isPostRequest) {
                //get selected data ids
                $selectedAttrSetIds = Yii::app()->request->getParam('attribute_set_ids', array());
                $selectedAttrGroupIds = Yii::app()->request->getParam('attribute_group_ids', array());
                $selectedAttrIds = Yii::app()->request->getParam('attribute_ids', array());
                if ($selectedAttrSetIds AND $selectedAttrGroupIds AND $selectedAttrIds) {
                    //make setting data to save
                    $settingData = [
                        'attribute_set_ids' => $selectedAttrSetIds,
                        'attribute_group_ids' => $selectedAttrGroupIds,
                        'attribute_ids' => $selectedAttrIds
                    ];
                    $step->setting_data = base64_encode(serialize($settingData));
                    $step->status = UBMigrate::STATUS_SETTING;
                    //save settings data
                    if ($step->update()) {
                        //alert message
                        Yii::app()->user->setFlash('success', "Your settings have been saved successfully");
                        //get next step index
                        $stepIndex = ($this->stepIndex < UBMigrate::MAX_STEP_INDEX) ? ++$this->stepIndex : 1;
                        //go to next step
                        $this->redirect(UBMigrate::getSettingUrl($stepIndex));
                    }
                } else {
                    Yii::app()->user->setFlash('note', Yii::t('frontend', 'You have not selected data to migrate yet.'));
                }
            }

            $assignData = array(
                'step' => $step,
                'productEntityTypeId' => $productEntityTypeId,
                'attributeSets' => $attributeSets,
                'attributes' => $attributes,
                'customerAttributes' => $customerAttributes,
                'customerAddressAttributes' => $customerAddressAttributes,
                'continue' => $continue
            );
            $this->render("setting", $assignData);
        } else {
            Yii::app()->user->setFlash('note', Yii::t('frontend', "Reminder! You need to finish settings in the step #%s", array("%s" => ($result['back_step_index']))));
            $this->redirect($result['back_step_url']);
        }
    }

    /**
     * @todo: Run Migrate data
     */
    public function actionRun()
    {
        //get current step object
        $step = UBMigrate::model()->find("id = {$this->stepIndex}");
        $rs = [
            'step_status_text' => $step->getStepStatusText(),
            'step_index' => $this->stepIndex,
            'status' => 'fail',
            'message' => '',
            'errors' => '',
            'offset' => 0
        ];

        //check can run migrate data
        $check = $step->canRun();
        if ($check['allowed']) {
            //check run mode
            if ($this->runMode == 'rerun') {
                //reset current offset
                UBMigrate::updateCurrentOffset(Mage1AttributeSet::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1AttributeGroup::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1Attribute::model()->tableName(), 0, $this->stepIndex);
            }

            //get mapping stores
            $mappingStores = UBMigrate::getMappingData('core_store', 2);

            //get setting data
            $settingData = $step->getSettingData();
            $selectedAttrSetIds = (isset($settingData['attribute_set_ids'])) ? $settingData['attribute_set_ids'] : [];
            $selectedAttrGroupIds = (isset($settingData['attribute_group_ids'])) ? $settingData['attribute_group_ids'] : [];
            $selectedAttrIds = (isset($settingData['attribute_ids'])) ? $settingData['attribute_ids'] : [];

            //some variables for paging
            $max1 = $max2 = $max3 = $max4 = 0;
            $offset1 = $offset2 = $offset3 = $offset4 = 0;
            try {
                //start migrate data by settings
                if ($selectedAttrSetIds AND $selectedAttrGroupIds AND $selectedAttrIds) {
                    //get product entity type id
                    $productEntityTypeId = UBMigrate::getM1EntityTypeIdByCode(UBMigrate::PRODUCT_TYPE_CODE);
                    //get customer entity type id
                    $customerEntityTypeId = UBMigrate::getM1EntityTypeIdByCode(UBMigrate::CUSTOMER_TYPE_CODE);
                    //get customer address entity type id
                    $customerAddressEntityTypeId = UBMigrate::getM1EntityTypeIdByCode(UBMigrate::CUSTOMER_ADDRESS_TYPE_CODE);
                    $strEntityTypeIds = "{$productEntityTypeId},{$customerEntityTypeId},{$customerAddressEntityTypeId}";
                    $strSelectedAttrSetIds = implode(',', $selectedAttrSetIds);

                    /**
                     * Table: eav_attribute_set
                     * Migrating attribute sets
                     */
                    //build condition to get data
                    //$condition = "entity_type_id IN ({$strEntityTypeIds}) AND attribute_set_id IN ({$strSelectedAttrSetIds})";
                    $condition = "entity_type_id IN ({$strEntityTypeIds})";
                    //get max total
                    $max1 = Mage1AttributeSet::model()->count($condition);
                    $offset1 = UBMigrate::getCurrentOffset($this->stepIndex, Mage1AttributeSet::model()->tableName());
                    $attributeSets = UBMigrate::getListObjects('Mage1AttributeSet', $condition, $offset1, $this->limit, "attribute_set_id ASC");
                    if ($attributeSets) {
                        $this->_migrateAttributeSets($attributeSets);
                    }

                    if ($offset1 == 0) {
                        //log for first entry
                        Yii::log("Start running step #{$this->stepIndex}",'info', 'ub_data_migration');
                        //update status of this step to migrating
                        $step->updateStatus(UBMigrate::STATUS_MIGRATING);
                    }

                    /**
                     * Table: eav_attribute_group
                     * Migrating attribute groups
                     * We only start migrate attribute groups when migrated all attribute sets
                     */
                    if ($offset1 >= $max1) {
                        //condition to get data
                        $strSelectedAttrGroupIds = implode(',', $selectedAttrGroupIds);
                        $condition = "attribute_group_id IN ({$strSelectedAttrGroupIds})";
                        //get max total
                        $max2 = Mage1AttributeGroup::model()->count($condition);
                        $offset2 = UBMigrate::getCurrentOffset($this->stepIndex, Mage1AttributeGroup::model()->tableName());
                        //get data by limit and offset
                        $attributeGroups = UBMigrate::getListObjects('Mage1AttributeGroup', $condition, $offset2, $this->limit, "attribute_group_id ASC");
                        if ($attributeGroups) {
                            $this->_migrateAttributeGroups($attributeGroups);
                        }
                    }

                    /**
                     * Table: eav_attribute
                     * we only attributes when all attribute sets and attribute groups was migrated
                     */
                    if ($offset1 >= $max1 AND $offset2 >= $max2) {
                        //condition to get data
                        $strSelectedAttrIds = implode(',', $selectedAttrIds);
                        $entityTypeIds = "{$productEntityTypeId},{$customerEntityTypeId},{$customerAddressEntityTypeId}";
                        $condition = "entity_type_id IN ({$entityTypeIds}) AND attribute_id IN ({$strSelectedAttrIds})";
                        //get max total
                        $max3 = Mage1Attribute::model()->count($condition);
                        $offset3 = UBMigrate::getCurrentOffset($this->stepIndex, Mage1Attribute::model()->tableName());
                        //get data by limit and offset
                        $attributes = UBMigrate::getListObjects('Mage1Attribute', $condition, $offset3, $this->limit, "attribute_id ASC");
                        if ($attributes) {
                            $this->_migrateAttributes($attributes, $mappingStores);
                        }
                    }

                    /**
                     * Table: eav_entity_attribute
                     */
                    //if has migrated all attribute sets, attribute groups and attributes
                    if ($offset1 >= $max1 AND $offset2 >= $max2 AND $offset3 >= $max3) {
                        //migrate data in table eav_entity_attribute
                        $this->_migrateEavEntityAttribute($strEntityTypeIds, $strSelectedAttrSetIds, $strSelectedAttrGroupIds, $strSelectedAttrIds);
                    }
                }

                //make result to respond
                if ($this->errors) {
                    //update step status
                    $step->updateStatus(UBMigrate::STATUS_ERROR);
                    $rs['step_status_text'] = $step->getStepStatusText();

                    $strErrors = implode('<br/>', $this->errors);
                    $rs['errors'] = $strErrors;
                    Yii::log($rs['errors'], 'error', 'ub_data_migration');
                } else {
                    if ($offset1 >= $max1 AND $offset2 >= $max2 AND $offset3 >= $max3) {
                        //update status of this step to finished
                        if ($step->updateStatus(UBMigrate::STATUS_FINISHED)) {
                            //update current offset to max
                            UBMigrate::updateCurrentOffset(Mage1AttributeSet::model()->tableName(), $max1, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1AttributeGroup::model()->tableName(), $max2, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1Attribute::model()->tableName(), $max3, $this->stepIndex);

                            //fix some attribute settings
                            $this->_fixProductAttributeSettings();

                            //update result to respond
                            $rs['status'] = 'done';
                            $rs['percent_done'] = UBMigrate::getPercentByStatus(UBMigrate::STATUS_FINISHED, [1]);
                            $rs['step_status_text'] = $step->getStepStatusText();
                            $rs['message'] = Yii::t('frontend', "Step #%s migration completed successfully", array('%s' => $this->stepIndex));
                            Yii::log($rs['message']."\n", 'info', 'ub_data_migration');
                        }
                    } else {
                        //update current offset for next run
                        if ($max1) {
                            UBMigrate::updateCurrentOffset(Mage1AttributeSet::model()->tableName(), ($offset1 + $this->limit), $this->stepIndex);
                        }
                        if ($max2) { // has done with attribute sets
                            UBMigrate::updateCurrentOffset(Mage1AttributeGroup::model()->tableName(), ($offset2 + $this->limit), $this->stepIndex);
                        }
                        if ($max3) { // has done with attributes
                            UBMigrate::updateCurrentOffset(Mage1Attribute::model()->tableName(), ($offset3 + $this->limit), $this->stepIndex);
                        }

                        //start calculate percent run ok
                        $totalSteps = UBMigrate::getTotalStepCanRunMigrate();
                        $percentOfOnceStep = (1 / $totalSteps) * 100;
                        $max = ($max3) ? $max3 : (($max2) ? $max2 : $max1);
                        $n = ceil($max / $this->limit);
                        $percentUp = ($percentOfOnceStep / 3) / $n;
                        //end calculate percent run ok

                        //update result to respond
                        $rs['status'] = 'ok';
                        $rs['percent_up'] = $percentUp;
                        $msg = ($offset1 == 0) ? '[Processing] Step #%s migration completed with' : '[Processing] Step #%s migration completed with';
                        $data['%s'] = $this->stepIndex;
                        if (isset($attributeSets) AND $attributeSets) {
                            $msg .= ' %s1 Attribute Sets';
                            $data['%s1'] = sizeof($attributeSets);
                        }
                        if (isset($attributeGroups) AND $attributeGroups) {
                            $msg .= ' %s2 Attribute Groups';
                            $data['%s2'] = sizeof($attributeGroups);
                        }
                        if (isset($attributes) AND $attributes) {
                            $msg .= ' %s3 Attributes';
                            $data['%s3'] = sizeof($attributes);
                        }
                        $rs['message'] = Yii::t('frontend', $msg, $data);
                        Yii::log($rs['message'], 'info', 'ub_data_migration');
                    }
                }
            } catch (Exception $e) {
                //update step status
                $step->updateStatus(UBMigrate::STATUS_ERROR);
                $rs['step_status_text'] = $step->getStepStatusText();

                $rs['errors'] = $e->getMessage();
                Yii::log($rs['errors'], 'error', 'ub_data_migration');
            }

        } else {
            if ($step->status == UBMigrate::STATUS_PENDING) {
                $rs['notice'] = Yii::t('frontend', "Step #%s has no settings yet. Navigate back to the UI dashboard to check the setting for step #%s again", array('%s' => $this->stepIndex));
            } elseif ($step->status == UBMigrate::STATUS_SKIPPING) {
                $rs['status'] = 'done';
                $rs['notice'] = Yii::t('frontend', "You marked step #%s as skipped.", array('%s' => $this->stepIndex));
            } else {
                if (isset($check['required_finished_step_index'])) {
                    $rs['notice'] = Yii::t('frontend', "Reminder! Before migrating data in the step #%s1, you have to complete migration in the step #%s2", array('%s1' => $step->sorder, '%s2' => $check['required_finished_step_index']));
                }
            }
        }

        //respond result
        if ($this->isCLI) {
            return $rs;
        } else {
            echo json_encode($rs);
            Yii::app()->end();
        }
    }

    private function _migrateAttributeSets($attributeSets)
    {
        /**
         * Table: eav_attribute_set
         */
        foreach ($attributeSets as $attributeSet) {
            //we will change name of attribute set migrated from M1
            $attributeSetName2 = $attributeSet->attribute_set_name . UBMigrate::ATTR_SET_ENDFIX;
            $entityTypeId2 = UBMigrate::getM2EntityTypeIdById($attributeSet->entity_type_id);
            $m2Id = UBMigrate::getM2EntityId(3, 'eav_attribute_set', $attributeSet->attribute_set_id);
            $canReset = UBMigrate::RESET_YES;
            if (is_null($m2Id)) {
                $condition = "entity_type_id = {$entityTypeId2} AND attribute_set_name = '" . addslashes($attributeSetName2) . "'";
                $attributeSet2 = Mage2AttributeSet::model()->find($condition);
                if (!$attributeSet2) {
                    //add new
                    $attributeSet2 = new Mage2AttributeSet();
                    $attributeSet2->entity_type_id = $entityTypeId2;
                    $attributeSet2->attribute_set_name = $attributeSetName2;
                    $attributeSet2->sort_order = $attributeSet->sort_order;
                } else {
                    $canReset = UBMigrate::RESET_NO;
                }
            } else {
                //update
                $attributeSet2 = Mage2AttributeSet::model()->find("attribute_set_id = {$m2Id}");
                if ($attributeSet2) {
                    $attributeSet2->attribute_set_name = $attributeSetName2;
                    $attributeSet2->sort_order = $attributeSet->sort_order;
                }
            }
            //save/update
            if ($attributeSet2 && $attributeSet2->save()) {
                if (is_null($m2Id)) {
                    //update to map log
                    UBMigrate::log([
                        'entity_name' => $attributeSet->tableName(),
                        'm1_id' => $attributeSet->attribute_set_id,
                        'm2_id' => $attributeSet2->attribute_set_id,
                        'm2_model_class' => get_class($attributeSet2),
                        'm2_key_field' => 'attribute_set_id',
                        'can_reset' => $canReset,
                        'step_index' => $this->stepIndex
                    ]);
                }
                if ($canReset) { //is custom attribute set
                    //add needed core attribute group for this attribute set
                    $this->_fixAttributeSet($attributeSet2->attribute_set_id);
                }
                $this->_traceInfo();
            } else {
                $this->errors[] = get_class($attributeSet2) . ": " . UBMigrate::getStringErrors($attributeSet2->getErrors());
            }
        }

        return true;
    }

    private function _fixAttributeSet($attributeSetId2)
    {
        $condition = "attribute_set_id = {$attributeSetId2} AND attribute_group_code = 'bundle-items'";
        if (!Mage2AttributeGroup::model()->find($condition)) {
            $attributeGroup2 = new Mage2AttributeGroup();
            $attributeGroup2->attribute_set_id = $attributeSetId2;
            $attributeGroup2->attribute_group_name = 'Schedule Design Update';
            $attributeGroup2->attribute_group_code = 'schedule-design-update';
            $attributeGroup2->tab_group_code = 'advanced';
            $attributeGroup2->sort_order = 99;
            $attributeGroup2->save();
            //for Bundle Items group
            $attributeGroup2 = new Mage2AttributeGroup();
            $attributeGroup2->attribute_set_id = $attributeSetId2;
            $attributeGroup2->attribute_group_name = 'Bundle Items';
            $attributeGroup2->attribute_group_code = 'bundle-items';
            $attributeGroup2->tab_group_code = null;
            $attributeGroup2->sort_order = 100;
            $attributeGroup2->save();
        }

        return true;
    }

    private function _fixProductAttributeSettings()
    {
        //get product entity type
        $entityTypeId = UBMigrate::getM2EntityTypeIdByCode(UBMigrate::PRODUCT_TYPE_CODE);

        $groupsNeedFix = array(
            'product-details' => array(
                'status','name','sku','sku_type','price','price_type','tax_class_id',
                'quantity_and_stock_status','weight','weight_type','category_ids','visibility'),
            'bundle-items' => array('shipment_type'),
            'schedule-design-update' => array('custom_design_from', 'custom_design_to', 'custom_design', 'custom_layout')
        );
        //get product attribute sets from M2
        $attributeSets = Mage2AttributeSet::model()->findAll("entity_type_id = {$entityTypeId}");
        //check and update settings in the table eav_entity_attribute
        foreach ($attributeSets as $attributeSet) {
            foreach ($groupsNeedFix as $groupCode => $attributes) {
                $group2 = Mage2AttributeGroup::model()->find("attribute_set_id = {$attributeSet->attribute_set_id} AND attribute_group_code = '{$groupCode}'");
                if ($group2) {
                    foreach ($attributes as $key => $attributeCode) {
                        $attribute2 = UBMigrate::getMage2Attribute($attributeCode, $entityTypeId);
                        $condition = "entity_type_id = {$entityTypeId}";
                        $condition .= " AND attribute_set_id = {$attributeSet->attribute_set_id}";
                        $condition .= " AND attribute_id = {$attribute2->attribute_id}";
                        $setting = Mage2EntityAttribute::model()->find($condition);
                        if (!$setting) {
                            //add new
                            $setting = new Mage2EntityAttribute();
                            $setting->entity_type_id = $entityTypeId;
                            $setting->attribute_set_id = $attributeSet->attribute_set_id;
                            $setting->attribute_id = $attribute2->attribute_id;
                        }
                        $setting->attribute_group_id = $group2->attribute_group_id;
                        $setting->sort_order = $key;
                        //save/update
                        if (!$setting->save()) {
                            $this->errors[] = get_class($setting) . ": " . UBMigrate::getStringErrors($setting->getErrors());
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateAttributeGroups($attributeGroups)
    {
        /**
         * Table: eav_attribute_group
         */
        foreach ($attributeGroups as $attributeGroup) {
            $attributeSetId2 = UBMigrate::getM2EntityId($this->stepIndex, 'eav_attribute_set', $attributeGroup->attribute_set_id);
            $entityTypeCode1 = UBMigrate::getM1EntityTypeCode($attributeGroup->attribute_set_id);

            //We will change the name of Attribute Group migrated from Magento1
            $attributeGroupName2 = $attributeGroup->attribute_group_name;
            //NOTE: this values is new added in Magento2
            $attributeGroupCode2 = trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($attributeGroupName2)), '-');
            $tabGroupCode2 = null;

            if ($entityTypeCode1 == UBMigrate::PRODUCT_TYPE_CODE) {
                //we have to make some convert
                $attributeGroupCode2 = (preg_match("/(general)/i", $attributeGroupCode2)) ? 'product-details' : $attributeGroupCode2;
                $attributeGroupCode2 = (preg_match("/(prices)/i", $attributeGroupCode2)) ? 'advanced-pricing' : $attributeGroupCode2;
                $attributeGroupCode2 = (preg_match("/(design)/i", $attributeGroupCode2)) ? 'design' : $attributeGroupCode2;
                $attributeGroupCode2 = (preg_match("/(images)/i", $attributeGroupCode2)) ? 'image-management' : $attributeGroupCode2;
                $attributeGroupCode2 = (preg_match("/(meta-information)/i", $attributeGroupCode2)) ? 'search-engine-optimization' : $attributeGroupCode2;
                //tab group code
                $tabGroupCode2 = (preg_match("/(product-details|image-management|search-engine-optimization)/i", $attributeGroupCode2)) ? 'basic' : $tabGroupCode2;
                $tabGroupCode2 = (preg_match("/(advanced-pricing)/i", $attributeGroupCode2)) ? 'advanced' : $tabGroupCode2;
            }

            //check map
            $m2Id = UBMigrate::getM2EntityId($this->stepIndex, 'eav_attribute_group', $attributeGroup->attribute_group_id);
            $canReset = UBMigrate::RESET_YES;
            if (is_null($m2Id)) {
                $condition = "attribute_set_id = {$attributeSetId2} AND attribute_group_name = '" . addslashes($attributeGroupName2) . "'";
                $attributeGroup2 = Mage2AttributeGroup::model()->find($condition);
                if (!$attributeGroup2) {
                    //add new
                    $attributeGroup2 = new Mage2AttributeGroup();
                    $attributeGroup2->attribute_set_id = $attributeSetId2;
                    $attributeGroup2->attribute_group_name = $attributeGroupName2;
                    $attributeGroup2->attribute_group_code = $attributeGroupCode2;
                    $attributeGroup2->tab_group_code = $tabGroupCode2;
                    $attributeGroup2->sort_order = $attributeGroup->sort_order;
                    $attributeGroup2->default_id = $attributeGroup->default_id;
                } else {
                    $canReset = UBMigrate::RESET_NO;
                }
            } else {
                //update
                $attributeGroup2 = Mage2AttributeGroup::model()->find("attribute_group_id = {$m2Id}");
                if ($attributeGroup2) {
                    $attributeGroup2->attribute_group_name = $attributeGroupName2;
                    $attributeGroup2->attribute_group_code = $attributeGroupCode2;
                    $attributeGroup2->tab_group_code = $tabGroupCode2;
                    $attributeGroup2->sort_order = $attributeGroup->sort_order;
                }
            }
            //save/update
            if ($attributeGroup2 && $attributeGroup2->save()) {
                if (is_null($m2Id)) {
                    //update to map log
                    UBMigrate::log([
                        'entity_name' => $attributeGroup->tableName(),
                        'm1_id' => $attributeGroup->attribute_group_id,
                        'm2_id' => $attributeGroup2->attribute_group_id,
                        'm2_model_class' => get_class($attributeGroup2),
                        'm2_key_field' => 'attribute_group_id',
                        'can_reset' => $canReset,
                        'step_index' => $this->stepIndex
                    ]);
                }
                $this->_traceInfo();
            } else {
                $this->errors[] = get_class($attributeGroup2) . ": " . UBMigrate::getStringErrors($attributeGroup2->getErrors());
            }
        }

        return true;
    }

    private function _migrateAttributes($attributes, $mappingStores)
    {
        /**
         * Table: eav_attribute
         */
        foreach ($attributes as $attribute) {
            $m2Id = UBMigrate::getM2EntityId('3_attribute', 'eav_attribute', $attribute->attribute_id);
            $canReset = UBMigrate::RESET_YES;
            if (is_null($m2Id)) {
                $entityTypeId2 = UBMigrate::getM2EntityTypeIdById($attribute->entity_type_id);
                $condition = "entity_type_id = {$entityTypeId2} AND attribute_code = '{$attribute->attribute_code}'";
                $attribute2 = Mage2Attribute::model()->find($condition);
                if (!$attribute2) {
                    //add new
                    $attribute2 = new Mage2Attribute();
                    foreach ($attribute2->attributes as $key => $value) {
                        if (isset($attribute->$key)) {
                            $attribute2->$key = $attribute->$key;
                        }
                    }
                    //we don't take old value of attribute_id
                    $attribute2->attribute_id = null;
                    //we need re-update some other values
                    $attribute2->is_user_defined = 1;
                    $attribute2->attribute_model = null;
                    $attribute2->entity_type_id = $entityTypeId2;
                    $attribute2->frontend_model = UBMigrate::getM2FrontendModel($attribute->frontend_model);
                    $attribute2->backend_model = UBMigrate::getM2BackendModel($attribute->backend_model);
                    $attribute2->source_model = UBMigrate::getM2SourceModel($attribute->source_model);
                } else {
                    $canReset = UBMigrate::RESET_NO;
                    //we have update some values for some cases from M1 database.
                    if ($attribute->is_user_defined) {
                        $attribute2->backend_type = $attribute->backend_type;
                        $attribute2->backend_model = UBMigrate::getM2BackendModel($attribute->backend_model);
                    }
                }
            } else {
                $attribute2 = Mage2Attribute::model()->find("attribute_id = {$m2Id}");
                if ($attribute->is_user_defined) { // we only update label for custom attribute - coming soon
                    $attribute2->frontend_label = $attribute->frontend_label;
                }
                $attribute2->default_value = $attribute->default_value;
                $attribute2->is_required = $attribute->is_required;
            }
            //datetime type was converted to date type
            $attribute2->frontend_input = ($attribute2->frontend_input == 'datetime') ? 'date' : $attribute2->frontend_input;
            //save/update
            if (!$attribute2->save()) {
                $this->errors[] = get_class($attribute2) . ": " . UBMigrate::getStringErrors($attribute2->getErrors());
            } else {
                if (is_null($m2Id)) {
                    //update to map log
                    UBMigrate::log([
                        'entity_name' => $attribute->tableName(),
                        'm1_id' => $attribute->attribute_id,
                        'm2_id' => $attribute2->attribute_id,
                        'm2_model_class' => get_class($attribute2),
                        'm2_key_field' => 'attribute_id',
                        'can_reset' => $canReset,
                        'step_index' => "3Attribute"
                    ]);
                }
                $this->_traceInfo();
            }
            //start migrate Attribute EAV
            if ($attribute2->attribute_id) {
                /**
                 * Table: eav_attribute_label
                 */
                $this->_migrateAttributeLabels($attribute, $attribute2, $mappingStores);
                /**
                 * Table: eav_attribute_option
                 */
                $this->_migrateAttributeOptions($attribute, $attribute2, $mappingStores);
                /**
                 * Tables: catalog_eav_attribute, customer_eav_attribute
                 */
                $this->_migrateAttributeSettings($attribute, $attribute2);
            }
        }//end foreach attributes

        return true;
    }

    private function _migrateAttributeLabels($attribute, $attribute2, $mappingStores)
    {
        /**
         * Table: eav_attribute_label
         */
        $strMigratedStoreIds = implode(',', array_keys($mappingStores));
        $condition = "attribute_id = {$attribute->attribute_id} AND store_id IN ({$strMigratedStoreIds})";
        $attributeLabels = Mage1AttributeLabel::model()->findAll($condition);
        if ($attributeLabels) {
            foreach ($attributeLabels as $attributeLabel) {
                $storeId2 = $mappingStores[$attributeLabel->store_id];
                $condition = "attribute_id = {$attribute2->attribute_id} AND store_id = {$storeId2}";
                $attributeLabel2 = Mage2AttributeLabel::model()->find($condition);
                if (!$attributeLabel2) {
                    //add new
                    $attributeLabel2 = new Mage2AttributeLabel();
                    $attributeLabel2->attribute_id = $attribute2->attribute_id;
                    $attributeLabel2->store_id = $storeId2;
                    $attributeLabel2->value = $attributeLabel->value;
                } else {
                    //update
                    $attributeLabel2->value = $attributeLabel->value;
                }
                //save
                if (!$attributeLabel2->save()) {
                    $this->errors[] = get_class($attributeLabel2) . ": " . UBMigrate::getStringErrors($attributeLabel2->getErrors());
                } else {
                    $this->_traceInfo();
                }
            }
        }

        return true;
    }

    private function _migrateAttributeOptions($attribute, $attribute2, $mappingStores)
    {
        /**
         * Table: eav_attribute_option
         */
        $strMigratedStoreIds = implode(',', array_keys($mappingStores));
        $attributeOptions = Mage1AttributeOption::model()->findAll("attribute_id = {$attribute->attribute_id}");
        if ($attributeOptions) {
            foreach ($attributeOptions as $attributeOption) {
                $m2Id = UBMigrate::getM2EntityId('3_attribute_option', 'eav_attribute_option', $attributeOption->option_id);
                $canReset = UBMigrate::RESET_YES;
                if (is_null($m2Id)) {
                    //add new
                    $attributeOption2 = new Mage2AttributeOption();
                    $attributeOption2->attribute_id = $attribute2->attribute_id;
                    $attributeOption2->sort_order = $attributeOption->sort_order;
                } else { //update
                    $attributeOption2 = Mage2AttributeOption::model()->find("option_id = {$m2Id}");
                    $attributeOption2->sort_order = $attributeOption->sort_order;
                }
                //save/update
                if ($attributeOption2->save()) {
                    if (is_null($m2Id)) {
                        //update to map log
                        UBMigrate::log([
                            'entity_name' => $attributeOption->tableName(),
                            'm1_id' => $attributeOption->option_id,
                            'm2_id' => $attributeOption2->option_id,
                            'm2_model_class' => get_class($attributeOption2),
                            'm2_key_field' => 'option_id',
                            'can_reset' => $canReset,
                            'step_index' => "3AttributeOption"
                        ]);
                    }
                    $this->_traceInfo();
                } else {
                    $this->errors[] = get_class($attributeOption2) . ": " . UBMigrate::getStringErrors($attributeOption2->getErrors());
                }
                //start migrate attribute option values
                if ($attributeOption2->option_id) {
                    /**
                     * Table: eav_attribute_option_value
                     */
                    $condition = "option_id = {$attributeOption->option_id} AND store_id IN ({$strMigratedStoreIds})";
                    $optionValues = Mage1AttributeOptionValue::model()->findAll($condition);
                    if ($optionValues) {
                        foreach ($optionValues as $optionValue) {
                            $storeId2 = $mappingStores[$optionValue->store_id];
                            $optionValue2 = Mage2AttributeOptionValue::model()->find("option_id = {$attributeOption2->option_id} AND store_id = {$storeId2}");
                            if (!$optionValue2) {
                                //add new
                                $optionValue2 = new Mage2AttributeOptionValue();
                                $optionValue2->option_id = $attributeOption2->option_id;
                                $optionValue2->store_id = $storeId2;
                                $optionValue2->value = $optionValue->value;
                            } else {
                                //update
                                $optionValue2->value = $optionValue->value;
                            }
                            if (!$optionValue2->save()) {
                                $this->errors[] = get_class($optionValue2) . ": " . UBMigrate::getStringErrors($optionValue2->getErrors());
                            } else {
                                $this->_traceInfo();
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateAttributeSettings($attribute, $attribute2)
    {
        $entityTypeCode1 = UBMigrate::getM1EntityTypeCodeById($attribute->entity_type_id);
        if ($entityTypeCode1 == UBMigrate::PRODUCT_TYPE_CODE) {
            /**
             * Table: catalog_eav_attribute
             */
            $attributeSetting = Mage1CatalogEavAttribute::model()->find("attribute_id = {$attribute->attribute_id}");
            if ($attributeSetting) {
                $attributeSetting2 = Mage2CatalogEavAttribute::model()->find("attribute_id = {$attribute2->attribute_id}");
                if (!$attributeSetting2) {
                    //add new (a custom attribute)
                    $attributeSetting2 = new Mage2CatalogEavAttribute();
                    foreach ($attributeSetting2->attributes as $key => $value) {
                        if (isset($attributeSetting->$key)) {
                            $attributeSetting2->$key = $attributeSetting->$key;
                        }
                    }
                    //this is new field in Magento2. Default value is 0
                    $attributeSetting2->is_required_in_admin_store = 0;
                    //this was changed in Magento 2
                    $attributeSetting2->attribute_id = $attribute2->attribute_id;
                    $attributeSetting2->frontend_input_renderer = UBMigrate::getM2FrontendInputRenderer($attributeSetting2->frontend_input_renderer);
                    //because some new rules with configurable attribute in Magento 2
                    if ($attributeSetting->is_configurable) {
                        $attributeSetting2->apply_to = null;
                    }
                } else {
                    //update some values
                    //$attributeSetting2->is_visible = $attributeSetting->is_visible;
                    $attributeSetting2->is_searchable = $attributeSetting->is_searchable;
                    $attributeSetting2->is_filterable = $attributeSetting->is_filterable;
                    $attributeSetting2->is_html_allowed_on_front = $attributeSetting->is_html_allowed_on_front;
                    $attributeSetting2->is_filterable_in_search = $attributeSetting->is_filterable_in_search;
                    $attributeSetting2->used_in_product_listing = $attributeSetting->used_in_product_listing;
                    $attributeSetting2->used_for_sort_by = $attributeSetting->used_for_sort_by;
                    $attributeSetting2->is_comparable = $attributeSetting->is_comparable;
                    $attributeSetting2->is_global = $attributeSetting->is_global;
                    //because some new rules with configurable attribute in Magento 2
                    if ($attributeSetting->is_configurable) {
                        $attributeSetting2->apply_to = null;
                    }
                    $attributeSetting2->is_visible_on_front = $attributeSetting->is_visible_on_front;
                    $attributeSetting2->is_visible_in_advanced_search = $attributeSetting->is_visible_in_advanced_search;//can split here (coming soon)
                    $attributeSetting2->position = $attributeSetting->position;
                    $attributeSetting2->is_wysiwyg_enabled = $attributeSetting->is_wysiwyg_enabled;
                    $attributeSetting2->is_used_for_price_rules = $attributeSetting->is_used_for_price_rules;
                    $attributeSetting2->is_used_for_promo_rules = $attributeSetting->is_used_for_promo_rules;
                }
                //save/update
                if (!$attributeSetting2->save()) {
                    $this->errors[] = get_class($attributeSetting2) . ": " . UBMigrate::getStringErrors($attributeSetting2->getErrors());
                } else {
                    $this->_traceInfo();
                }
            }
        } else if (in_array($entityTypeCode1, array(UBMigrate::CUSTOMER_TYPE_CODE, UBMigrate::CUSTOMER_ADDRESS_TYPE_CODE))) {
            /**
             * Table: customer_eav_attribute
             */
            $attributeSetting = Mage1CustomerEavAttribute::model()->find("attribute_id = {$attribute->attribute_id}");
            if ($attributeSetting) {
                $attributeSetting2 = Mage2CustomerEavAttribute::model()->find("attribute_id = {$attribute2->attribute_id}");
                if (!$attributeSetting2) {
                    //add new (a custom attribute)
                    $attributeSetting2 = new Mage2CustomerEavAttribute();
                    foreach ($attributeSetting2->attributes as $key => $value) {
                        if (isset($attributeSetting->$key)) {
                            $attributeSetting2->$key = $attributeSetting->$key;
                        }
                    }
                    //this was changed in Magento 2
                    $attributeSetting2->attribute_id = $attribute2->attribute_id;
                } else {
                    //update some values if needed - coming soon
                }
                //save/update
                if (!$attributeSetting2->save()) {
                    $this->errors[] = get_class($attributeSetting2) . ": " . UBMigrate::getStringErrors($attributeSetting2->getErrors());
                } else {
                    $this->_traceInfo();
                }
            }
        }


        return true;
    }

    private function _migrateEavEntityAttribute($strEntityTypeIds, $strSelectedAttrSetIds, $strSelectedAttrGroupIds, $strSelectedAttrIds)
    {
        //get needed mapping data
        $mappingAttributeSets = UBMigrate::getMappingData('eav_attribute_set', 3);
        $mappingAttributeGroups = UBMigrate::getMappingData('eav_attribute_group', 3);
        $mappingAttributes = UBMigrate::getMappingData('eav_attribute', '3_attribute');
        /**
         * Table: eav_entity_attribute
         */
        $condition = "entity_type_id IN ({$strEntityTypeIds}) AND attribute_id IN ($strSelectedAttrIds)";
        $condition .= " AND attribute_set_id IN ({$strSelectedAttrSetIds})";
        $condition .= " AND attribute_group_id IN ({$strSelectedAttrGroupIds})";
        $entityAttributes = Mage1EntityAttribute::model()->findAll($condition);
        if ($entityAttributes) {
            foreach ($entityAttributes as $entityAttribute) {
                $entityTypeId2 = UBMigrate::getM2EntityTypeIdById($entityAttribute->entity_type_id);
                $attributeSetId2 = $mappingAttributeSets[$entityAttribute->attribute_set_id];
                $attributeGroupId2 = $mappingAttributeGroups[$entityAttribute->attribute_group_id];
                $attributeId2 = isset($mappingAttributes[$entityAttribute->attribute_id]) ? $mappingAttributes[$entityAttribute->attribute_id] : null;
                if ($attributeSetId2 AND $attributeGroupId2 AND $attributeId2) {
                    $condition = "attribute_id = {$attributeId2} AND attribute_group_id = {$attributeGroupId2}";
                    $entityAttribute2 = Mage2EntityAttribute::model()->find($condition);
                    if (!$entityAttribute2) {
                        $condition = "attribute_id = {$attributeId2} AND attribute_set_id = {$attributeSetId2}";
                        $entityAttribute2 = Mage2EntityAttribute::model()->find($condition);
                        if (!$entityAttribute2) {
                            //add new
                            $entityAttribute2 = new Mage2EntityAttribute();
                            //fill values
                            $entityAttribute2->entity_type_id = $entityTypeId2;
                            $entityAttribute2->attribute_set_id = $attributeSetId2;
                            $entityAttribute2->attribute_group_id = $attributeGroupId2;
                            $entityAttribute2->attribute_id = $attributeId2;
                            $entityAttribute2->sort_order = $entityAttribute->sort_order;
                            //save or update
                            if (!$entityAttribute2->save()) {
                                $this->errors[] = get_class($entityAttribute2) . ": " . UBMigrate::getStringErrors($entityAttribute2->getErrors());
                            } else {
                                $this->_traceInfo();
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _traceInfo()
    {
        if ($this->isCLI) {
            echo ".";
        }
    }

}
