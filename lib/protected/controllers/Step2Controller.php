<?php

include_once('BaseController.php');

/**
 * @todo: Websites, Store Groups and Stores Migration
 *
 * Class Step2Controller
 */
class Step2Controller extends BaseController
{
    protected $stepIndex = 2;
    protected $websites2 = [];
    protected $storeGroups2 = [];

    /**
     * @todo: Setting
     */
    public function actionSetting()
    {
        //get step object
        $step = UBMigrate::model()->find("id = {$this->stepIndex}");
        $result = UBMigrate::checkStep($step->sorder);
        if ($result['allowed']) {

            //get list front-end websites from magento1 and exclude the admin website
            $condition = "code <> 'admin'";
            $websites = Mage1Website::model()->findAll($condition);

            if (Yii::app()->request->isPostRequest) {
                //get selected data ids
                $selectedWebsiteIds = Yii::app()->request->getParam('website_ids', array());
                $selectedStoreGroupIds = Yii::app()->request->getParam('store_group_ids', array());
                $selectedStoreIds = Yii::app()->request->getParam('store_ids', array());
                $selectAll = Yii::app()->request->getParam('select_all', false);
                $isMergeDefaultWebsite = Yii::app()->request->getParam('is_merge_default_website', 0);
                if ($selectedWebsiteIds AND $selectedStoreGroupIds AND $selectedStoreIds) {
                    //add admin website id
                    array_push($selectedWebsiteIds, '0');
                    //add store group admin
                    array_push($selectedStoreGroupIds, '0');
                    //add admin store id
                    array_push($selectedStoreIds, '0');

                    //get current default website in M1
                    $defaultWebsite1 = Mage1Website::model()->find("is_default = 1");

                    //get current default website in M2
                    $defaultWebsite2 = Mage2Website::model()->find("is_default = 1");

                    //get current default Store Group in M2
                    $defaultStoreGroup2 = Mage2StoreGroup::model()->find("group_id = {$defaultWebsite2->default_group_id}");

                    //save settings data
                    $totalStore = Mage1Store::model()->count();
                    $settingData = [
                        'website_ids' => $selectedWebsiteIds,
                        'store_group_ids' => $selectedStoreGroupIds,
                        'store_ids' => $selectedStoreIds,
                        'select_all' => $selectAll,
                        'select_all_website' => ((sizeof($selectedWebsiteIds) - 1) == sizeof($websites)) ? 1 : 0,
                        'select_all_store' => (sizeof($selectedStoreIds) == $totalStore) ? 1 : 0,
                        'default_website_id1' => $defaultWebsite1->website_id,
                        'default_website_id2' => $defaultWebsite2->website_id,
                        'default_root_category_id2' => $defaultStoreGroup2->root_category_id,
                        'is_merge_default_website' => $isMergeDefaultWebsite,
                        'store_need_update_root_cat_ids' => array()
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
                    Yii::app()->user->setFlash('note', Yii::t('frontend', 'You must select at least one website, one store group, one store to migrate'));
                }
            }

            $assignData = array(
                'step' => $step,
                'websites' => $websites,
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
            try {
                //check run mode
                if ($this->runMode == 'rerun') {
                    //reset current offset
                    UBMigrate::updateCurrentOffset(Mage1Website::model()->tableName(), 0, $this->stepIndex);
                    UBMigrate::updateCurrentOffset(Mage1StoreGroup::model()->tableName(), 0, $this->stepIndex);
                    UBMigrate::updateCurrentOffset(Mage1Store::model()->tableName(), 0, $this->stepIndex);
                }

                //get setting data
                $settingData = $step->getSettingData();
                $selectedWebsiteIds = (isset($settingData['website_ids'])) ? $settingData['website_ids'] : [];
                $selectedStoreGroupIds = (isset($settingData['store_group_ids'])) ? $settingData['store_group_ids'] : [];
                $selectedStoreIds = (isset($settingData['store_ids'])) ? $settingData['store_ids'] : [];
                //some variables for paging
                $max1 = $max2 = $max3 = 0;
                $offset1 = $offset2 = $offset3 = 0;

                //start migrate data by settings
                if ($selectedWebsiteIds AND $selectedStoreGroupIds AND $selectedStoreIds) {
                    /**
                     * Migrate websites
                     */
                    $strWebsiteIds = implode(',', $selectedWebsiteIds);
                    $condition = "website_id IN ({$strWebsiteIds})";
                    $max1 = Mage1Website::model()->count($condition);
                    $offset1 = UBMigrate::getCurrentOffset(2, Mage1Website::model()->tableName());
                    $websites = UBMigrate::getListObjects('Mage1Website', $condition, $offset1, $this->limit, "website_id ASC");
                    if ($websites) {
                        $this->_migrateWebsites($websites, $settingData);
                    }

                    if ($offset1 == 0) {
                        //update status of this step to migrating
                        $step->updateStatus(UBMigrate::STATUS_MIGRATING);
                        //log for first entry
                        Yii::log("Start running step #{$this->stepIndex}",'info', 'ub_data_migration');
                    }

                    /**
                     * Migrate Store Groups
                     */
                    if ($offset1 >= $max1) { //has migrated all selected websites
                        //get mapping websites
                        $mappingWebsites = UBMigrate::getMappingData('core_website', 2);
                        //build condition
                        $strGroupIds = implode(',', $selectedStoreGroupIds);
                        $condition = "group_id IN ({$strGroupIds})";
                        $max2 = Mage1StoreGroup::model()->count($condition);
                        $offset2 = UBMigrate::getCurrentOffset(2, Mage1StoreGroup::model()->tableName());
                        $storeGroups = UBMigrate::getListObjects('Mage1StoreGroup', $condition, $offset2, $this->limit, "group_id ASC");
                        if ($storeGroups) {
                            $this->_migrateStoreGroups($storeGroups, $mappingWebsites, $settingData);
                        }
                    }

                    if ($offset1 >= $max1 AND $offset2 >= $max2) { //has migrated all selected Websites and Store Groups
                        //get mapping store groups
                        $mappingStoreGroups = UBMigrate::getMappingData('core_store_group', 2);
                        //build condition
                        $strStoreIds = implode(',', $selectedStoreIds);
                        $condition = "store_id IN ({$strStoreIds})";
                        $max3 = Mage1Store::model()->count($condition);
                        $offset3 = UBMigrate::getCurrentOffset(2, Mage1Store::model()->tableName());
                        $stores = UBMigrate::getListObjects('Mage1Store', $condition, $offset3, $this->limit, "store_id ASC");
                        if ($stores) {
                            $this->_migrateStores($stores, $mappingWebsites, $mappingStoreGroups, $settingData);
                        }
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
                    if ($offset1 >= $max1 AND $offset2 >= $max2 AND $offset3 >= $max3) { //has migrated all
                        //update status of this step to finished
                        if ($step->updateStatus(UBMigrate::STATUS_FINISHED)) {
                            //update current offset to max
                            UBMigrate::updateCurrentOffset(Mage1Website::model()->tableName(), $max1, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1StoreGroup::model()->tableName(), $max2, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1Store::model()->tableName(), $max3, $this->stepIndex);

                            //get mapping stores
                            $mappingWebsites = UBMigrate::getMappingData('core_website', 2);
                            $mappingStoreGroups = UBMigrate::getMappingData('core_store_group', 2);
                            $mappingStores = UBMigrate::getMappingData('core_store', 2);

                            //re-update default_group_id for website
                            if ($mappingWebsites) {
                                $strWebsiteIds = implode(',', $mappingWebsites);
                                $websites2 = Mage2Website::model()->findAll("website_id IN ({$strWebsiteIds})");
                                foreach ($websites2 as $website2) {
                                    if (isset($mappingStoreGroups[$website2->default_group_id])) {
                                        $website2->default_group_id = $mappingStoreGroups[$website2->default_group_id];
                                        $website2->update();
                                    }
                                }
                            }

                            //re-update default_store_id for store group
                            if ($mappingStoreGroups) {
                                $strStoreGroupIds = implode(',', $mappingStoreGroups);
                                $storeGroups2 = Mage2StoreGroup::model()->findAll("group_id IN ({$strStoreGroupIds})");
                                foreach ($storeGroups2 as $storeGroup2) {
                                    if (isset($mappingStores[$storeGroup2->default_store_id])) {
                                        $storeGroup2->default_store_id = $mappingStores[$storeGroup2->default_store_id];
                                        $storeGroup2->update();
                                    }
                                }
                            }

                            //update result to respond
                            $rs['status'] = 'done';
                            $rs['percent_done'] = UBMigrate::getPercentByStatus(UBMigrate::STATUS_FINISHED, [1]);
                            $rs['step_status_text'] = $step->getStepStatusText();
                            $rs['message'] = Yii::t('frontend', "Step #%s migration completed successfully", array('%s' => $this->stepIndex));
                            Yii::log($rs['message'], 'info', 'ub_data_migration');
                            Yii::log($rs['message']."\n", 'info', 'ub_data_migration');
                        }
                    } else {
                        //update current offset for next run
                        if ($max1) {
                            UBMigrate::updateCurrentOffset(Mage1Website::model()->tableName(), ($offset1 + $this->limit), $this->stepIndex);
                        }
                        if ($max2) { // has done with attribute sets
                            UBMigrate::updateCurrentOffset(Mage1StoreGroup::model()->tableName(), ($offset2 + $this->limit), $this->stepIndex);
                        }
                        if ($max3) { // has done with attributes
                            UBMigrate::updateCurrentOffset(Mage1Store::model()->tableName(), ($offset3 + $this->limit), $this->stepIndex);
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
                        if (isset($websites) AND $websites) {
                            $msg .= ' %s1 Websites';
                            $data['%s1'] = sizeof($websites);
                        }
                        if (isset($storeGroups) AND $storeGroups) {
                            $msg .= ' %s2 Store Groups';
                            $data['%s2'] = sizeof($storeGroups);
                        }
                        if (isset($stores) AND $stores) {
                            $msg .= ' %s3 Stores';
                            $data['%s3'] = sizeof($stores);
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

    private function _migrateWebsites($websites, $settingData)
    {
        $isMergeDefaultWebsite = $settingData['is_merge_default_website'];
        if ($isMergeDefaultWebsite) {
            $defaultWebsite2 = Mage2Website::model()->find("website_id = {$settingData['default_website_id2']}");
        }
        foreach ($websites as $website1) {
            $m2Id = UBMigrate::getM2EntityId($this->stepIndex, 'core_website', $website1->website_id);
            $canReset = UBMigrate::RESET_YES;
            if (is_null($m2Id)) {
                if ($website1->code == 'admin') {
                    $websiteCode2 = 'admin';
                } else {
                    if ($website1->is_default && $isMergeDefaultWebsite) {
                        $websiteCode2 = $defaultWebsite2->code;
                    } else {
                        $websiteCode2 = "{$website1->code}_migrated";
                    }
                }
                //find website instance from Magento2 by code
                $websiteCode2 = ( strlen(trim($websiteCode2)) > 32 ) ? substr(trim($websiteCode2), 0, 32) : $websiteCode2;
                $website2 = Mage2Website::model()->find("code = '{$websiteCode2}'");
                if (!$website2) {
                    //add new
                    $website2 = new Mage2Website();
                    $website2->code = $websiteCode2;
                    $website2->name = $website1->name;
                    $website2->sort_order = $website1->sort_order;
                    $website2->default_group_id = $website1->default_group_id; //we will re-update this when all store_group was migrated
                    $website2->is_default = 0;
                } else {
                    $canReset = UBMigrate::RESET_NO;
                    //update info if needed -> coming soon
                }
            } else {
                $website2 = Mage2Website::model()->find("website_id = {$m2Id}");
                //update info if needed -> coming soon
            }
            //save/update
            if ($website2 && $website2->save()) {
                $this->websites2[] = $website2;
                if (is_null($m2Id)) {
                    //update to map log
                    UBMigrate::log([
                        'entity_name' => $website1->tableName(),
                        'm1_id' => $website1->website_id,
                        'm2_id' => $website2->website_id,
                        'm2_model_class' => get_class($website2),
                        'm2_key_field' => 'website_id',
                        'can_reset' => $canReset,
                        'step_index' => $this->stepIndex
                    ]);
                }
                $this->_traceInfo();
            } else {
                $this->errors[] = get_class($website2) . ": " . UBMigrate::getStringErrors($website2->getErrors());
            }
        }

        return true;
    }

    private function _migrateStoreGroups($storeGroups, $mappingWebsites, $settingData)
    {
        if ($storeGroups) {
            $storeNeedUpdateRootCatIds = array();
            $isMergeDefaultWebsite = $settingData['is_merge_default_website'];
            if ($isMergeDefaultWebsite) {
                $defaultWebsite1 = Mage1Website::model()->find("website_id = {$settingData['default_website_id1']}");
                $defaultWebsite2 = Mage2Website::model()->find("website_id = {$settingData['default_website_id2']}");
            }
            foreach ($storeGroups as $storeGroup1) {
                $needUpdate = false;
                $websiteId2 = $mappingWebsites[$storeGroup1->website_id];
                $m2Id = UBMigrate::getM2EntityId($this->stepIndex, 'core_store_group', $storeGroup1->group_id);
                $canReset = UBMigrate::RESET_YES;
                if (is_null($m2Id)) {
                    //we will merge admin store group
                    if ($storeGroup1->website_id == 0 AND $storeGroup1->name == 'Default') {
                        $storeGroup2 = Mage2StoreGroup::model()->find("website_id = 0 AND name = 'Default'");
                        $canReset = UBMigrate::RESET_NO;
                    } else {
                        if ($isMergeDefaultWebsite && $storeGroup1->group_id == $defaultWebsite1->default_group_id) {
                            // we will merge default store group of default website
                            $storeGroup2 = Mage2StoreGroup::model()->find("group_id = {$defaultWebsite2->default_group_id}");
                            $canReset = UBMigrate::RESET_NO;
                        } else {
                            $needUpdate = true;
                            //add new store group
                            $storeGroup2 = new Mage2StoreGroup();
                            $storeGroup2->website_id = $websiteId2;
                            //we will update this value after migrated all product categories in the step #4
                            $storeGroup2->root_category_id = $storeGroup1->root_category_id;
                            $storeGroup2->default_store_id = $storeGroup1->default_store_id; //we will update this after migrated all stores
                            $storeGroup2->name = $storeGroup1->name;
                            //this is a new field added from Magento ver.2.2.0
                            $storeGroup2->code = $this->_getStoreGroupCode($storeGroup1->group_id, $storeGroup1->name);
                        }
                    }
                } else {
                    $storeGroup2 = Mage2StoreGroup::model()->find("group_id = {$m2Id}");
                }
                //save/update
                if ($storeGroup2 && $storeGroup2->save()) {
                    $this->storeGroups2[] = $storeGroup2;
                    if (is_null($m2Id)) {
                        //update to map log
                        UBMigrate::log([
                            'entity_name' => $storeGroup1->tableName(),
                            'm1_id' => $storeGroup1->group_id,
                            'm2_id' => $storeGroup2->group_id,
                            'm2_model_class' => get_class($storeGroup2),
                            'm2_key_field' => 'group_id',
                            'can_reset' => $canReset,
                            'step_index' => $this->stepIndex
                        ]);
                    }
                    if ($needUpdate) {
                        $storeNeedUpdateRootCatIds[] = $storeGroup2->group_id;
                    }
                    $this->_traceInfo();
                } else {
                    $this->errors[] = get_class($storeGroup2) . ": " . UBMigrate::getStringErrors($storeGroup2->getErrors());
                }
            }

            if ($storeNeedUpdateRootCatIds) {
                //update to settings data
                UBMigrate::updateSetting(2, 'store_need_update_root_cat_ids', $storeNeedUpdateRootCatIds);
            }
        }

        return true;
    }

    private function _migrateStores($stores, $mappingWebsites, $mappingStoreGroups, $settingData)
    {
        if ($stores) {
            $isMergeDefaultWebsite = $settingData['is_merge_default_website'];
            if ($isMergeDefaultWebsite) {
                $defaultWebsite1 = Mage1Website::model()->find("website_id = {$settingData['default_website_id1']}");
                $defaultStoreGroup1 = Mage1StoreGroup::model()->find("group_id = {$defaultWebsite1->default_group_id}");
                $defaultStore1 = Mage1Store::model()->find("store_id = {$defaultStoreGroup1->default_store_id}");
                $defaultWebsite2 = Mage2Website::model()->find("website_id = {$settingData['default_website_id2']}");
            }
            foreach ($stores as $store1) {
                $m2Id = UBMigrate::getM2EntityId($this->stepIndex, 'core_store', $store1->store_id);
                $canReset = UBMigrate::RESET_YES;
                if (is_null($m2Id)) {
                    if ($store1->code == 'admin') {
                        $storeCode2 = 'admin';
                    } else {
                        if ($isMergeDefaultWebsite && $store1->store_id == $defaultStore1->store_id) {
                            //we will merge default store view of default store group from default websites
                            $defaultStoreGroup2 = Mage2StoreGroup::model()->find("group_id = {$defaultWebsite2->default_group_id}");
                            $defaultStore2 = Mage2Store::model()->find("store_id = {$defaultStoreGroup2->default_store_id}");
                            $storeCode2 = $defaultStore2->code;
                        } else {
                            $storeCode2 = "{$store1->code}_{$store1->store_id}";
                            //because max length of code field is 32 chars
                            if (strlen($storeCode2) > 32) {
                                $storeCode2 = substr($storeCode2, (strlen($storeCode2)-32), 32);
                            }
                        }
                    }
                    $store2 = Mage2Store::model()->find("code = '{$storeCode2}'");
                    if (!$store2) {
                        //add new
                        $store2 = new Mage2Store();
                        $store2->code = $storeCode2;
                    } else {
                        $canReset = UBMigrate::RESET_NO;
                    }
                } else {
                    $store2 = Mage2Store::model()->find("store_id = {$m2Id}");
                }
                //update store info
                $store2->name = $store1->name;
                $store2->website_id = $mappingWebsites[$store1->website_id];
                $store2->group_id = $mappingStoreGroups[$store1->group_id];
                $store2->is_active = $store1->is_active;
                $store2->sort_order = $store1->sort_order;
                //save/update
                if ($store2 && $store2->save()) {
                    if (is_null($m2Id)) {
                        //update to map log
                        UBMigrate::log([
                            'entity_name' => $store1->tableName(),
                            'm1_id' => $store1->store_id,
                            'm2_id' => $store2->store_id,
                            'm2_model_class' => get_class($store2),
                            'm2_key_field' => 'store_id',
                            'can_reset' => $canReset,
                            'step_index' => $this->stepIndex
                        ]);
                    }
                    $this->_traceInfo();
                } else {
                    $this->errors[] = get_class($store2) . ": " . UBMigrate::getStringErrors($store2->getErrors());
                }
            }
        }

        return true;
    }

    private function _getStoreGroupCode($storeGroupId, $storeGroupName) {
        $code = preg_replace('/\s+/', '_', $storeGroupName);
        $code = preg_replace('/[^a-z0-9-_]/', '', strtolower($code));
        $code = preg_replace('/^[^a-z]+/', '', $code);

        if (empty($code)) {
            $code = 'store_group';
        }

        //this handle for case: There are some stores has same store name
        $code .= "_{$storeGroupId}";

        //because max length of code field is 32 chars
        if (strlen($code) > 32) {
            $code = substr($code, (strlen($code)-32), 32);
        }

        return $code;
    }

    private function _traceInfo()
    {
        if ($this->isCLI) {
            echo ".";
        }
    }

}
