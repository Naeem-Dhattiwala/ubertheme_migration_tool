<?php

include_once('BaseController.php');

/**
 * @todo: Sales data migration
 *
 * Class Step7Controller
 */
class Step7Controller extends BaseController
{
    protected $stepIndex = 7;

    /**
     * @todo: Setting
     */
    public function actionSetting()
    {
        //get step object
        $step = UBMigrate::model()->find("id = {$this->stepIndex}");
        $result = UBMigrate::checkStep($step->sorder);
        if ($result['allowed']) {
            //get current setting data
            $settingData = $step->getSettingData();

            //get selected store ids
            $selectedStoreIds = UBMigrate::getSetting(2, 'store_ids');
            $strSelectedStoreIds = implode(',', $selectedStoreIds);
            //get selected product types
            $selectedProductTypes = UBMigrate::getSetting(5, 'product_types');
            //get selected customer group ids
            $selectedCustomerGroupIds = UBMigrate::getSetting(6, 'customer_group_ids');

            //sales objects to migrate
            $salesObjects = array(
                'rule_coupon' => ['label' => Yii::t('frontend', 'Sales Rules & Coupons')],
                'order_status' => ['label' => Yii::t('frontend', 'Sales Order Status')],
                'order' => [
                    'label' => Yii::t('frontend', 'Sales Orders'),
                    'related' => [
                        'quote' => Yii::t('frontend', 'Sales Quotes'),
                        'payment' => Yii::t('frontend', 'Sales Payments'),
                        'invoice' => Yii::t('frontend', 'Sales Invoices'),
                        'shipment' => Yii::t('frontend', 'Sales Shipments'),
                        'credit' => Yii::t('frontend', 'Sales Credit Memos')
                    ]
                ],
                'sales_aggregated_data' => [
                    'label' => Yii::t('frontend', 'Sales Aggregated Data'),
                    'related' => [
                        'sales_order_aggregated_created' => Yii::t('frontend', 'Sales Order Aggregated Created'),
                        'sales_order_aggregated_updated' => Yii::t('frontend', 'Sales Order Aggregated Updated'),
                        'sales_refunded_aggregated' => Yii::t('frontend', 'Sales Refunded Aggregated'),
                        'sales_refunded_aggregated_order' => Yii::t('frontend', 'Sales Refunded Aggregated Order'),
                        'sales_invoiced_aggregated' => Yii::t('frontend', 'Sales Invoiced Aggregated'),
                        'sales_invoiced_aggregated_order' => Yii::t('frontend', 'Sales Invoiced Aggregated Order'),
                        'sales_shipping_aggregated' => Yii::t('frontend', 'Sales Shipping Aggregated'),
                        'sales_shipping_aggregated_order' => Yii::t('frontend', 'Sales Shipping Aggregated Order'),
                        'sales_bestsellers_aggregated_daily' => Yii::t('frontend', 'Sales Bestsellers Aggregated Daily'),
                        'sales_bestsellers_aggregated_monthly' => Yii::t('frontend', 'Sales Bestsellers Aggregated Monthly'),
                        'sales_bestsellers_aggregated_yearly' => Yii::t('frontend', 'Sales Bestsellers Aggregated Yearly'),
                    ]
                ]
            );
            $mNotes = array();
            if (Yii::app()->request->isPostRequest) {
                //check required settings
                if ($selectedStoreIds AND $selectedProductTypes AND $selectedCustomerGroupIds) {
                    //get selected data ids
                    $selectedObjects = Yii::app()->request->getParam('sales_objects', array());
                    $selectedAggregatedTables = Yii::app()->request->getParam('sales_aggregated_tables', array());
                    $keepOriginalId = Yii::app()->request->getParam('keep_original_id', 0);
                    if ($selectedObjects) {
                        //make setting data to save
                        $newSettingData = [
                            'sales_objects' => $selectedObjects,
                            'sales_aggregated_tables' => $selectedAggregatedTables,
                            'keep_original_id' => $keepOriginalId,
                            'migrated_sales_objects' => (isset($settingData['migrated_sales_objects'])) ? $settingData['migrated_sales_objects'] : [],
                            'migrated_sales_aggregated_tables' => (isset($settingData['migrated_sales_aggregated_tables'])) ? $settingData['migrated_sales_aggregated_tables'] : [],
                        ];
                        $step->setting_data = base64_encode(serialize($newSettingData));
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
                        Yii::app()->user->setFlash('note', Yii::t('frontend', 'You must select at least one object to migrate'));
                    }
                } else {
                    if (empty($selectedCustomerGroupIds)) {
                        $mNotes[] = Yii::t('frontend', 'Reminder! You have to complete all settings in the step #6 (Customers) first');
                    } else if (empty($selectedProductTypes)) {
                        $mNotes[] = Yii::t('frontend', 'Reminder! You have to complete all settings in the step #5 (Products) first');
                    }
                }
            }

            if ($mNotes) {
                Yii::app()->user->setFlash('note', implode('<br/>', $mNotes));
            }

            $assignData = array(
                'step' => $step,
                'salesObjects' => $salesObjects,
                'strSelectedStoreIds' => $strSelectedStoreIds,
                'settingData' => $settingData
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
                UBMigrate::updateCurrentOffset(Mage1Salesrule::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesOrderStatus::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesOrder::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesOrderAggregatedCreated::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesOrderAggregatedUpdated::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesRefundedAggregated::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesRefundedAggregatedOrder::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesInvoicedAggregated::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesInvoicedAggregatedOrder::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesShippingAggregated::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesShippingAggregatedOrder::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesBestsellersDaily::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesBestsellersMonthly::model()->tableName(), 0, $this->stepIndex);
                UBMigrate::updateCurrentOffset(Mage1SalesBestsellersYearly::model()->tableName(), 0, $this->stepIndex);
            }

            //get mapping websites
            $mappingWebsites = UBMigrate::getMappingData('core_website', 2);
            //get mapping stores
            $mappingStores = UBMigrate::getMappingData('core_store', 2);
            //get mapping product attributes
            $mappingAttributes = UBMigrate::getMappingData('eav_attribute', '3_attribute');
            //get mapping customer groups
            $mappingCustomerGroups = UBMigrate::getMappingData('customer_group', 6);

            //check has keep original customer ids
            $keepOriginalId = UBMigrate::getSetting(7, 'keep_original_id');

            //get setting data
            $settingData = $step->getSettingData();
            $selectedSalesObjects = (isset($settingData['sales_objects'])) ? $settingData['sales_objects'] : [];
            $selectedSalesAggregatedTables = (isset($settingData['sales_aggregated_tables'])) ? $settingData['sales_aggregated_tables'] : [];

            //some variables for paging
            $max1 = $offset1 = $max2 = $offset2 = $max3 = $offset3 = 0;
            $max4 = $offset4 = $max5 = $offset5 = $max6 = $offset6 = 0;
            $max7 = $offset7 = $max8 = $offset8 = $max9 = $offset9 = $max10 = $offset10 = 0;
            $max11 = $offset11 = $max12 = $offset12 = $max13 = $offset13 = $max14 = $offset14 = 0;

            try {
                //start migrate data by settings
                if ($selectedSalesObjects) {
                    /**
                     * migrate sales rules & coupons data
                     */
                    if (in_array('rule_coupon', $selectedSalesObjects)) {
                        //get max total
                        $max1 = Mage1Salesrule::model()->count();
                        $offset1 = UBMigrate::getCurrentOffset(7, Mage1Salesrule::model()->tableName());
                        //get data by limit and offset
                        $salesRules = UBMigrate::getListObjects('Mage1Salesrule', '', $offset1, $this->limit, "rule_id ASC");
                        if ($salesRules) {
                            //migrate sales rules
                            $this->_migrateSalesRules($salesRules, $mappingWebsites, $mappingStores, $mappingAttributes, $mappingCustomerGroups, $keepOriginalId);
                        }

                        if ($offset1 == 0) {
                            //log for first entry
                            Yii::log("Start running step #{$this->stepIndex}",'info', 'ub_data_migration');
                            //update status of this step to migrating
                            $step->updateStatus(UBMigrate::STATUS_MIGRATING);
                        }
                    }
                    //end migrate sales rules & coupons

                    /**
                     * migrate sales_order_status
                     * we only migrated sales orders statuses when migrated all sales rules
                     */
                    if (in_array('order_status', $selectedSalesObjects) AND !sizeof($salesRules)) {
                        $max2 = Mage1SalesOrderStatus::model()->count();
                        $offset2 = UBMigrate::getCurrentOffset(7, Mage1SalesOrderStatus::model()->tableName());
                        //get data by limit and offset
                        $orderStatuses = UBMigrate::getListObjects('Mage1SalesOrderStatus', '', $offset2, $this->limit);
                        if ($orderStatuses) {
                            //migrate sales order statuses
                            $this->_migrateSalesOrderStatuses($orderStatuses, $mappingStores);
                        }
                    }
                    //end migrate sales_order_status

                    /**
                     * migrate sales orders data
                     * we only migrated sales orders data when migrated all sales order statuses
                     */
                    if (in_array('order', $selectedSalesObjects) AND !sizeof($salesRules) AND !sizeof($orderStatuses)) {
                        //build condition
                        $condition = [];
                        if (!UBMigrate::getSetting(2, 'select_all_store')) {
                            //get migrated store ids
                            $strMigratedStoreIds = implode(',', array_keys($mappingStores));
                            $condition[] = "(store_id IN ({$strMigratedStoreIds}) OR store_id IS NULL)";
                        }
                        $condition = implode(" AND ", $condition);
                        //get max total
                        $max3 = Mage1SalesOrder::model()->count($condition);
                        $offset3 = UBMigrate::getCurrentOffset(7, Mage1SalesOrder::model()->tableName());
                        //get data by limit and offset
                        $salesOrders = UBMigrate::getListObjects('Mage1SalesOrder', $condition, $offset3, $this->limit, "entity_id ASC");
                        if ($salesOrders) {
                            //migrate sales orders
                            $this->_migrateSalesOrders($salesOrders, $mappingStores, $mappingAttributes, $mappingCustomerGroups, $keepOriginalId);
                        }
                    }
                    //end migrate sales orders

                    /**
                     * sales aggregated data
                     * we only migrated below data when all sales orders was migrated
                     */
                    $canRun = (!sizeof($salesRules) AND !sizeof($orderStatuses) AND !sizeof($salesOrders)) ? 1 : 0;
                    if (in_array('sales_aggregated_data', $selectedSalesObjects) AND $canRun) {

                        //build condition with stores
                        $condition = '';
                        $isSelectAllStores = UBMigrate::getSetting(2, 'select_all_store');
                        if (!$isSelectAllStores) {
                            $strStoreIds = implode(',', array_keys($mappingStores));
                            $condition = "store_id IN ({$strStoreIds}) OR store_id is NULL";
                        }

                        /**
                         * Table: sales_order_aggregated_created
                         */
                        if (in_array('sales_order_aggregated_created', $selectedSalesAggregatedTables)) {
                            $m1Class = 'Mage1SalesOrderAggregatedCreated';
                            $m2Class = 'Mage2SalesOrderAggregatedCreated';
                            $max4 = $m1Class::model()->count($condition);
                            $offset4 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list4 = UBMigrate::getListObjects($m1Class, $condition, $offset4, $this->limit);
                            if ($list4) {
                                $this->_migrateListObjects($list4, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_order_aggregated_updated
                         */
                        $canRun = ($offset4 >= $max4) ? 1 : 0;
                        if (in_array('sales_order_aggregated_updated', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesOrderAggregatedUpdated';
                            $m2Class = 'Mage2SalesOrderAggregatedUpdated';
                            $max5 = $m1Class::model()->count($condition);
                            $offset5 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list5 = UBMigrate::getListObjects($m1Class, $condition, $offset5, $this->limit);
                            if ($list5) {
                                $this->_migrateListObjects($list5, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_refunded_aggregated
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5) ? 1 : 0;
                        if (in_array('sales_refunded_aggregated', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesRefundedAggregated';
                            $m2Class = 'Mage2SalesRefundedAggregated';
                            $max6 = $m1Class::model()->count($condition);
                            $offset6 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list6 = UBMigrate::getListObjects($m1Class, $condition, $offset6, $this->limit);
                            if ($list6) {
                                $this->_migrateListObjects($list6, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_refunded_aggregated_order
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5 AND $offset6 >= $max6) ? 1 : 0;
                        if (in_array('sales_refunded_aggregated_order', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesRefundedAggregatedOrder';
                            $m2Class = 'Mage2SalesRefundedAggregatedOrder';
                            $max7 = $m1Class::model()->count($condition);
                            $offset7 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list7 = UBMigrate::getListObjects($m1Class, $condition, $offset7, $this->limit);
                            if ($list7) {
                                $this->_migrateListObjects($list7, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_invoiced_aggregated
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5 AND $offset6 >= $max6 AND $offset7 >= $max7) ? 1 : 0;
                        if (in_array('sales_invoiced_aggregated', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesInvoicedAggregated';
                            $m2Class = 'Mage2SalesInvoicedAggregated';
                            $max8 = $m1Class::model()->count($condition);
                            $offset8 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list8 = UBMigrate::getListObjects($m1Class, $condition, $offset8, $this->limit);
                            if ($list8) {
                                $this->_migrateListObjects($list8, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_invoiced_aggregated_order
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5 AND $offset6 >= $max6
                            AND $offset7 >= $max7 AND $offset8 >= $max8) ? 1 : 0;
                        if (in_array('sales_invoiced_aggregated_order', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesInvoicedAggregatedOrder';
                            $m2Class = 'Mage2SalesInvoicedAggregatedOrder';
                            $max9 = $m1Class::model()->count($condition);
                            $offset9 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list9 = UBMigrate::getListObjects($m1Class, $condition, $offset9, $this->limit);
                            if ($list9) {
                                $this->_migrateListObjects($list9, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_shipping_aggregated
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5 AND $offset6 >= $max6
                            AND $offset7 >= $max7 AND $offset8 >= $max8 AND $offset9 >= $max9) ? 1 : 0;
                        if (in_array('sales_shipping_aggregated', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesShippingAggregated';
                            $m2Class = 'Mage2SalesShippingAggregated';
                            $max10 = $m1Class::model()->count($condition);
                            $offset10 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list10 = UBMigrate::getListObjects($m1Class, $condition, $offset10, $this->limit);
                            if ($list10) {
                                $this->_migrateShippingAggregatedData($list10, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_shipping_aggregated_order
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5 AND $offset6 >= $max6
                            AND $offset7 >= $max7 AND $offset8 >= $max8 AND $offset9 >= $max9 AND $offset10 >= $max10) ? 1 : 0;
                        if (in_array('sales_shipping_aggregated_order', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesShippingAggregatedOrder';
                            $m2Class = 'Mage2SalesShippingAggregatedOrder';
                            $max11 = $m1Class::model()->count($condition);
                            $offset11 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list11 = UBMigrate::getListObjects($m1Class, $condition, $offset11, $this->limit);
                            if ($list11) {
                                $this->_migrateShippingAggregatedData($list11, $m2Class, $mappingStores);
                            }
                        }

                        //re-update condition string
                        $isSelectAllProducts = UBMigrate::getSetting(5, 'select_all_product');
                        if (!$isSelectAllProducts) {
                            $mappingProducts = UBMigrate::getMappingData('catalog_product_entity', 5);
                            $strProductsIds = implode(',', array_keys($mappingProducts));
                            if (empty($condition)) {
                                $condition = "product_id IN ({$strProductsIds})";
                            } else {
                                $condition .= " AND product_id IN ({$strProductsIds})";
                            }
                        }

                        /**
                         * Table: sales_bestsellers_aggregated_daily
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5 AND $offset6 >= $max6
                            AND $offset7 >= $max7 AND $offset8 >= $max8 AND $offset9 >= $max9
                            AND $offset10 >= $max10 AND $offset11 >= $max11) ? 1 : 0;
                        if (in_array('sales_bestsellers_aggregated_daily', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesBestsellersDaily';
                            $m2Class = 'Mage2SalesBestsellersDaily';
                            $max12 = $m1Class::model()->count($condition);
                            $offset12 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list12 = UBMigrate::getListObjects($m1Class, $condition, $offset12, $this->limit);
                            if ($list12) {
                                $this->_migrateBestsellerData($list12, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_bestsellers_aggregated_monthly
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5 AND $offset6 >= $max6
                            AND $offset7 >= $max7 AND $offset8 >= $max8 AND $offset9 >= $max9
                            AND $offset10 >= $max10 AND $offset11 >= $max11 AND $offset12 >= $max12) ? 1 : 0;
                        if (in_array('sales_bestsellers_aggregated_monthly', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesBestsellersMonthly';
                            $m2Class = 'Mage2SalesBestsellersMonthly';
                            $max13 = $m1Class::model()->count($condition);
                            $offset13 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list13 = UBMigrate::getListObjects($m1Class, $condition, $offset13, $this->limit);
                            if ($list13) {
                                $this->_migrateBestsellerData($list13, $m2Class, $mappingStores);
                            }
                        }

                        /**
                         * Table: sales_bestsellers_aggregated_yearly
                         */
                        $canRun = ($offset4 >= $max4 AND $offset5 >= $max5 AND $offset6 >= $max6
                            AND $offset7 >= $max7 AND $offset8 >= $max8 AND $offset9 >= $max9
                            AND $offset10 >= $max10 AND $offset11 >= $max11
                            AND $offset12 >= $max12 AND $offset13 >= $max13) ? 1 : 0;
                        if (in_array('sales_bestsellers_aggregated_yearly', $selectedSalesAggregatedTables) AND $canRun) {
                            $m1Class = 'Mage1SalesBestsellersYearly';
                            $m2Class = 'Mage2SalesBestsellersYearly';
                            $max14 = $m1Class::model()->count($condition);
                            $offset14 = UBMigrate::getCurrentOffset(7, $m1Class::model()->tableName());
                            $list14 = UBMigrate::getListObjects($m1Class, $condition, $offset14, $this->limit);
                            if ($list14) {
                                $this->_migrateBestsellerData($list14, $m2Class, $mappingStores);
                            }
                        }
                    }
                    //end migrate aggregated data
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
                    //if all selected data migrated
                    if ($offset1 >= $max1 AND $offset2 >= $max2 AND $offset3 >= $max3 AND $offset4 >= $max4
                        AND $offset5 >= $max5 AND $offset6 >= $max6 AND $offset7 >= $max7 AND $offset8 >= $max8
                        AND $offset9 >= $max9 AND $offset10 >= $max10 AND $offset11 >= $max11 AND $offset12 >= $max12
                        AND $offset13 >= $max13 AND $offset14 >= $max14) {
                        //update status of this step to finished
                        if ($step->updateStatus(UBMigrate::STATUS_FINISHED)) {
                            //update migrated objects
                            UBMigrate::updateSetting(7, 'migrated_sales_objects', $selectedSalesObjects);
                            UBMigrate::updateSetting(7, 'migrated_sales_aggregated_tables', $selectedSalesAggregatedTables);

                            //update current offset to max value
                            UBMigrate::updateCurrentOffset(Mage1Salesrule::model()->tableName(), $max1, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesOrderStatus::model()->tableName(), $max2, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesOrder::model()->tableName(), $max3, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesOrderAggregatedCreated::model()->tableName(), $max4, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesOrderAggregatedUpdated::model()->tableName(), $max5, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesRefundedAggregated::model()->tableName(), $max6, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesRefundedAggregatedOrder::model()->tableName(), $max7, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesInvoicedAggregated::model()->tableName(), $max8, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesInvoicedAggregatedOrder::model()->tableName(),$max9, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesShippingAggregated::model()->tableName(), $max10, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesShippingAggregatedOrder::model()->tableName(), $max11, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesBestsellersDaily::model()->tableName(), $max12, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesBestsellersMonthly::model()->tableName(), $max13, $this->stepIndex);
                            UBMigrate::updateCurrentOffset(Mage1SalesBestsellersYearly::model()->tableName(), $max14, $this->stepIndex);

                            //update result to respond
                            $rs['status'] = 'done';
                            $rs['percent_done'] = UBMigrate::getPercentByStatus(UBMigrate::STATUS_FINISHED, [1]);
                            $rs['step_status_text'] = $step->getStepStatusText();
                            $rs['message'] = Yii::t('frontend', 'Step #%s migration completed successfully', array('%s' => $this->stepIndex));
                            Yii::log($rs['message']."\n", 'info', 'ub_data_migration');
                        }
                    } else {
                        //update current offset for next run
                        if ($max1) {
                            UBMigrate::updateCurrentOffset(Mage1Salesrule::model()->tableName(), ($offset1 + $this->limit), $this->stepIndex);
                            $max = $max1;
                        }
                        if ($max2) {
                            UBMigrate::updateCurrentOffset(Mage1SalesOrderStatus::model()->tableName(), ($offset2 + $this->limit), $this->stepIndex);
                            $max = $max2;
                        }
                        if ($max3) {
                            UBMigrate::updateCurrentOffset(Mage1SalesOrder::model()->tableName(), ($offset3 + $this->limit), $this->stepIndex);
                            $max = $max3;
                        }
                        if ($max4) {
                            UBMigrate::updateCurrentOffset(Mage1SalesOrderAggregatedCreated::model()->tableName(), ($offset4 + $this->limit), $this->stepIndex);
                            $max = $max4;
                        }
                        if ($max5) {
                            UBMigrate::updateCurrentOffset(Mage1SalesOrderAggregatedUpdated::model()->tableName(), ($offset5 + $this->limit), $this->stepIndex);
                            $max = $max5;
                        }
                        if ($max6) {
                            UBMigrate::updateCurrentOffset(Mage1SalesRefundedAggregated::model()->tableName(), ($offset6 + $this->limit), $this->stepIndex);
                            $max = $max6;
                        }
                        if ($max7) {
                            UBMigrate::updateCurrentOffset(Mage1SalesRefundedAggregatedOrder::model()->tableName(), ($offset7 + $this->limit), $this->stepIndex);
                            $max = $max7;
                        }
                        if ($max8) {
                            UBMigrate::updateCurrentOffset(Mage1SalesInvoicedAggregated::model()->tableName(), ($offset8 + $this->limit), $this->stepIndex);
                            $max = $max8;
                        }
                        if ($max9) {
                            UBMigrate::updateCurrentOffset(Mage1SalesInvoicedAggregatedOrder::model()->tableName(), ($offset9 + $this->limit), $this->stepIndex);
                            $max = $max9;
                        }
                        if ($max10) {
                            UBMigrate::updateCurrentOffset(Mage1SalesShippingAggregated::model()->tableName(), ($offset10 + $this->limit), $this->stepIndex);
                            $max = $max10;
                        }
                        if ($max11) {
                            UBMigrate::updateCurrentOffset(Mage1SalesShippingAggregatedOrder::model()->tableName(), ($offset11 + $this->limit), $this->stepIndex);
                            $max = $max11;
                        }
                        if ($max12) {
                            UBMigrate::updateCurrentOffset(Mage1SalesBestsellersDaily::model()->tableName(), ($offset12 + $this->limit), $this->stepIndex);
                            $max = $max12;
                        }
                        if ($max13) {
                            UBMigrate::updateCurrentOffset(Mage1SalesBestsellersMonthly::model()->tableName(), ($offset13 + $this->limit), $this->stepIndex);
                            $max = $max13;
                        }
                        if ($max14) {
                            UBMigrate::updateCurrentOffset(Mage1SalesBestsellersYearly::model()->tableName(), ($offset14 + $this->limit), $this->stepIndex);
                            $max = $max14;
                        }

                        //start calculate percent run ok
                        $totalSteps = UBMigrate::getTotalStepCanRunMigrate();
                        $percentOfOnceStep = (1 / $totalSteps) * 100;
                        $n = ceil($max / $this->limit);
                        $percentUp = ($percentOfOnceStep / 14) / $n;
                        //end calculate percent run ok

                        //update result to respond
                        $rs['status'] = 'ok';
                        $rs['percent_up'] = $percentUp;

                        //build message
                        $msg = ($offset1 == 0) ? '[Processing] Step #%s migration completed with' : '[Processing] Step #%s migration completed with';
                        $data['%s'] = $this->stepIndex;
                        if (isset($salesRules) AND $salesRules) {
                            $msg .= ' %s1 Sales Rules;';
                            $data['%s1'] = sizeof($salesRules);
                        } elseif (isset($orderStatuses) AND $orderStatuses) {
                            $msg .= ' %s2 Sales Order Statuses;';
                            $data['%s2'] = sizeof($orderStatuses);
                        }  elseif (isset($salesOrders) AND $salesOrders) {
                            $msg .= ' %s3 Sales Orders;';
                            $data['%s3'] = sizeof($salesOrders);
                        } elseif (isset($list4) AND $list4) {
                            $msg .= ' %s4 SalesOrderAggregatedCreated items;';
                            $data['%s4'] = sizeof($list4);
                        } elseif (isset($list5) AND $list5) {
                            $msg .= ' %s5 SalesOrderAggregatedUpdated items;';
                            $data['%s5'] = sizeof($list5);
                        } elseif (isset($list6) AND $list6) {
                            $msg .= ' %s6 SalesOrderAggregatedUpdated items;';
                            $data['%s6'] = sizeof($list6);
                        } elseif (isset($list7) AND $list7) {
                            $msg .= ' %s7 SalesRefundedAggregatedOrder items;';
                            $data['%s7'] = sizeof($list7);
                        } elseif (isset($list8) AND $list8) {
                            $msg .= ' %s8 SalesInvoicedAggregated items;';
                            $data['%s8'] = sizeof($list8);
                        } elseif (isset($list9) AND $list9) {
                            $msg .= ' %s9 SalesInvoicedAggregatedOrder items;';
                            $data['%s9'] = sizeof($list9);
                        } elseif (isset($list10) AND $list10) {
                            $msg .= ' %s10 SalesShippingAggregated items;';
                            $data['%s10'] = sizeof($list10);
                        } elseif (isset($list11) AND $list11) {
                            $msg .= ' %s11 SalesShippingAggregatedOrder items;';
                            $data['%s11'] = sizeof($list11);
                        } elseif (isset($list12) AND $list12) {
                            $msg .= ' %s12 SalesBestsellersDaily items;';
                            $data['%s12'] = sizeof($list12);
                        } elseif (isset($list13) AND $list13) {
                            $msg .= ' %s13 SalesBestsellersMonthly items;';
                            $data['%s13'] = sizeof($list13);
                        } elseif (isset($list14) AND $list14) {
                            $msg .= ' %s14 SalesBestsellersYearly items';
                            $data['%s14'] = sizeof($list14);
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

    private function _migrateSalesRules($salesRules, $mappingWebsites, $mappingStores, $mappingAttributes, $mappingCustomerGroups, $keepOriginalId)
    {
        //check has keep original product ids in step #5
        $keepProductId = UBMigrate::getSetting(5, 'keep_original_id');
        /**
         * Table: salesrule
         */
        foreach ($salesRules as $salesRule) {
            $m2Id = UBMigrate::getM2EntityId(7, 'salesrule', $salesRule->rule_id);
            if (is_null($m2Id)) {
                $salesRule2 = new Mage2Salesrule();
                //fill values
                foreach ($salesRule2->attributes as $key => $value) {
                    if (isset($salesRule->$key)) {
                        $salesRule2->$key = $salesRule->$key;
                    }
                }
                $salesRule2->rule_id = ($keepOriginalId) ? $salesRule->rule_id : null;
            } else { //updatealesrule
                $salesRule2 = Mage2Salesrule::model()->find("rule_id = {$m2Id}");
                //update values
                foreach ($salesRule2->attributes as $key => $value) {
                    if ($key != 'rule_id' && isset($salesRule->$key)) {
                        $salesRule2->$key = $salesRule->$key;
                    }
                }
            }
            //because some related ids was changed, so we have to re-update
            if (!$keepProductId && $salesRule2->product_ids) {
                $productIds = preg_split('/,\s*/', $salesRule2->product_ids);;
                if ($productIds) {
                    foreach ($productIds as $key => $id) {
                        $productIds[$key] = UBMigrate::getM2EntityId(5, 'catalog_product_entity', $id);
                    }
                    $salesRule2->product_ids = implode(',', $productIds);
                }
            }
            /**
             * Because model class name and related ids was changed in Magento2 after migrated
             * So we have to convert conditions and actions,
             **/
            $salesRule2->conditions_serialized = $this->_convertSalesRuleCondition($salesRule2->conditions_serialized);
            $salesRule2->actions_serialized = $this->_convertSalesRuleAction($salesRule2->actions_serialized);
            //save/update
            if (!$salesRule2->save()) {
                $this->errors[] = get_class($salesRule2) . ": " . UBMigrate::getStringErrors($salesRule2->getErrors());
            } else {
                if (is_null($m2Id)) {
                    //update to map log
                    UBMigrate::log([
                        'entity_name' => $salesRule->tableName(),
                        'm1_id' => $salesRule->rule_id,
                        'm2_id' => $salesRule2->rule_id,
                        'm2_model_class' => get_class($salesRule2),
                        'm2_key_field' => 'rule_id',
                        'can_reset' => UBMigrate::RESET_YES,
                        'step_index' => $this->stepIndex
                    ]);
                }
                $this->_traceInfo();
            }
            //migrate related data
            if ($salesRule2->rule_id) {
                //migrate sales rule coupon
                $this->_migrateSalesRuleCoupons($salesRule, $salesRule2, $keepOriginalId);
                //migrate sales rule label
                $this->_migrateSalesRuleLabels($salesRule, $salesRule2, $mappingStores);
                //migrate sales rule product attribute
                $this->_migrateSalesRuleProductAttributes($salesRule, $salesRule2, $mappingWebsites, $mappingAttributes, $mappingCustomerGroups);
                //migrate sales rules websites relation
                $this->_migrateSalesRuleWebsites($salesRule, $salesRule2, $mappingWebsites);
                //migrate sales rules customer groups
                $this->_migrateSalesRuleCustomerGroups($salesRule, $salesRule2, $mappingCustomerGroups);
                //migrate sales rules customers
                $this->_migrateSalesRuleCustomers($salesRule, $salesRule2);
            }
        }

        return true;
    }

    private function _convertSalesRuleCondition($conditionsSerialized)
    {
        $conditions = UBMigrate::mb_unserialize($conditionsSerialized);
        //convert type of condition
        if (isset($conditions['type']) AND $conditions['type']) {
            UBMigrate::convertConditionType($conditions['type']);
        }
        //convert sub conditions
        if (isset($conditions['conditions']) AND $conditions['conditions']) {
            UBMigrate::convertConditions($conditions['conditions']);
        }

        if (version_compare(UBMigrate::getM2Version(), '2.2.0', '<')) {
            return serialize($conditions);
        } else {
            //this changed from Magento ver.2.2.0
            return UBMigrate::encodeJson($conditions);
        }
    }

    private function _convertSalesRuleAction($actionsSerialized)
    {
        $actions = UBMigrate::mb_unserialize($actionsSerialized);
        //convert type of condition
        if (isset($actions['type']) AND $actions['type']) {
            UBMigrate::convertConditionType($actions['type']);
        }
        //convert sub conditions
        if (isset($actions['conditions']) AND $actions['conditions']) {
            UBMigrate::convertConditions($actions['conditions']);
        }

        if (version_compare(UBMigrate::getM2Version(), '2.2.0', '<')) {
            return serialize($actions);
        } else {
            //this changed from Magento ver.2.2.0
            return UBMigrate::encodeJson($actions);
        }
    }

    private function _migrateSalesRuleCoupons($salesRule, $salesRule2, $keepOriginalId)
    {
        //check has keep original customer ids
        $keepCustomerId = UBMigrate::getSetting(6, 'keep_original_id');
        /**
         * Table: salesrule_coupon
         */
        $coupons = Mage1SalesruleCoupon::model()->findAll("rule_id = {$salesRule->rule_id}");
        if ($coupons) {
            foreach ($coupons as $coupon) {
                $m2Id = UBMigrate::getM2EntityId(7, 'salesrule_coupon', $coupon->coupon_id);
                $canReset = UBMigrate::RESET_YES;
                if (is_null($m2Id)) {
                    $coupon2 = Mage2SalesruleCoupon::model()->find("code = '".addslashes($coupon->code)."'");
                    if (!$coupon2) {
                        //add new
                        $coupon2 = new Mage2SalesruleCoupon();
                        //fill values
                        foreach ($coupon2->attributes as $key => $value) {
                            if (isset($coupon->$key)) {
                                $coupon2->$key = $coupon->$key;
                            }
                            $coupon2->coupon_id = ($keepOriginalId) ? $coupon->coupon_id : null;
                            //because some entity ids was changed
                            $coupon2->rule_id = $salesRule2->rule_id;
                            if (empty($coupon2->expiration_date) || $coupon2->expiration_date === '0000-00-00 00:00:00') {
                                $coupon2->expiration_date = date("Y-m-d H:i:s");
                            }
                            
                            if (empty($coupon2->created_at) || $coupon2->created_at === '0000-00-00 00:00:00') {
                                $coupon2->created_at = date("Y-m-d H:i:s");
                            }
                            if ($coupon2->usage_per_customer) {
                                $coupon2->usage_per_customer = UBMigrate::getM2EntityId(6, 'customer_entity', $coupon2->usage_per_customer);
                            }
                        }
                    } else {
                        $canReset = UBMigrate::RESET_NO;
                    }
                } else {
                    //update
                    $coupon2 = Mage2SalesruleCoupon::model()->find("coupon_id = {$m2Id}");
                    foreach ($coupon2->attributes as $key => $value) {
                        if (isset($coupon->$key) AND !in_array($key, array('coupon_id', 'rule_id'))) {
                            $coupon2->$key = $coupon->$key;
                        }
                        if (!$keepCustomerId && $coupon2->usage_per_customer) {
                            $coupon2->usage_per_customer = UBMigrate::getM2EntityId(6, 'customer_entity', $coupon2->usage_per_customer);
                        }
                    }
                }
                //save/update
                if ($coupon2->save()) {
                    if (is_null($m2Id)) {
                        //update to map log
                        UBMigrate::log([
                            'entity_name' => $coupon->tableName(),
                            'm1_id' => $coupon->coupon_id,
                            'm2_id' => $coupon2->coupon_id,
                            'm2_model_class' => get_class($coupon2),
                            'm2_key_field' => 'coupon_id',
                            'can_reset' => $canReset,
                            'step_index' => $this->stepIndex
                        ]);
                    }
                    $this->_traceInfo();
                    /**
                     * Table: salesrule_coupon_usage
                     */
                    $couponUsages = Mage1SalesruleCouponUsage::model()->findAll("coupon_id = {$coupon->coupon_id}");
                    if ($couponUsages) {
                        foreach ($couponUsages as $couponUsage) {
                            $customerId2 = (!$keepCustomerId) ? UBMigrate::getM2EntityId(6, 'customer_entity', $couponUsage->customer_id) : $couponUsage->customer_id;
                            if ($customerId2) {
                                $couponUsage2 = Mage2SalesruleCouponUsage::model()->find("coupon_id = {$coupon2->coupon_id} AND customer_id = {$customerId2}");
                                if (!$couponUsage2) {
                                    $couponUsage2 = new Mage2SalesruleCouponUsage();
                                    $couponUsage2->coupon_id = $coupon2->coupon_id;
                                    $couponUsage2->customer_id = $customerId2;
                                }
                                $couponUsage2->times_used = $couponUsage->times_used;
                                if (!$couponUsage2->save()) {
                                    $this->errors[] = get_class($couponUsage2) . ": " . UBMigrate::getStringErrors($couponUsage2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                } else {
                    $this->errors[] = get_class($coupon2) . ": " . UBMigrate::getStringErrors($coupon2->getErrors());
                }
            }
        }

        return true;
    }

    private function _migrateSalesRuleLabels($salesRule, $salesRule2, $mappingStores)
    {
        /**
         * Table: salesrule_label
         */
        $strMigratedStoreIds = implode(',', array_keys($mappingStores));
        $condition = "rule_id = {$salesRule->rule_id} AND store_id IN ({$strMigratedStoreIds})";
        $labels = Mage1SalesruleLabel::model()->findAll($condition);
        if ($labels) {
            foreach ($labels as $label) {
                $storeId2 = isset($mappingStores[$label->store_id]) ? $mappingStores[$label->store_id] : 0;
                $condition = "rule_id = {$salesRule2->rule_id} AND store_id = {$storeId2}";
                $label2 = Mage2SalesruleLabel::model()->find($condition);
                if (!$label2) {
                    //add new
                    $label2 = new Mage2SalesruleLabel();
                    $label2->rule_id = $salesRule2->rule_id;
                    $label2->store_id = $storeId2;
                }
                $label2->label = $label->label;
                //save/update
                if (!$label2->save()) {
                    $this->errors[] = get_class($label2) . ": " . UBMigrate::getStringErrors($label2->getErrors());
                } else {
                    $this->_traceInfo();
                }
            }
        }

        return true;
    }

    private function _migrateSalesRuleProductAttributes($salesRule, $salesRule2, $mappingWebsites, $mappingAttributes, $mappingCustomerGroups)
    {
        /**
         * Table: salesrule_product_attribute
         */
        $strMigratedWebsiteIds = implode(',', array_keys($mappingWebsites));
        $strMigratedCustomerGroupIds = implode(',', array_keys($mappingCustomerGroups));
        $condition = "rule_id = {$salesRule->rule_id} AND website_id IN ({$strMigratedWebsiteIds}) AND customer_group_id IN ({$strMigratedCustomerGroupIds})";
        $ruleProductAttrs = Mage1SalesruleProductAttribute::model()->findAll($condition);
        if ($ruleProductAttrs) {
            foreach ($ruleProductAttrs as $ruleProductAttr) {
                $attributeId2 = isset($mappingAttributes[$ruleProductAttr->attribute_id]) ? $mappingAttributes[$ruleProductAttr->attribute_id] : null;
                $websiteId2 = isset($mappingWebsites[$ruleProductAttr->website_id]) ? $mappingWebsites[$ruleProductAttr->website_id] : null;
                $customerGroupId2 = isset($mappingCustomerGroups[$ruleProductAttr->customer_group_id]) ? $mappingCustomerGroups[$ruleProductAttr->customer_group_id] : null;
                if ($attributeId2 && !is_null($customerGroupId2) && !is_null($websiteId2)) {
                    $strCon = "rule_id = {$salesRule2->rule_id} AND website_id = {$websiteId2} AND customer_group_id = {$customerGroupId2} AND attribute_id = {$attributeId2}";
                    $ruleProductAttr2 = Mage2SalesruleProductAttribute::model()->find($strCon);
                    if (!$ruleProductAttr2) {
                        //add new
                        $ruleProductAttr2 = new Mage2SalesruleProductAttribute();
                        $ruleProductAttr2->rule_id = $salesRule2->rule_id;
                        $ruleProductAttr2->website_id = $websiteId2;
                        $ruleProductAttr2->customer_group_id = $customerGroupId2;
                        $ruleProductAttr2->attribute_id = $attributeId2;
                        if (!$ruleProductAttr2->save()) {
                            $errors[] = get_class($ruleProductAttr2) . ": " . UBMigrate::getStringErrors($ruleProductAttr2->getErrors());
                        } else {
                            $this->_traceInfo();
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesRuleWebsites($salesRule, $salesRule2, $mappingWebsites)
    {
        /**
         * Table: salesrule_website
         * This table was not exists in Magento 1.6.x
         */
        if (UBMigrate::getMG1Version() != 'mage16x') {
            $strMigratedWebsiteIds = implode(',', array_keys($mappingWebsites));
            $condition = "rule_id = {$salesRule->rule_id} AND website_id IN ({$strMigratedWebsiteIds})";
            $ruleWebsites = Mage1SalesruleWebsite::model()->findAll($condition);
            if ($ruleWebsites) {
                foreach ($ruleWebsites as $ruleWebsite) {
                    $websiteId2 = isset($mappingWebsites[$ruleWebsite->website_id]) ? $mappingWebsites[$ruleWebsite->website_id] : null;
                    if (!is_null($websiteId2)) {
                        $ruleWebsite2 = Mage2SalesruleWebsite::model()->find("rule_id = {$salesRule2->rule_id} AND website_id = {$websiteId2}");
                        if (!$ruleWebsite2) {
                            $ruleWebsite2 = new Mage2SalesruleWebsite();
                            $ruleWebsite2->rule_id = $salesRule2->rule_id;
                            $ruleWebsite2->website_id = $websiteId2;
                            if (!$ruleWebsite2->save()) {
                                $this->errors[] = get_class($ruleWebsite2) . ": " . UBMigrate::getStringErrors($ruleWebsite2->getErrors());
                            } else {
                                $this->_traceInfo();
                            }
                        }
                    }
                }
            }
        } else { // is Magento 1.6.x
            //update for table salesrule_website in Magento 2 from website_ids field in salesrule table in Magento 1.6.x
            if (isset($salesRule->website_ids) AND $salesRule->website_ids) {
                $websiteIds = explode(',', $salesRule->website_ids);
                if ($websiteIds) {
                    foreach ($websiteIds as $websiteId) {
                        $websiteId2 = isset($mappingWebsites[$websiteId]) ? $mappingWebsites[$websiteId] : null;
                        if (!is_null($websiteId2)) {
                            $ruleWebsite2 = Mage2SalesruleWebsite::model()->find("rule_id = {$salesRule2->rule_id} AND website_id = {$websiteId2}");
                            if (!$ruleWebsite2) {
                                $ruleWebsite2 = new Mage2SalesruleWebsite();
                                $ruleWebsite2->rule_id = $salesRule2->rule_id;
                                $ruleWebsite2->website_id = $websiteId2;
                                if (!$ruleWebsite2->save()) {
                                    $this->errors[] = get_class($ruleWebsite2) . ": " . UBMigrate::getStringErrors($ruleWebsite2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesRuleCustomerGroups($salesRule, $salesRule2, $mappingCustomerGroups)
    {
        /**
         * Table: salesrule_customer_group
         * This table was not exists in Magento 1.6.x
         */
        if (UBMigrate::getMG1Version() != 'mage16x') {
            $ruleCustomerGroups = Mage1SalesruleCustomerGroup::model()->findAll("rule_id = {$salesRule->rule_id}");
            if ($ruleCustomerGroups) {
                foreach ($ruleCustomerGroups as $ruleCustomerGroup) {
                    $customerGroupId2 = isset($mappingCustomerGroups[$ruleCustomerGroup->customer_group_id]) ? $mappingCustomerGroups[$ruleCustomerGroup->customer_group_id] : null;
                    if (!is_null($customerGroupId2)) {
                        $ruleCustomerGroup2 = Mage2SalesruleCustomerGroup::model()->find("rule_id = {$salesRule2->rule_id} AND customer_group_id = {$customerGroupId2}");
                        if (!$ruleCustomerGroup2) {
                            $ruleCustomerGroup2 = new Mage2SalesruleCustomerGroup();
                            $ruleCustomerGroup2->rule_id = $salesRule2->rule_id;
                            $ruleCustomerGroup2->customer_group_id = $customerGroupId2;
                            if (!$ruleCustomerGroup2->save()) {
                                $this->errors[] = get_class($ruleCustomerGroup2) . ": " . UBMigrate::getStringErrors($ruleCustomerGroup2->getErrors());
                            } else {
                                $this->_traceInfo();
                            }
                        }
                    }
                }
            }
        } else { // is Magento 1.6.x
            //update for table salesrule_customer_group in Magento 2 from customer_group_ids field in salesrule table in Magento 1.6.x
            if (isset($salesRule->customer_group_ids) AND $salesRule->customer_group_ids) {
                $cg_ids = explode(',', $salesRule->customer_group_ids);
                if ($cg_ids) {
                    foreach ($cg_ids as $cg_id) {
                        $customerGroupId2 = isset($mappingCustomerGroups[$cg_id]) ? $mappingCustomerGroups[$cg_id] : null;
                        if (!is_null($customerGroupId2)) {
                            $ruleCustomerGroup2 = Mage2SalesruleCustomerGroup::model()->find("rule_id = {$salesRule2->rule_id} AND customer_group_id = {$customerGroupId2}");
                            if (!$ruleCustomerGroup2) {
                                $ruleCustomerGroup2 = new Mage2SalesruleCustomerGroup();
                                $ruleCustomerGroup2->rule_id = $salesRule2->rule_id;
                                $ruleCustomerGroup2->customer_group_id = $customerGroupId2;
                                if (!$ruleCustomerGroup2->save()) {
                                    $this->errors[] = get_class($ruleCustomerGroup2) . ": " . UBMigrate::getStringErrors($ruleCustomerGroup2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesRuleCustomers($salesRule, $salesRule2)
    {
        //check has keep original customer ids in step #6
        $keepCustomerId = UBMigrate::getSetting(6, 'keep_original_id');
        /**
         * Table: salesrule_customer
         */
        $ruleCustomers = Mage1SalesruleCustomer::model()->findAll("rule_id = {$salesRule->rule_id}");
        if ($ruleCustomers) {
            foreach ($ruleCustomers as $ruleCustomer) {
                $customerId2 = (!$keepCustomerId) ? UBMigrate::getM2EntityId(6, 'customer_entity', $ruleCustomer->customer_id) : $ruleCustomer->customer_id;
                if ($customerId2) {
                    $condition = "rule_id = {$salesRule2->rule_id} AND customer_id = {$customerId2}";
                    $ruleCustomer2 = Mage2SalesruleCustomer::model()->find($condition);
                    if (!$ruleCustomer2) { //add new
                        $ruleCustomer2 = new Mage2SalesruleCustomer();
                        $ruleCustomer2->rule_id = $salesRule2->rule_id;
                        $ruleCustomer2->customer_id = $customerId2;
                    }
                    $ruleCustomer2->times_used = $ruleCustomer->times_used;
                    //save/update
                    if (!$ruleCustomer2->save()) {
                        $this->errors[] = get_class($ruleCustomer2) . ": " . UBMigrate::getStringErrors($ruleCustomer2->getErrors());
                    } else {
                        $this->_traceInfo();
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesOrderStatuses($orderStatuses, $mappingStores)
    {
        /**
         * Table: sales_order_status
         */
        $strMigratedStoreIds = implode(',', array_keys($mappingStores));
        foreach ($orderStatuses as $model) {
            $model2 = Mage2SalesOrderStatus::model()->find("status = '{$model->status}'");
            if (!$model2) {
                $model2 = new Mage2SalesOrderStatus();
                $model2->status = $model->status;
            }
            $model2->label = $model->label;
            //save/update
            if (!$model2->save()) {
                $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
            } else {
                $this->_traceInfo();
            }
            //migrate related data
            if ($model2->status) {
                /**
                 * Table: sales_order_status_label
                 */
                $condition = "status = '{$model->status}' AND store_id IN ({$strMigratedStoreIds})";
                $statusLabels = Mage1SalesOrderStatusLabel::model()->findAll($condition);
                if ($statusLabels) {
                    foreach ($statusLabels as $statusLabel) {
                        $storeId2 = isset($mappingStores[$statusLabel->store_id]) ? $mappingStores[$statusLabel->store_id] : null;
                        if (!is_null($storeId2)) {
                            $statusLabel2 = Mage2SalesOrderStatusLabel::model()->find("store_id = {$storeId2} AND status = '{$statusLabel->status}'");
                            if (!$statusLabel2) {
                                $statusLabel2 = new Mage2SalesOrderStatusLabel();
                                $statusLabel2->status = $model->status;
                                $statusLabel2->store_id = $storeId2;
                            }
                            $statusLabel2->label = $model->label;
                            if (!$statusLabel2->save()) {
                                $this->errors[] = get_class($statusLabel2) . ": " . UBMigrate::getStringErrors($statusLabel2->getErrors());
                            } else {
                                $this->_traceInfo();
                            }
                        }
                    }
                }
                /**
                 * Table: sales_order_status_state
                 */
                $statusStates = Mage1SalesOrderStatusState::model()->findAll("status = '{$model->status}'");
                if ($statusStates) {
                    foreach ($statusStates as $statusState) {
                        $statusState2 = Mage2SalesOrderStatusState::model()->find("status = '{$statusState->status}' AND state = '{$statusState->state}'");
                        if (!$statusState2) {
                            $statusState2 = new Mage2SalesOrderStatusState();
                            $statusState2->status = $statusState->status;
                            $statusState2->state = $statusState->state;
                            //this field is new in Magento 2
                            $statusState2->visible_on_front = 0; //default value is 0
                        }
                        $statusState2->is_default = $statusState->is_default;
                        if (!$statusState2->save()) {
                            $this->errors[] = get_class($statusState2) . ": " . UBMigrate::getStringErrors($statusState2->getErrors());
                        } else {
                            $this->_traceInfo();
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesOrders($salesOrders, $mappingStores, $mappingAttributes, $mappingCustomerGroups, $keepOriginalId)
    {
        //check has keep original customer ids
        $keepCustomerId = UBMigrate::getSetting(6, 'keep_original_id');
        //check has keep product ids
        $keepProductId = UBMigrate::getSetting(5, 'keep_original_id');
        //get mapping sales rules
        $mappingSalesRules = UBMigrate::getMappingData('salesrule', 7);

        /**
         * Table: sales_flat_order
         */
        foreach ($salesOrders as $salesOrder) {
            $storeId2 = isset($mappingStores[$salesOrder->store_id]) ? $mappingStores[$salesOrder->store_id] : null;
            $condition = "increment_id = '{$salesOrder->increment_id}'";
            if (is_null($storeId2)) {
                $condition .= " AND store_id IS NULL";
            } else {
                $condition .= " AND store_id = {$storeId2}";
            }
            $salesOrder2 = Mage2SalesOrder::model()->find($condition);
            if (!$salesOrder2) {
                $salesOrder2 = new Mage2SalesOrder();
                //fill values
                foreach ($salesOrder2->attributes as $key => $value) {
                    if (isset($salesOrder->$key)) {
                        /**
                         * Value of some fields in Magento 2 only accept max length is = 32 chars
                         * So we have to check length of that fields in here to split
                         */
                        $val = $salesOrder->$key;
                        if (in_array($key, array('store_name', 'shipping_method', 'x_forwarded_for', 'remote_ip', 'customer_taxvat', 'customer_suffix', 'customer_prefix')) AND strlen($val) > 32) {
                            $val = substr($val, 0, 32);
                        } elseif (in_array($key, array('applied_rule_ids')) AND strlen($val) > 128) {
                            $val = str_replace(' ', '', $val);
                            $val = substr($val, 0, 128);
                        } elseif (in_array($key, array(
                                'weight','base_grand_total','base_subtotal','grand_total','subtotal',
                                'base_subtotal_incl_tax','subtotal_incl_tax')) AND strlen($val) > 12) {
                            $val = str_replace(' ', '', $val);
                            $val = substr($val, 0, 12);
                        } elseif (in_array($key, array('shipping_description')) AND strlen($val) > 255) {
                            $val = substr(trim($val), 0, 255);
                        }
                        $salesOrder2->$key = $val;
                    }
                }
                $salesOrder2->entity_id = ($keepOriginalId) ? $salesOrder->entity_id : null;
                //because ids of some related entities was changed
                $salesOrder2->store_id = $storeId2;
                if (!is_null($salesOrder2->customer_group_id)) {
                    $salesOrder2->customer_group_id = (isset($mappingCustomerGroups[$salesOrder->customer_group_id])) ? $mappingCustomerGroups[$salesOrder->customer_group_id] : null;
                }
                $salesOrder2->customer_id = (!$keepCustomerId) ? UBMigrate::getM2EntityId(6, 'customer_entity', $salesOrder->customer_id) : $salesOrder->customer_id;
                if (!$keepOriginalId) {
                    $salesOrder2->shipping_address_id = UBMigrate::getM2EntityId('7_order_address', 'sales_flat_order_address', $salesOrder->shipping_address_id);
                    $salesOrder2->billing_address_id = UBMigrate::getM2EntityId('7_order_address', 'sales_flat_order_address', $salesOrder->billing_address_id);
                    if ($salesOrder2->applied_rule_ids) { //salesrule
                        $appliedRuleIds = explode(',', $salesOrder2->applied_rule_ids);
                        $appliedRuleIds2 = [];
                        foreach ($appliedRuleIds as $id) {
                            if (isset($mappingSalesRules[$id])) {
                                $appliedRuleIds2[] =  $mappingSalesRules[$id];
                            }
                        }
                        $salesOrder2->applied_rule_ids = implode(',', $appliedRuleIds2);
                    }
                }
                //some attributes which we have to re-update values on it after migrated all sales orders: quote_id,quote_address_id
                //ext_customer_id, ext_order_id,
                //relation_child_id (order id), relation_child_real_id (increment_id), => coming soon
                //relation_parent_id (order id),relation_parent_real_id (increment_id), => coming soon
                //save
                if ($salesOrder2->updated_at === '0000-00-00 00:00:00' || empty($salesOrder2->updated_at)) {
                    $salesOrder2->updated_at = date("Y-m-d H:i:s");
                }
                if ($salesOrder2->created_at === '0000-00-00 00:00:00' || empty($salesOrder2->created_at)) {
                    $salesOrder2->created_at = date("Y-m-d H:i:s");
                }
                if (!$salesOrder2->save()) {
                    $this->errors[] = get_class($salesOrder2) . ": " . UBMigrate::getStringErrors($salesOrder2->getErrors());
                } else {
                    //save to map table
                    UBMigrate::log([
                        'entity_name' => $salesOrder->tableName(),
                        'm1_id' => $salesOrder->entity_id,
                        'm2_id' => $salesOrder2->entity_id,
                        'm2_model_class' => get_class($salesOrder2),
                        'm2_key_field' => 'entity_id',
                        'can_reset' => UBMigrate::RESET_YES,
                        'step_index' => "7Order"
                    ]);
                    $this->_traceInfo();
                }
            } else {
                //update
                foreach ($salesOrder2->attributes as $key => $value) {
                    if (isset($salesOrder->$key) AND !in_array($key, array('entity_id','is_virtual','store_id',
                            'customer_id','customer_group_id','increment_id','customer_email'))) {
                        /**
                         * Value of some fields in Magento 2 only accept max length is = 32 chars
                         * So we have to check length of that fields in here to split
                         */
                        $val = $salesOrder->$key;
                        if (in_array($key, array('store_name', 'x_forwarded_for', 'remote_ip', 'customer_taxvat', 'customer_suffix', 'customer_prefix')) AND strlen($val) > 32) {
                            $val = substr($val, 0, 32);
                        } elseif (in_array($key, array('applied_rule_ids')) AND strlen($val) > 128) {
                            $val = str_replace(' ', '', $val);
                            $val = substr($val, 0, 128);
                        } elseif (in_array($key, array(
                                'weight','base_grand_total','base_subtotal','grand_total','subtotal',
                                'base_subtotal_incl_tax','subtotal_incl_tax')) AND strlen($val) > 12) {
                            $val = str_replace(' ', '', $val);
                            $val = substr($val, 0, 12);
                        } elseif (in_array($key, array('shipping_description')) AND strlen($val) > 255) {
                            $val = substr(trim($val), 0, 255);
                        } elseif (in_array($key, array('shipping_method')) AND strlen($val) > 120) {
                            $val = substr(trim($val), 0, 120);
                        }
                        $salesOrder2->$key = $val;
                    }
                }

                if (!$keepOriginalId) {
                    $salesOrder2->shipping_address_id = UBMigrate::getM2EntityId('7_order_address', 'sales_flat_order_address', $salesOrder->shipping_address_id);
                    $salesOrder2->billing_address_id = UBMigrate::getM2EntityId('7_order_address', 'sales_flat_order_address', $salesOrder->billing_address_id);
                    if ($salesOrder2->applied_rule_ids) { //related to salesrule table
                        $appliedRuleIds = explode(',', $salesOrder2->applied_rule_ids);
                        $appliedRuleIds2 = [];
                        foreach ($appliedRuleIds as $id) {
                            if (isset($mappingSalesRules[$id])) {
                                $appliedRuleIds2[] =  $mappingSalesRules[$id];
                            }
                        }
                        $salesOrder2->applied_rule_ids = implode(',', $appliedRuleIds2);
                    }
                }
                if ($salesOrder2->updated_at === '0000-00-00 00:00:00' || empty($salesOrder2->updated_at)) {
                    $salesOrder2->updated_at = date("Y-m-d H:i:s");
                }
                if ($salesOrder2->update()) {
                    $this->_traceInfo();
                }
            }
            //migrate related data
            if ($salesOrder2->entity_id) {
                /**
                 * migrate sales oder grid
                 */
                $this->_migrateSalesOrderGrid($salesOrder, $salesOrder2, $mappingStores, $keepCustomerId);
                /**
                 * migrate sales order status history
                 */
                $this->_migrateSalesOrderStatusHistory($salesOrder->entity_id, $salesOrder2->entity_id);
                /**
                 * migrate sales quote of sales order
                 * we only migrate the sales quote, which has placed a sales order
                 */
                $this->_migrateSalesQuote($salesOrder2, $mappingStores, $mappingCustomerGroups, $keepOriginalId, $keepCustomerId, $keepProductId);
                /**
                 * migrate sales order items
                 */
                $this->_migrateSalesOrderItem($salesOrder->entity_id, $salesOrder2->entity_id, $mappingStores, $mappingAttributes, $mappingSalesRules, $keepOriginalId);
                /**
                 * migrate sales order address
                 */
                $this->_migrateSalesOrderAddress($salesOrder->entity_id, $salesOrder2->entity_id, $keepOriginalId, $keepCustomerId);
                /**
                 * migrate sales payments
                 */
                $this->_migrateSalesPayment($salesOrder->entity_id, $salesOrder2->entity_id, $keepOriginalId);
                /**
                 * migrate sales invoices
                 */
                $this->_migrateSalesInvoice($salesOrder->entity_id, $salesOrder2->entity_id, $mappingStores, $keepOriginalId);
                /**
                 * migrate sales shipments
                 */
                $this->_migrateSalesShipment($salesOrder->entity_id, $salesOrder2->entity_id, $mappingStores, $keepOriginalId, $keepCustomerId);
                /**
                 * migrate sales creditmemo
                 */
                $this->_migrateSalesCreditmemo($salesOrder->entity_id, $salesOrder2->entity_id, $mappingStores, $keepOriginalId);
                /**
                 * migrate sales order tax
                 */
                $this->_migrateSalesOrderTax($salesOrder->entity_id, $salesOrder2->entity_id, $keepOriginalId);
            }
        }

        return true;
    }

    private function _migrateSalesQuote($salesOrder2, $mappingStores, $mappingCustomerGroups, $keepOriginalId, $keepCustomerId, $keepProductId)
    {
        //get mapping sales rules
        $mappingSalesRules = UBMigrate::getMappingData('salesrule', 7);
        //we have migrated customer tax classes in step 6 so we can get mapping here
        $mappingTaxClasses = UBMigrate::getMappingData('tax_class', 6);
        /**
         * Table: sales_flat_quote
         */
        if ($salesOrder2->quote_id) {
            $quote = Mage1SalesQuote::model()->find("entity_id = {$salesOrder2->quote_id}");
            if ($quote) {
                $storeId2 = isset($mappingStores[$quote->store_id]) ? $mappingStores[$quote->store_id] : null;
                if (!is_null($storeId2)) {
                    //check has migrated
                    $m2Id = UBMigrate::getM2EntityId('7_quote', 'sales_flat_quote', $quote->entity_id);
                    if (is_null($m2Id)) {
                        //add new
                        $quote2 = new Mage2SalesQuote();
                        //fill values
                        foreach ($quote2->attributes as $key => $value) {
                            if (isset($quote->$key)) {
                                if (in_array($key, array('base_grand_total', 'grand_total')) AND strlen($quote->$key) > 12) {
                                    $quote2->$key = substr(trim($quote->$key), 0, 12);
                                } else {
                                    $quote2->$key = $value;
                                }
                            }
                        }
                        $quote2->entity_id = ($keepOriginalId) ? $quote->entity_id : null;
                        if (empty($quote2->created_at)) {
                            $quote2->created_at = date("Y-m-d H:i:s");
                        }
                        if ($quote2->updated_at === '0000-00-00 00:00:00' || empty($quote2->updated_at)) {
                            $quote2->updated_at = date("Y-m-d H:i:s");
                        }
                        if ($quote2->converted_at === '0000-00-00 00:00:00') {
                            $quote2->converted_at = null;
                        }
                        //because some entity ids was changed
                        $quote2->store_id = $storeId2;
                        if (!$keepOriginalId && $quote2->orig_order_id) {
                            $quote2->orig_order_id = UBMigrate::getM2EntityId('7_order', 'sales_flat_order', $quote2->orig_order_id);
                        }
                        if ($quote2->customer_group_id) {
                            $quote2->customer_group_id = isset($mappingCustomerGroups[$quote2->customer_group_id]) ? $mappingCustomerGroups[$quote2->customer_group_id] : 0;
                        }
                        if (!$keepCustomerId && $quote2->customer_id) {
                            $quote2->customer_id = UBMigrate::getM2EntityId(6, 'customer_entity', $quote2->customer_id);
                        }
                        if (!$keepOriginalId && $quote2->applied_rule_ids) {
                            $appliedRuleIds = explode(',', $quote2->applied_rule_ids);
                            $appliedRuleIds2 = [];
                            if (is_array($appliedRuleIds)) {
                                foreach ($appliedRuleIds as $id) {
                                    if (isset($mappingSalesRules[$id])) {
                                        $appliedRuleIds2[] = $mappingSalesRules[$id];
                                    }
                                }
                            }
                            $quote2->applied_rule_ids = implode(',', $appliedRuleIds2);
                        }
                        $quote2->customer_tax_class_id = isset($mappingTaxClasses[$quote2->customer_tax_class_id]) ? $mappingTaxClasses[$quote2->customer_tax_class_id] : null;
                    } else {
                        //update
                        $quote2 = Mage2SalesQuote::model()->find("entity_id = {$m2Id}");
                        //update values
                        foreach ($quote2->attributes as $key => $value) {
                            if (isset($quote->$key) AND !in_array($key, array('entity_id','store_id','orig_order_id',
                                    'customer_group_id','customer_id','created_at'))) {
                                if (in_array($key, array('base_grand_total', 'grand_total')) AND strlen($quote->$key) > 12) {
                                    $quote2->$key = substr(trim($quote->$key), 0, 12);
                                } else {
                                    $quote2->$key = $value;
                                }
                            }
                        }
                        if (!$keepOriginalId && $quote2->applied_rule_ids) {
                            $appliedRuleIds = explode(',', $quote2->applied_rule_ids);
                            $appliedRuleIds2 = [];
                            if (is_array($appliedRuleIds)) {
                                foreach ($appliedRuleIds as $id) {
                                    if (isset($mappingSalesRules[$id])) {
                                        $appliedRuleIds2[] = $mappingSalesRules[$id];
                                    }
                                }
                            }
                            $quote2->applied_rule_ids = implode(',', $appliedRuleIds2);
                        }
                        $quote2->customer_tax_class_id = isset($mappingTaxClasses[$quote2->customer_tax_class_id]) ? $mappingTaxClasses[$quote2->customer_tax_class_id] : null;
                    }
                    //save/update
                    if (!$quote2->save()) {
                        $this->errors[] = get_class($quote2) . ": " . UBMigrate::getStringErrors($quote2->getErrors());
                    } else {
                        if (is_null($m2Id)) {
                            UBMigrate::log([
                                'entity_name' => $quote->tableName(),
                                'm1_id' => $quote->entity_id,
                                'm2_id' => $quote2->entity_id,
                                'm2_model_class' => get_class($quote2),
                                'm2_key_field' => 'entity_id',
                                'can_reset' => UBMigrate::RESET_YES,
                                'step_index' => "7Quote"
                            ]);
                        }
                        $this->_traceInfo();
                        //migrate sales quote item
                        $this->_migrateSalesQuoteItem($quote->entity_id, $quote2->entity_id, $mappingStores, $mappingSalesRules, $keepOriginalId, $keepProductId);
                        //migrate sales quote_payment
                        $this->_migrateSalesQuotePayment($quote->entity_id, $quote2->entity_id, $keepOriginalId);
                        //migrate sales quote_address
                        $this->_migrateSalesQuoteAddress($salesOrder2, $quote->entity_id, $quote2->entity_id, $mappingSalesRules, $keepOriginalId, $keepCustomerId);
                        //we have to re-update value of some fields in main table - sales_order
                        $salesOrder2->quote_id = $quote2->entity_id;
                        $salesOrder2->update();
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesQuoteItem($quoteId1, $quoteId2, $mappingStores, $mappingSalesRules, $keepOriginalId, $keepProductId)
    {
        /**
         * Table: sales_flat_quote_item
         */
        $models = Mage1SalesQuoteItem::model()->findAll("quote_id = {$quoteId1}");
        if ($models) {
            foreach ($models as $model) {
                $storeId2 = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
                //check has migrated
                $m2Id = UBMigrate::getM2EntityId('7_quote_item', 'sales_flat_quote_item', $model->item_id);
                if (is_null($m2Id)) {
                    //add new
                    $model2 = new Mage2SalesQuoteItem();
                    //fill values
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key)) {
                            $val = $model->$key;
                            if (in_array($key, array('weight', 'price', 'base_price', 'price_incl_tax', 'base_price_incl_tax', 'row_total', 'base_row_total', 'row_weight', 'row_total_incl_tax', 'base_row_total_incl_tax')) AND strlen(trim($val)) > 12) {
                                $val = substr(trim($val), 0, 12);
                            }
                            $model2->$key = $val;
                        }
                    }
                    $model2->item_id = ($keepOriginalId) ? $model->item_id : null;
                    //because some entity ids was changed
                    $model2->store_id = $storeId2;
                    $model2->quote_id = $quoteId2;
                    if (!$keepProductId) {
                        $model2->product_id = UBMigrate::getM2EntityId(5, 'catalog_product_entity', $model->product_id);
                    }
                    if (!$keepOriginalId && $model2->parent_item_id) {
                        $model2->parent_item_id = UBMigrate::getM2EntityId('7_quote_item', 'sales_flat_quote_item', $model2->parent_item_id);
                    }
                    if (!$keepOriginalId && $model2->applied_rule_ids) {
                        $appliedRuleIds = explode(',', $model2->applied_rule_ids);
                        $appliedRuleIds2 = [];
                        if (is_array($appliedRuleIds)) {
                            foreach ($appliedRuleIds as $id) {
                                if (isset($mappingSalesRules[$id])) {
                                    $appliedRuleIds2[] = $mappingSalesRules[$id];
                                }
                            }
                        }
                        $model2->applied_rule_ids = implode(',', $appliedRuleIds2);
                    }
                } else {
                    //update
                    $model2 = Mage2SalesQuoteItem::model()->find("item_id = {$m2Id}");
                    //update values
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key) AND !in_array($key, array('item_id','store_id','quote_id','product_id','parent_item_id','created_at'))) {
                            $val = $model->$key;
                            if (in_array($key, array('weight', 'price', 'base_price', 'price_incl_tax', 'base_price_incl_tax', 'row_total', 'base_row_total', 'row_weight', 'row_total_incl_tax', 'base_row_total_incl_tax')) AND strlen(trim($val)) > 12) {
                                $val = substr(trim($val), 0, 12);
                            }
                            $model2->$key = $val;
                        }
                    }
                    if (!$keepOriginalId && $model2->applied_rule_ids) {
                        $appliedRuleIds = explode(',', $model2->applied_rule_ids);
                        $appliedRuleIds2 = [];
                        if (is_array($appliedRuleIds)) {
                            foreach ($appliedRuleIds as $id) {
                                if (isset($mappingSalesRules[$id])) {
                                    $appliedRuleIds2[] = $mappingSalesRules[$id];
                                }
                            }
                        }
                        $model2->applied_rule_ids = implode(',', $appliedRuleIds2);
                    }
                }
                //save/update
                if (!$model2->save()) {
                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                } else {
                    if (is_null($m2Id)) {
                        //update to map log
                        UBMigrate::log([
                            'entity_name' => $model->tableName(),
                            'm1_id' => $model->item_id,
                            'm2_id' => $model2->item_id,
                            'm2_model_class' => get_class($model2),
                            'm2_key_field' => 'item_id',
                            'can_reset' => UBMigrate::RESET_YES,
                            'step_index' => "7QuoteItem"
                        ]);
                    }
                    $this->_traceInfo();
                    /**
                     * Table: sales_flat_quote_item_option
                     */
                    $itemOptions = Mage1SalesQuoteItemOption::model()->findAll("item_id = {$model->item_id}");
                    if ($itemOptions) {
                        foreach ($itemOptions as $itemOption) {
                            $productId2 = (!$keepProductId) ? UBMigrate::getM2EntityId(5, 'catalog_product_entity', $itemOption->product_id) : $itemOption->product_id;
                            if ($productId2) {
                                $optCode2 = trim($itemOption->code);
                                $optValue2 = $itemOption->value;
                                //we have to re-update new ids in M2 for code and value
                                $this->_convertQuoteItemOptionCodeValue($productId2, $optCode2, $optValue2, $keepProductId);
                                //check has existed
                                $condition = "item_id = {$model2->item_id} AND product_id = {$productId2} AND code = '{$optCode2}'";
                                $itemOption2 = Mage2SalesQuoteItemOption::model()->find($condition);
                                if (!$itemOption2) {
                                    $itemOption2 = new Mage2SalesQuoteItemOption();
                                    $itemOption2->option_id = ($keepOriginalId) ? $itemOption->option_id : null;
                                    //because some entity ids was changed
                                    $itemOption2->item_id = $model2->item_id;
                                    $itemOption2->product_id = $productId2;
                                    $itemOption2->code = $optCode2;
                                }
                                $itemOption2->value = $optValue2;
                                //save/update
                                if (!$itemOption2->save()) {
                                    $this->errors[] = get_class($itemOption2) . ": " . UBMigrate::getStringErrors($itemOption2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesQuotePayment($quoteId1, $quoteId2, $keepOriginalId)
    {
        /**
         * Table: sales_flat_quote_payment
         */
        $models = Mage1SalesQuotePayment::model()->findAll("quote_id = {$quoteId1}");
        if ($models) {
            foreach ($models as $model) {
                $condition = "quote_id = {$quoteId2} AND created_at = '{$model->created_at}'";
                $model2 = Mage2SalesQuotePayment::model()->find($condition);
                if (!$model2) {
                    $model2 = new Mage2SalesQuotePayment();
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key)) {
                            $model2->$key = $model->$key;
                        }
                    }
                    $model2->payment_id = ($keepOriginalId) ? $model->payment_id : null;
                    $model2->quote_id = $quoteId2;
                } else {
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key) AND !in_array($key, array('payment_id','quote_id','created_at'))) {
                            $model2->$key = $model->$key;
                        }
                    }
                }
                //save/update
                if (!$model2->save()) {
                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                } else {
                    $this->_traceInfo();
                }
            }
        }

        return true;
    }

    private function _migrateSalesQuoteAddress(&$salesOrder2, $quoteId1, $quoteId2, $mappingSalesRules, $keepOriginalId, $keepCustomerId)
    {
        //check has keep product ids in the step #5
        $keepProductId = UBMigrate::getSetting(5, 'keep_original_id');
        /**
         * Table: sales_flat_quote_address
         */
        $models = Mage1SalesQuoteAddress::model()->findAll("quote_id = {$quoteId1}");
        if ($models) {
            foreach ($models as $model) {
                //check has migrated
                $m2Id = UBMigrate::getM2EntityId('7_quote_address', 'sales_flat_quote_address', $model->address_id);
                if (is_null($m2Id)) {
                    $model2 = new Mage2SalesQuoteAddress();
                    //fill values
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key)) {
                            /**
                             * Have some new max length rule in Magento 2
                             * So we have to check length to split here
                             */
                            $val = $model->$key;
                            if (in_array($key, array('region', 'city')) AND strlen($val) > 40) {
                                $val = substr($val, 0, 40);
                            } elseif (in_array($key, array('postcode', 'telephone', 'fax')) AND strlen($val) > 20) {
                                $val = substr($val, 0, 20);
                            } elseif (in_array($key, array('country_id')) AND strlen($val) > 30) {
                                $val = substr($val, 0, 30);
                            } elseif (in_array($key, array( 'discount_amount',
                                    'base_discount_amount','weight', 'subtotal',
                                    'base_subtotal','grand_total',
                                    'base_grand_total','subtotal_incl_tax',
                                    'shipping_amount','base_shipping_amount',
                                    'shipping_incl_tax','base_shipping_incl_tax'
                                    )) AND strlen($val) > 12) {
                                $val = substr($val, 0, 12);
                            } elseif (in_array($key, array('address_type')) AND strlen($val) > 10) {
                                $val = substr($val, 0, 10);
                            } elseif (in_array($key, array('shipping_method')) AND strlen($val) > 120) {
                                $val = substr($val, 0, 120);
                            }
                            $model2->$key = $val;
                        }
                    }
                    $model2->address_id = ($keepOriginalId) ? $model->address_id : null;
                    //because some entity ids was changed
                    $model2->quote_id = $quoteId2;
                    if (!$keepCustomerId && $model2->customer_id) {
                        $model2->customer_id = UBMigrate::getM2EntityId(6, 'customer_entity', $model2->customer_id);
                    }
                    if (!$keepCustomerId && $model2->customer_address_id) {
                        $model2->customer_address_id = UBMigrate::getM2EntityId('6_customer_address', 'customer_address_entity', $model2->customer_address_id);
                    }
                    if (!$keepOriginalId && $model2->applied_taxes) {
                        $appliedTaxes = UBMigrate::mb_unserialize($model2->applied_taxes);
                        foreach ($appliedTaxes as $key => $tax) {
                            if (isset($tax['rates']) AND $tax['rates']) {
                                foreach ($tax['rates'] as $key2 => $value) {
                                    if (isset($value['rule_id']) AND $value['rule_id'] AND isset($mappingSalesRules[$value['rule_id']])) {
                                        $appliedTaxes[$key]['rates'][$key2]['rule_id'] = $mappingSalesRules[$value['rule_id']];
                                    }
                                }
                            }
                        }
                        //$model2->applied_taxes = serialize($appliedTaxes);
                        $model2->applied_taxes = UbMigrate::encodeJson($appliedTaxes); // this was changed from Magento ver.2.2.0
                    }
                } else {
                    //update
                    $model2 = Mage2SalesQuoteAddress::model()->find("address_id = {$m2Id}");
                    //update values
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key) AND !in_array($key, array('address_id','quote_id','customer_id','customer_address_id'))) {
                            /**
                             * Have some new max length rule in Magento 2
                             * So we have to check length to split here
                             */
                            $val = $model->$key;
                            if (in_array($key, array('region', 'shipping_method', 'city')) AND strlen($val) > 40) {
                                $val = substr($val, 0, 40);
                            } elseif (in_array($key, array('firstname', 'lastname', 'postcode', 'telephone', 'fax')) AND strlen($val) > 20) {
                                $val = substr($val, 0, 20);
                            } elseif (in_array($key, array('country_id')) AND strlen($val) > 30) {
                                $val = substr($val, 0, 30);
                            } elseif (in_array($key, array( 'discount_amount', 'base_discount_amount','weight', 'subtotal', 'base_subtotal','grand_total', 'base_grand_total','subtotal_incl_tax')) AND strlen($val) > 12) {
                                $val = substr($val, 0, 12);
                            } elseif (in_array($key, array('address_type')) AND strlen($val) > 10) {
                                $val = substr($val, 0, 10);
                            }
                            $model2->$key = $val;
                        }
                    }
                    if (!$keepOriginalId && $model2->applied_taxes) {
                        $appliedTaxes = UBMigrate::mb_unserialize($model2->applied_taxes);
                        foreach ($appliedTaxes as $key => $tax) {
                            if (isset($tax['rates']) AND $tax['rates']) {
                                foreach ($tax['rates'] as $key2 => $value) {
                                    if (isset($value['rule_id']) AND $value['rule_id'] AND isset($mappingSalesRules[$value['rule_id']])) {
                                        $appliedTaxes[$key]['rates'][$key2]['rule_id'] = $mappingSalesRules[$value['rule_id']];
                                    }
                                }
                            }
                        }
                        //$model2->applied_taxes = serialize($appliedTaxes);
                        $model2->applied_taxes = UbMigrate::encodeJson($appliedTaxes); // this was changed from Magento ver.2.2.0
                    }
                }
                //save/update
                if ($model2->save()) {
                    if (is_null($m2Id)) {
                        //update to map log
                        UBMigrate::log([
                            'entity_name' => $model->tableName(),
                            'm1_id' => $model->address_id,
                            'm2_id' => $model2->address_id,
                            'm2_model_class' => get_class($model2),
                            'm2_key_field' => 'address_id',
                            'can_reset' => UBMigrate::RESET_YES,
                            'step_index' => "7QuoteAddress"
                        ]);
                    }
                    $this->_traceInfo();

                    //re-update quote_address_id for sales_order if it has
                    if ($salesOrder2->quote_address_id AND ($model->address_id == $salesOrder2->quote_address_id)) {
                        $salesOrder2->quote_address_id = $model2->address_id;
                    }

                    /**
                     * Table: sales_flat_quote_address_item
                     */
                    $addressItems = Mage1SalesQuoteAddressItem::model()->findAll("quote_address_id = {$model->address_id}");
                    if ($addressItems) {
                        $addressItemMappingIds = [];
                        foreach ($addressItems as $addressItem) {
                            $quoteItemId2 = UBMigrate::getM2EntityId('7_quote_item', 'sales_flat_quote_item', $addressItem->quote_item_id);
                            if ($quoteItemId2) { 
                                $condition = "quote_address_id = {$model2->address_id} AND quote_item_id = {$quoteItemId2} AND created_at = '$addressItem->created_at'";
                                $addressItem2 = Mage2SalesQuoteAddressItem::model()->find($condition);
                                if (!$addressItem2) {
                                    //add new
                                    $addressItem2 = new Mage2SalesQuoteAddressItem();
                                    foreach ($addressItem2->attributes as $key => $value) {
                                        if (isset($addressItem->$key)) {
                                            $val = trim($addressItem->$key);
                                            if (in_array($key, array('row_weight')) && strlen($val) > 12) {
                                                $val = substr($val, 0, 12);
                                            }
                                            $addressItem2->$key = $val;
                                        }
                                    }

                                    $addressItem2->address_item_id = ($keepOriginalId) ? $addressItem->address_item_id : null;
                                    if (!$keepOriginalId && $addressItem2->parent_item_id) {
                                        $addressItem2->parent_item_id = $addressItemMappingIds[$addressItem2->parent_item_id];
                                    }
                                    $addressItem2->quote_address_id = $model2->address_id;
                                    $addressItem2->quote_item_id = $quoteItemId2;
                                    if (!$keepOriginalId && $addressItem2->applied_rule_ids) {
                                        $appliedRuleIds = explode(',', $addressItem2->applied_rule_ids);
                                        $appliedRuleIds2 = [];
                                        foreach ($appliedRuleIds as $id) {
                                            if (isset($mappingSalesRules[$id])) {
                                                $appliedRuleIds2[] = $mappingSalesRules[$id];
                                            }
                                        }
                                        $addressItem2->applied_rule_ids = implode(',', $appliedRuleIds2);
                                    }
                                    if (!$keepProductId) {
                                        $addressItem2->product_id = UBMigrate::getM2EntityId('5', 'catalog_product_entity', $addressItem2->product_id);
                                        if ($addressItem2->super_product_id) {
                                            $addressItem2->super_product_id = UBMigrate::getM2EntityId('5', 'catalog_product_entity', $addressItem2->super_product_id);
                                        }
                                        if ($addressItem2->parent_product_id) {
                                            $addressItem2->parent_product_id = UBMigrate::getM2EntityId('5', 'catalog_product_entity', $addressItem2->parent_product_id);
                                        }
                                    }
                                    if (!$addressItem2->save()) {
                                        $this->errors[] = get_class($addressItem2) . ": " . UBMigrate::getStringErrors($addressItem2->getErrors());
                                    } else {
                                        //mapping to update for child items
                                        $addressItemMappingIds[$addressItem->address_item_id] = $addressItem2->address_item_id;
                                        $this->_traceInfo();
                                    }
                                }
                            }
                        }
                    }
                    /**
                     * Table: sales_flat_quote_shipping_rate
                     */
                    $shippingRates = Mage1SalesQuoteShippingRate::model()->findAll("address_id = {$model->address_id}");
                    if ($shippingRates) {
                        foreach ($shippingRates as $shippingRate) {
                            $condition = "address_id = {$model2->address_id} AND created_at = '{$model->created_at}'";
                            $shippingRate2 = Mage2SalesQuoteShippingRate::model()->find($condition);
                            if ($shippingRate2) {
                                $shippingRate2 = new Mage2SalesQuoteShippingRate();
                                foreach ($shippingRate2->attributes as $key => $value) {
                                    if (isset($shippingRate->$key)) {
                                        $shippingRate2->$key = $shippingRate->$key;
                                    }
                                }
                                $shippingRate2->rate_id = ($keepOriginalId) ? $shippingRate->rate_id : null;
                                $shippingRate2->address_id = $model2->address_id;
                                if (!$shippingRate2->save()) {
                                    $this->errors[] = get_class($shippingRate2) . ": " . UBMigrate::getStringErrors($shippingRate2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                } else {
                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                }
            }
        }

        return true;
    }

    private function _convertProductOptions($productOptions, $mappingAttributes, $keepProductId, $keepOriginalId)
    {
        if ($productOptions) {
            if ($productOptions = UBMigrate::mb_unserialize($productOptions)) {
                //common case
                if (!$keepProductId AND isset($productOptions['info_buyRequest']['product']) AND $productOptions['info_buyRequest']['product']) {
                    $productOptions['info_buyRequest']['product'] = UBMigrate::getM2EntityId(5, 'catalog_product_entity', $productOptions['info_buyRequest']['product']);
                }
                if (isset($productOptions['info_buyRequest']['super_attribute']) AND $productOptions['info_buyRequest']['super_attribute']) {
                    $superAttributes = [];
                    foreach ($productOptions['info_buyRequest']['super_attribute'] as $attributeId => $attributeOptionId) {
                        $attributeId2 = isset($mappingAttributes[$attributeId]) ? $mappingAttributes[$attributeId] : null;
                        $superAttributes[$attributeId2] = UBMigrate::getM2EntityId('3_attribute_option', 'eav_attribute_option', $attributeOptionId);
                    }
                    $productOptions['info_buyRequest']['super_attribute'] = $superAttributes;
                }
                //downloadable product
                if (isset($productOptions['links']) AND $productOptions['links']) {
                    $links2 = [];
                    foreach ($productOptions['links'] as $key => $linkId) {
                        $links2[$key] = UBMigrate::getM2EntityId('5_product_download', 'downloadable_link', $linkId);
                    }
                    $productOptions['links'] = $links2;
                    if (isset($productOptions['info_buyRequest']['links'])) {
                        $productOptions['info_buyRequest']['links'] = $links2;
                    }
                }
                //grouped product
                if (!$keepProductId AND isset($productOptions['super_product_config']['product_id']) AND $productOptions['super_product_config']['product_id']) {
                    $productId2 = UBMigrate::getM2EntityId(5, 'catalog_product_entity', $productOptions['super_product_config']['product_id']);
                    $productOptions['super_product_config']['product_id'] = $productId2;
                    if (isset($productOptions['info_buyRequest']['super_product_config']['product_id'])) {
                        $productOptions['info_buyRequest']['super_product_config']['product_id'] = $productId2;
                    }
                }
                //bundle products
                if (!$keepProductId AND isset($productOptions['info_buyRequest']['bundle_option']) AND $productOptions['info_buyRequest']['bundle_option']) {
                    $bundleOption = [];
                    $bundleOptionQtys = [];
                    $bundleOptions = [];
                    foreach ($productOptions['info_buyRequest']['bundle_option'] as $bundleOptionId => $bundleSelectionId) {
                        $bundleOptionId2 = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_option', $bundleOptionId);
                        if (is_array($bundleSelectionId)) {
                            foreach ($bundleSelectionId as $key => $selectionId) {
                                if ($selectionId) {
                                    $bundleSelectionId[$key] = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_selection', $selectionId);
                                }
                            }
                            $bundleOption[$bundleOptionId2] = $bundleSelectionId;
                        } else {
                            if ($bundleSelectionId) {
                                $bundleOption[$bundleOptionId2] = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_selection', $bundleSelectionId);
                            }
                        }
                        //update option id for qty array
                        if (isset($productOptions['info_buyRequest']['bundle_option_qty']) AND isset($productOptions['info_buyRequest']['bundle_option_qty'][$bundleOptionId])) {
                            $bundleOptionQtys[$bundleOptionId2] = $productOptions['info_buyRequest']['bundle_option_qty'][$bundleOptionId];
                        }
                        //update for bundle_options in parent node
                        if (isset($productOptions['bundle_options'][$bundleOptionId])) {
                            $productOptions['bundle_options'][$bundleOptionId]['option_id'] = $bundleOptionId2;
                            $bundleOptions[$bundleOptionId2] = $productOptions['bundle_options'][$bundleOptionId];
                        }
                    }
                    $productOptions['info_buyRequest']['bundle_option'] = $bundleOption;
                    if (isset($productOptions['info_buyRequest']['bundle_option_qty'])) {
                        $productOptions['info_buyRequest']['bundle_option_qty'] = $bundleOptionQtys;
                    }
                    if ($bundleOptions) {
                        $productOptions['bundle_options'] = $bundleOptions;
                    }
                }
                if (isset($productOptions['bundle_selection_attributes']) AND $productOptions['bundle_selection_attributes']) {
                    $productOptions['bundle_selection_attributes'] = UBMigrate::mb_unserialize($productOptions['bundle_selection_attributes']);
                    if (!$keepProductId) {
                        if (isset($productOptions['bundle_selection_attributes']['option_id']) && $productOptions['bundle_selection_attributes']['option_id']) {
                            $productOptions['bundle_selection_attributes']['option_id'] = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_option', $productOptions['bundle_selection_attributes']['option_id']);
                        }
                    }
                    //this changed from Magento ver.2.2.0
                    $productOptions['bundle_selection_attributes'] = UBMigrate::encodeJson($productOptions['bundle_selection_attributes']);
                }

                //giftcard
                if (!$keepOriginalId AND isset($productOptions['giftcard_paid_invoice_items']) AND $productOptions['giftcard_paid_invoice_items']) {
                    $invoiceItems2 = [];
                    foreach ($productOptions['giftcard_paid_invoice_items'] as $key => $invoiceItemId) {
                        $invoiceItems2[$key] = UBMigrate::getM2EntityId("7_invoice_item", 'sales_flat_invoice_item', $invoiceItemId);
                    }
                    $productOptions['giftcard_paid_invoice_items'] = $invoiceItems2;
                }
            }

            if (version_compare(UBMigrate::getM2Version(), '2.2.0', '<')) {
                return serialize($productOptions);
            } else {
                //this changed from Magento ver.2.2.0
                return UBMigrate::encodeJson($productOptions);
            }
        } else {
            return null;
        }
    }

    private function _convertQuoteItemOptionCodeValue($productId2, &$optCode, &$optValue, $keepProductId)
    {
        //convert to Magento 2 code and value
        if ($optCode == 'info_buyRequest') {

            $buyRequest = UBMigrate::mb_unserialize($optValue);

            //simple
            if (!$keepProductId AND isset($buyRequest['product']) AND $buyRequest['product']) {
                $buyRequest['product'] = UBMigrate::getM2EntityId(5, 'catalog_product_entity', $buyRequest['product']);
            }
            //bundle
            if (!$keepProductId AND isset($buyRequest['bundle_option']) AND $buyRequest['bundle_option']) {
                $bundleOption = [];
                $bundleOptionQty = [];
                foreach ($buyRequest['bundle_option'] as $optionId => $selectionId) {
                    $optionId2 = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_option', $optionId);
                    if (is_array($selectionId)) {
                        foreach ($selectionId as $key => $sltId) {
                            if ($sltId) {
                                $bundleOption[$optionId2][$key] =  UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_selection', $sltId);
                            }
                        }
                    } else {
                        if ($selectionId) {
                            $bundleOption[$optionId2] = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_selection', $selectionId);
                        }
                        if (isset($buyRequest['bundle_option_qty'][$optionId])) {
                            $bundleOptionQty[$optionId2] = $buyRequest['bundle_option_qty'][$optionId];
                        }
                    }
                }
                $buyRequest['bundle_option'] = $bundleOption;
                $buyRequest['bundle_option_qty'] = $bundleOptionQty;
            }
            //downloadable
            if (!$keepProductId AND isset($buyRequest['links']) AND $buyRequest['links']) {
                $links2 = [];
                foreach ($buyRequest['links'] as $key => $linkId) {
                    $links2[$key] = UBMigrate::getM2EntityId('5_product_download', 'downloadable_link', $linkId);
                }
                $buyRequest['links'] = $links2;
            }
            //configurable
            if (isset($buyRequest['super_attribute']) AND $buyRequest['super_attribute']) {
                $superAttribute = [];
                foreach ($buyRequest['super_attribute'] as $attributeId => $attributeOptionId) {
                    $attributeId2 = isset($mappingAttributes[$attributeId]) ? $mappingAttributes[$attributeId] : null;
                    $superAttribute[$attributeId2] = UBMigrate::getM2EntityId('3_attribute_option', 'eav_attribute_option', $attributeOptionId);
                }
                $buyRequest['super_attribute'] = $superAttribute;
            }
            //virtual
            if (!$keepProductId AND isset($buyRequest['options']) AND $buyRequest['options']) {
                $options2 = [];
                foreach ($buyRequest['options'] as $productOptionId => $value) {
                    if (is_numeric($productOptionId)) {
                        $productOptionId2 = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_option', $productOptionId);
                        $options2[$productOptionId2] = $value;
                    } else {
                        $options2[$productOptionId] = $value;
                    }
                }
                //re-update
                $buyRequest['options'] = $options2;
            }

            //re-update value
            //$optValue = serialize($buyRequest);
            $optValue = UBMigrate::encodeJson($buyRequest); // this was changed from Magento ver.2.2.0

        } elseif ($optCode == 'attributes') {
            $values = UBMigrate::mb_unserialize($optValue);
            foreach ($values as $attributeId => $attributeOptionId) {
                $attributeId2 = isset($mappingAttributes[$attributeId]) ? $mappingAttributes[$attributeId] : null;
                $values[$attributeId2] = UBMigrate::getM2EntityId('3_attribute_option', 'eav_attribute_option', $attributeOptionId);
            }
            //$optValue = serialize($values);
            $optValue = UBMigrate::encodeJson($values); // this was changed from Magento ver.2.2.0
        } elseif (substr($optCode, 0, 12) == 'product_qty_') {
            $optCode = "product_qty_{$productId2}";
        } elseif ($optCode == 'simple_product') {
            $optValue = $productId2;
        } elseif ($optCode == 'parent_product_id') {
            $optValue = (!$keepProductId) ? UBMigrate::getM2EntityId(5, 'catalog_product_entity', $optValue) : $optValue;
        } elseif (substr($optCode, 0, 14) == 'selection_qty_') {
            $selectionId = substr($optCode, 14);
            if (is_numeric($selectionId)) {
                $selectionId = (!$keepProductId) ? UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_selection', $selectionId) : $selectionId;
                $optCode = "selection_qty_{$selectionId}";
            }
        } elseif (!$keepProductId AND $optCode == 'bundle_identity') {
            $values = explode('_', $optValue);
            $values[0] = $productId2;
            foreach ($values as $key => $value) {
                if ($value AND ($key % 2 == 1)) {
                    $values[$key] = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_selection', $value);
                }
            }
            $optValue = implode('_', $values);
        } elseif ($optCode == 'bundle_option_ids') {
            $values = UBMigrate::mb_unserialize($optValue);
            foreach ($values as $key => $bundleOptionId) {
                $bundleOptionId = (!$keepProductId) ? UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_option', $bundleOptionId) : $bundleOptionId;
                $values[$key] = $bundleOptionId;
            }
            //$optValue = serialize($values);
            $optValue = UBMigrate::encodeJson($values); // this was changed from Magento ver.2.2.0
        } elseif ($optCode == 'bundle_selection_ids') {
            $values = UBMigrate::mb_unserialize($optValue);
            foreach ($values as $key => $bundleSelectionId) {
                if ($bundleSelectionId) {
                    $bundleSelectionId = (!$keepProductId) ? UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_selection', $bundleSelectionId) : $bundleSelectionId;
                    $values[$key] = $bundleSelectionId;
                }
            }
            //$optValue = serialize($values);
            $optValue = UBMigrate::encodeJson($values); // this was changed from Magento ver.2.2.0
        } elseif (!$keepProductId AND $optCode == 'selection_id') {
            if ($optValue) {
                $optValue = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_selection', $optValue);
            }
        } elseif ($optCode == 'bundle_selection_attributes') {
            $values = UBMigrate::mb_unserialize($optValue);
            if (isset($values['option_id']) AND $values['option_id']) {
                $values['option_id'] = (!$keepProductId) ? UBMigrate::getM2EntityId('5_product_option', 'catalog_product_bundle_option', $values['option_id']) : $values['option_id'];
            }
            //$optValue = serialize($values);
            $optValue = UBMigrate::encodeJson($values); // this was changed from Magento ver.2.2.0
        } elseif ($optCode == 'downloadable_link_ids') {
            $values = explode(',', $optValue);
            if ($values) {
                foreach ($values as $key => $value) {
                    if (is_numeric($value)) {
                        $values[$key] = (!$keepProductId) ? UBMigrate::getM2EntityId('5_product_download', 'downloadable_link', $value) : $value;
                    }
                }
                //$optValue = implode(',', $values);
                $optValue = UBMigrate::encodeJson($values); // this was changed from Magento ver.2.2.0
            }
        } elseif ($optCode == 'option_ids') {
            $values = preg_split('/,\s*/', $optValue);
            if ($values) {
                foreach ($values as $key => $value) {
                    if (is_numeric($value)) {
                        $values[$key] = (!$keepProductId) ? UBMigrate::getM2EntityId('5_product_option', 'catalog_product_option', $value) : $value;
                    }
                }
                //$optValue = implode(',', $values);
                $optValue = UBMigrate::encodeJson($values); // this was changed from Magento ver.2.2.0
            }
        } elseif (!$keepProductId AND substr($optCode, 0, 7) == 'option_') {
            $productOptionId = (int)substr($optCode, 7);
            $optCode = "option_" . UBMigrate::getM2EntityId('5_product_option', 'catalog_product_option', $productOptionId);
            if (is_numeric($optValue)) {
                $optValue = UBMigrate::getM2EntityId('5_product_option', 'catalog_product_option_type_price', $optValue);
            }
        }

        return true;
    }

    private function _migrateSalesPayment($salesOrderId1, $salesOrderId2, $keepOriginalId)
    {
        /**
         * Table: sales_flat_order_payment
         */
        $salesPayments = Mage1SalesOrderPayment::model()->findAll("parent_id = {$salesOrderId1}");
        if ($salesPayments) {
            foreach ($salesPayments as $salesPayment) {
                $salesPayment2 = Mage2SalesOrderPayment::model()->find("parent_id = {$salesOrderId2}");
                if (!$salesPayment2) {
                    $salesPayment2 = new Mage2SalesOrderPayment();
                    //fill values
                    foreach ($salesPayment2->attributes as $key => $value) {
                        if (isset($salesPayment->$key)) {
                            /**
                             * Have some new max length rule in Magento 2
                             * So we have to check length to split here
                             */
                            $val = $salesPayment->$key;
                          
                            if (in_array($key, array('po_number', 'last_trans_id', 'cc_status_description', 'cc_avs_status', 'cc_trans_id')) && strlen($val) > 32) {
                                $val = substr(trim($val), 0, 32);
                            } else if (in_array($key, array('base_amount_ordered', 'amount_ordered')) && strlen($val) > 12) {
                                $val = substr(trim($val), 0, 12);
                            } else if (in_array($key, array('cc_number_enc','cc_owner',)) && strlen($val) > 128) {
                                $val = substr(trim($val), 0, 128);
                            }
                            $salesPayment2->$key = $val;
                        }
                    }

                    $salesPayment2->entity_id = ($keepOriginalId) ? $salesPayment->entity_id : null;
                    $salesPayment2->parent_id = $salesOrderId2;

                    //because the this field name was changed in Magento 2
                    $salesPayment2->cc_last_4 = isset($salesPayment->cc_last4) ? $salesPayment->cc_last4 : null;

                    //because Magento2 was changed serialized() to json_encode() proceed for value on additional_information field
                    if ($salesPayment2->additional_information) {
                        $additionalInfo = UBMigrate::mb_unserialize($salesPayment2->additional_information);
                        $salesPayment2->additional_information = UBMigrate::encodeJson($additionalInfo);
                    }

                } else {
                    //because Magento2 was changed serialized() to json_encode() proceed for value on additional_information field
                    if ($salesPayment->additional_information) {
                        $additionalInfo = UBMigrate::mb_unserialize($salesPayment->additional_information);
                        $salesPayment2->additional_information = UBMigrate::encodeJson($additionalInfo);
                    }
                    //update more -> coming soon if needed
                }
                //save/update
                if ($salesPayment2->save()) {
                    /**
                     * Table: sales_payment_transaction
                     */
                    $models = Mage1SalesPaymentTransaction::model()->findAll("payment_id = {$salesPayment->entity_id}");
                    if ($models) {
                        $paymentTransactionMappingIds = [];
                        foreach ($models as $model) {
                            $condition = "order_id = {$salesOrderId2} AND payment_id = {$salesPayment2->entity_id} AND txn_id = '{$model->txn_id}'";
                            $model2 = Mage2SalesPaymentTransaction::model()->find($condition);
                            if (!$model2) {
                                $model2 = new Mage2SalesPaymentTransaction();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $model2->$key = $model->$key;
                                    }
                                }
                                $model2->transaction_id = ($keepOriginalId) ? $model->transaction_id : null;
                                $model2->order_id = $salesOrderId2;
                                $model2->payment_id = $salesPayment2->entity_id;
                                if (!$keepOriginalId && $model2->parent_id) {
                                    $model2->parent_id = isset($paymentTransactionMappingIds[$model2->parent_id]) ? $paymentTransactionMappingIds[$model2->parent_id] : null;
                                }

                                //because Magento2 was changed serialized() to json_encode() proceed for value on additional_information field
                                if ($model2->additional_information) {
                                    $additionalInfo = UBMigrate::mb_unserialize($model2->additional_information);
                                    $model2->additional_information = UBMigrate::encodeJson($additionalInfo);
                                }

                            } else {
                                //because Magento2 was changed serialized() to json_encode() proceed for value on additional_information field
                                if ($model->additional_information) {
                                    $additionalInfo = UBMigrate::mb_unserialize($model->additional_information);
                                    $model2->additional_information = UBMigrate::encodeJson($additionalInfo);
                                }
                                //update more fields - coming soon if needed
                            }

                            //save/update
                            if (!$model2->save()) {
                                $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                            } else {
                                $paymentTransactionMappingIds[$model->transaction_id] = $model2->transaction_id;
                            }
                        }
                    }
                } else {
                    $this->errors[] = get_class($salesPayment2) . ": " . UBMigrate::getStringErrors($salesPayment2->getErrors());
                }
            }
        }

        return true;
    }

    private function _migrateSalesInvoice($salesOrderId1, $salesOrderId2, $mappingStores, $keepOriginalId)
    {
        //check has keep product ids in the step #5
        $keepProductId = UBMigrate::getSetting(5, 'keep_original_id');
        /**
         * Table: sales_flat_invoice
         * Because there isn't action edit from admin for a invoice so we haven't check to delta update
         */
        $salesInvoices = Mage1SalesInvoice::model()->findAll("order_id = {$salesOrderId1}");
        if ($salesInvoices) {
            foreach ($salesInvoices as $salesInvoice) {
                $storeId2 = isset($mappingStores[$salesInvoice->store_id]) ? $mappingStores[$salesInvoice->store_id] : null;
                $condition = "increment_id = '{$salesInvoice->increment_id}'";
                if (is_null($storeId2)) {
                    $condition .= " AND store_id IS NULL";
                } else {
                    $condition .= " AND store_id = {$storeId2}";
                }
                $salesInvoice2 = Mage2SalesInvoice::model()->find($condition);
                if (!$salesInvoice2) {
                    $salesInvoice2 = new Mage2SalesInvoice();
                    foreach ($salesInvoice2->attributes as $key => $value) {
                        if (isset($salesInvoice->$key)) {
                            $salesInvoice2->$key = $salesInvoice->$key;
                        }
                    }
                    if (empty($salesInvoice2->created_at)) {
                        $salesInvoice2->created_at = date("Y-m-d H:i:s");
                    }
                    if ($salesInvoice2->updated_at === '0000-00-00 00:00:00' || empty($salesInvoice2->updated_at)) {
                        $salesInvoice2->updated_at = date("Y-m-d H:i:s");
                    }
                    $salesInvoice2->entity_id = ($keepOriginalId) ? $salesInvoice->entity_id : null;
                    $salesInvoice2->store_id = $storeId2;

                    if (!$keepOriginalId) {
                        $salesInvoice2->billing_address_id = UBMigrate::getM2EntityId("7_order_address", 'sales_flat_order_address', $salesInvoice2->billing_address_id);
                        if ($salesInvoice2->shipping_address_id) {
                            $salesInvoice2->shipping_address_id = UBMigrate::getM2EntityId("7_order_address", 'sales_flat_order_address', $salesInvoice2->shipping_address_id);
                        }
                    }

                    $salesInvoice2->order_id = $salesOrderId2;
                    //save
                    if (!$salesInvoice2->save()) {
                        $this->errors[] = get_class($salesInvoice2) . ": " . UBMigrate::getStringErrors($salesInvoice2->getErrors());
                    } else {
                        /**
                         * update to map log
                         * we have to map this to get again new entity_id in other context
                         */
                        UBMigrate::log([
                            'entity_name' => $salesInvoice->tableName(),
                            'm1_id' => $salesInvoice->entity_id,
                            'm2_id' => $salesInvoice2->entity_id,
                            'm2_model_class' => get_class($salesInvoice2),
                            'm2_key_field' => 'entity_id',
                            'can_reset' => UBMigrate::RESET_YES,
                            'step_index' => "7Invoice"
                        ]);
                        $this->_traceInfo();
                    }
                }
                //migrate related child tables
                if ($salesInvoice2->entity_id) {
                    /**
                     * Table: sales_flat_invoice_grid
                     */
                    $condition = "entity_id = {$salesInvoice->entity_id}";
                    $models = Mage1SalesInvoiceGrid::model()->findAll($condition);
                    if ($models) {
                        foreach ($models as $model) {
                            $storeId2 = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
                            $condition = "increment_id = '{$model->increment_id}'";
                            if (is_null($storeId2)) {
                                $condition .= " AND store_id IS NULL";
                            } else {
                                $condition .= " AND store_id = {$storeId2}";
                            }
                            $model2 = Mage2SalesInvoiceGrid::model()->find($condition);
                            if (!$model2) {
                                $model2 = new Mage2SalesInvoiceGrid();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $model2->$key = $model->$key;
                                    }
                                }
                                $model2->entity_id = $salesInvoice2->entity_id;
                                $model2->store_id = $storeId2;
                                $model2->order_id = $salesOrderId2;
                                if (!$model2->save()) {
                                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                    /**
                     * Table: sales_flat_invoice_item
                     */
                    $condition = "parent_id = {$salesInvoice->entity_id}";
                    $models = Mage1SalesInvoiceItem::model()->findAll($condition);
                    if ($models) {
                        foreach ($models as $model) {
                            $m2Id = UBMigrate::getM2EntityId("7_invoice_item", 'sales_flat_invoice_item', $model->entity_id);
                            if (is_null($m2Id)) {
                                $model2 = new Mage2SalesInvoiceItem();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $val = $model->$key;
                                        /**
                                         * Because Magento2 was change method to save weee_tax_applied to database:
                                         * So we have to make convert this
                                         */
                                        if ($key == 'weee_tax_applied') {
                                            $val = json_encode(UBMigrate::mb_unserialize($val));
                                        }
                                        $model2->$key = $val;
                                    }
                                }
                                $model2->entity_id = ($keepOriginalId) ? $model->entity_id : null;
                                $model2->parent_id = $salesInvoice2->entity_id;
                                if (!$keepProductId) {
                                    $model2->product_id = UBMigrate::getM2EntityId(5, 'catalog_product_entity', $model2->product_id);
                                }
                                if (!$keepOriginalId) {
                                    $model2->order_item_id = UBMigrate::getM2EntityId("7_order_item", 'sales_flat_order_item', $model2->order_item_id);
                                }
                                //save
                                if (!$model2->save()) {
                                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                } else {
                                    /**
                                     * update to map log
                                     * we have to map this to get again new entity_id in other context
                                     */
                                    UBMigrate::log([
                                        'entity_name' => $model->tableName(),
                                        'm1_id' => $model->entity_id,
                                        'm2_id' => $model2->entity_id,
                                        'm2_model_class' => get_class($model2),
                                        'm2_key_field' => 'entity_id',
                                        'can_reset' => UBMigrate::RESET_YES,
                                        'step_index' => "7InvoiceItem"
                                    ]);
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                    /**
                     * Table: sales_flat_invoice_comment
                     */
                    $condition = "parent_id = {$salesInvoice->entity_id}";
                    $models = Mage1SalesInvoiceComment::model()->findAll($condition);
                    if ($models) {
                        foreach ($models as $model) {
                            $condition = "parent_id = {$salesInvoice2->entity_id} AND created_at = '{$model->created_at}'";
                            $model2 = Mage2SalesInvoiceComment::model()->find($condition);
                            if (!$model2) {
                                $model2 = new Mage2SalesInvoiceComment();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $model2->$key = $model->$key;
                                    }
                                }
                                $model2->entity_id = ($keepOriginalId) ? $model->entity_id : null;
                                $model2->parent_id = $salesInvoice2->entity_id;
                                if (!$model2->save()) {
                                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesShipment($salesOrderId1, $salesOrderId2, $mappingStores, $keepOriginalId, $keepCustomerId)
    {
        //check has keep product ids in the step #5
        $keepProductId = UBMigrate::getSetting(5, 'keep_original_id');
        /**
         * Table: sales_flat_shipment
         */
        $salesShipments = Mage1SalesShipment::model()->findAll("order_id = {$salesOrderId1}");
        if ($salesShipments) {
            foreach ($salesShipments as $salesShipment) {
                $storeId2 = isset($mappingStores[$salesShipment->store_id]) ? $mappingStores[$salesShipment->store_id] : null;
                $condition = "increment_id = '{$salesShipment->increment_id}'";
                if (is_null($storeId2)) {
                    $condition .= " AND store_id IS NULL";
                } else {
                    $condition .= " AND store_id = {$storeId2}";
                }
                $salesShipment2 = Mage2SalesShipment::model()->find($condition);
                if (!$salesShipment2) {
                    $salesShipment2 = new Mage2SalesShipment();
                    foreach ($salesShipment2->attributes as $key => $value) {
                        if (isset($salesShipment->$key)) {
                            $salesShipment2->$key = $salesShipment->$key;
                        }
                    }
                    $salesShipment2->entity_id = ($keepOriginalId) ? $salesShipment->entity_id : null;
                    $salesShipment2->store_id = $storeId2;
                    $salesShipment2->order_id = $salesOrderId2;
                    if (!$keepCustomerId) {
                        $salesShipment2->customer_id = UBMigrate::getM2EntityId(6, 'customer_entity', $salesShipment2->customer_id);
                    }
                    if (!$keepOriginalId) {
                        $salesShipment2->shipping_address_id = UBMigrate::getM2EntityId("7_order_address", 'sales_flat_order_address', $salesShipment2->shipping_address_id);
                        $salesShipment2->billing_address_id = UBMigrate::getM2EntityId("7_order_address", 'sales_flat_order_address', $salesShipment2->billing_address_id);
                    }
                    if (empty($salesShipment2->created_at)) {
                        $salesShipment2->created_at = date('Y-m-d H:i:s');
                    }
                    if (!$salesShipment2->save()) {
                        $this->errors[] = get_class($salesShipment2) . ": " . UBMigrate::getStringErrors($salesShipment2->getErrors());
                    } else {
                        $this->_traceInfo();
                    }
                }
                //migrate related child tables
                if ($salesShipment2->entity_id) {
                    /**
                     * Table: sales_flat_shipment_grid
                     */
                    $models = Mage1SalesShipmentGrid::model()->findAll("entity_id = {$salesShipment->entity_id}");
                    if ($models) {
                        foreach ($models as $model) {
                            $storeId2 = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
                            $condition = "increment_id = '{$model->increment_id}'";
                            if (is_null($storeId2)) {
                                $condition .= " AND store_id IS NULL";
                            } else {
                                $condition .= " AND store_id = {$storeId2}";
                            }
                            $model2 = Mage2SalesShipmentGrid::model()->find($condition);
                            if (!$model2) {
                                $model2 = new Mage2SalesShipmentGrid();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $model2->$key = $model->$key;
                                    }
                                }
                                $model2->entity_id = $salesShipment2->entity_id;
                                //because new max length of this field in M2 is 128
                                if (strlen($model2->shipping_name) > 128) {
                                    $model2->shipping_name = substr($model2->shipping_name, 0, 128);
                                }
                                $model2->store_id = $storeId2;
                                $model2->order_id = $salesOrderId2;
                                $model2->customer_name = $model2->shipping_name;
                                if (empty(trim($model2->customer_name))) {
                                    $model2->customer_name = 'N/A';
                                }
                                if (empty(trim($model2->order_increment_id))) {
                                    $model2->order_increment_id = 'N/A';
                                }
                                if (!$model2->save()) {
                                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                    /**
                     * Table: sales_flat_shipment_item
                     */
                    $models = Mage1SalesShipmentItem::model()->findAll("parent_id = {$salesShipment->entity_id}");
                    if ($models) {
                        foreach ($models as $model) {
                            $oderItemId2 = (!$keepOriginalId) ? UBMigrate::getM2EntityId("7_order_item", 'sales_flat_order_item', $model->order_item_id) : $model->order_item_id;
                            if ($oderItemId2) {
                                $productId2 = (!$keepProductId) ? UBMigrate::getM2EntityId(5, 'catalog_product_entity', $model->product_id) : $model->product_id;
                                $condition = "parent_id = {$salesShipment2->entity_id} AND order_item_id = {$oderItemId2}";
                                $model2 = Mage2SalesShipmentItem::model()->find($condition);
                                if (!$model2) {
                                    $model2 = new Mage2SalesShipmentItem();
                                    foreach ($model2->attributes as $key => $value) {
                                        if (isset($model->$key)) {
                                            $val = $model->$key;
                                            /**
                                             * Have some new max length rule in Magento 2
                                             * So we have to check length to split here
                                             */
                                            if (in_array($key, array('weight')) AND strlen($val) > 12) {
                                                $val = substr($val, 0, 12);
                                            }
                                            $model2->$key = $val;
                                        }
                                    }
                                    $model2->entity_id = ($keepOriginalId) ? $model->entity_id : null;
                                    $model2->parent_id = $salesShipment2->entity_id;
                                    $model2->product_id = $productId2;
                                    $model2->order_item_id = $oderItemId2;
                                    if (!$model2->save()) {
                                        $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                    } else {
                                        $this->_traceInfo();
                                    }
                                }
                            }
                        }
                    }
                    /**
                     * Table: sales_flat_shipment_track
                     */
                    $models = Mage1SalesShipmentTrack::model()->findAll("parent_id = {$salesShipment->entity_id}");
                    if ($models) {
                        foreach ($models as $model) {
                            $condition = "parent_id = {$salesShipment2->entity_id} AND order_id = {$salesOrderId2} AND created_at = '{$model->created_at}'";
                            $model2 = Mage2SalesShipmentTrack::model()->find($condition);
                            if (!$model2) {
                                $model2 = new Mage2SalesShipmentTrack();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $model2->$key = $model->$key;
                                    }
                                }
                                $model2->entity_id = ($keepOriginalId) ? $model->entity_id : null;
                                $model2->parent_id = $salesShipment2->entity_id;
                                $model2->order_id = $salesOrderId2;
                                if (!$model2->save()) {
                                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                    /**
                     * Table: sales_flat_shipment_comment
                     */
                    $models = Mage1SalesShipmentComment::model()->findAll("parent_id = {$salesShipment->entity_id}");
                    if ($models) {
                        foreach ($models as $model) {
                            $condition = "parent_id = {$salesShipment2->entity_id} AND created_at = '{$model->created_at}'";
                            $model2 = Mage2SalesShipmentComment::model()->find($condition);
                            if (!$model2) {
                                $model2 = new Mage2SalesShipmentComment();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $model2->$key = $model->$key;
                                    }
                                }
                                $model2->entity_id = ($keepOriginalId) ? $model->entity_id : null;
                                $model2->parent_id = $salesShipment2->entity_id;
                                if (!$model2->save()) {
                                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesCreditmemo($salesOrderId1, $salesOrderId2, $mappingStores, $keepOriginalId)
    {
        //check has keep product ids in the step #5
        $keepProductId = UBMigrate::getSetting(5, 'keep_original_id');
        /**
         * Table: sales_flat_creditmemo
         */
        $salesCredits = Mage1SalesCreditmemo::model()->findAll("order_id = {$salesOrderId1}");
        if ($salesCredits) {
            foreach ($salesCredits as $salesCredit) {
                $storeId2 = isset($mappingStores[$salesCredit->store_id]) ? $mappingStores[$salesCredit->store_id] : null;
                $condition = "increment_id = '{$salesCredit->increment_id}'";
                if (is_null($storeId2)) {
                    $condition .= " AND store_id IS NULL";
                } else {
                    $condition .= " AND store_id = {$storeId2}";
                }
                $salesCredit2 = Mage2SalesCreditmemo::model()->find($condition);
                if (!$salesCredit2) {
                    $salesCredit2 = new Mage2SalesCreditmemo();
                    foreach ($salesCredit2->attributes as $key => $value) {
                        if (isset($salesCredit->$key)) {
                            $salesCredit2->$key = $salesCredit->$key;
                        }
                    }
                    $salesCredit2->entity_id = ($keepOriginalId) ? $salesCredit->entity_id : null;
                    $salesCredit2->store_id = $storeId2;
                    $salesCredit2->order_id = $salesOrderId2;
                    if (!$keepOriginalId) {
                        $salesCredit2->shipping_address_id = UBMigrate::getM2EntityId("7_order_address", 'sales_flat_order_address', $salesCredit2->shipping_address_id);
                        $salesCredit2->billing_address_id = UBMigrate::getM2EntityId("7_order_address", 'sales_flat_order_address', $salesCredit2->billing_address_id);
                        if ($salesCredit2->invoice_id) {
                            $salesCredit2->invoice_id = UBMigrate::getM2EntityId("7_invoice", 'sales_flat_invoice', $salesCredit2->invoice_id);
                        }
                    }
                    if (!$salesCredit2->save()) {
                        $this->errors[] = get_class($salesCredit2) . ": " . UBMigrate::getStringErrors($salesCredit2->getErrors());
                    } else {
                        $this->_traceInfo();
                    }
                }
                //migrate related child tables
                if ($salesCredit2->entity_id) {
                    /**
                     * Table: sales_flat_creditmemo_grid
                     */
                    $models = Mage1SalesCreditmemoGrid::model()->findAll("entity_id = {$salesCredit->entity_id}");
                    if ($models) {
                        foreach ($models as $model) {
                            $storeId2 = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
                            $condition = "increment_id = '{$model->increment_id}'";
                            if (is_null($storeId2)) {
                                $condition .= " AND store_id IS NULL";
                            } else {
                                $condition .= " AND store_id = {$storeId2}";
                            }
                            $model2 = Mage2SalesCreditmemoGrid::model()->find($condition);
                            if (!$model2) {
                                $model2 = new Mage2SalesCreditmemoGrid();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $model2->$key = $model->$key;
                                    }
                                }
                                $model2->entity_id = $salesCredit2->entity_id;
                                $model2->order_id = $salesOrderId2;
                                $model2->store_id = $storeId2;
                                //this is new field in M2 and it is required field
                                $model2->customer_name = substr($model->billing_name, 0, 128);
                                if (empty(trim($model2->customer_name))) {
                                    $model2->customer_name = 'N/A';
                                }
                                if (!$model2->save()) {
                                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                    /**
                     * Table: sales_flat_creditmemo_item
                     */
                    $models = Mage1SalesCreditmemoItem::model()->findAll("parent_id = {$salesCredit->entity_id}");
                    if ($models) {
                        foreach ($models as $model) {
                            $productId2 = (!$keepProductId) ? UBMigrate::getM2EntityId(5, 'catalog_product_entity', $model->product_id) : $model->product_id;
                            $orderItemId2 = (!$keepOriginalId) ? UBMigrate::getM2EntityId("7_order_item", 'sales_flat_order_item', $model->order_item_id) : $model->order_item_id;
                            if ($productId2 AND $orderItemId2) {
                                $condition = "parent_id = {$salesCredit2->entity_id} AND product_id = {$productId2} AND order_item_id = {$orderItemId2}";
                                $model2 = Mage2SalesCreditmemoItem::model()->find($condition);
                                if (!$model2) {
                                    $model2 = new Mage2SalesCreditmemoItem();
                                    foreach ($model2->attributes as $key => $value) {
                                        if (isset($model->$key)) {
                                            $val = $model->$key;
                                            /**
                                             * Because Magento2 was change method to save weee_tax_applied to database:
                                             * So we have to make convert this
                                             */
                                            if ($key == 'weee_tax_applied') {
                                                $val = json_encode(UBMigrate::mb_unserialize($val));
                                            }
                                            $model2->$key = $val;
                                        }
                                    }
                                    $model2->entity_id = ($keepOriginalId) ? $model->entity_id : null;
                                    $model2->parent_id = $salesCredit2->entity_id;
                                    $model2->product_id = $productId2;
                                    $model2->order_item_id = $orderItemId2;
                                    //save
                                    if (!$model2->save()) {
                                        $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                    } else {
                                        $this->_traceInfo();
                                    }
                                }
                            }
                        }
                    }
                    /**
                     * Table: sales_flat_creditmemo_comment
                     */
                    $models = Mage1SalesCreditmemoComment::model()->findAll("parent_id = {$salesCredit->entity_id}");
                    if ($models) {
                        foreach ($models as $model) {
                            $condition = "parent_id = {$salesCredit2->entity_id} AND created_at = '{$model->created_at}'";
                            $model2 = Mage2SalesCreditmemoComment::model()->find($condition);
                            if (!$model2) {
                                $model2 = new Mage2SalesCreditmemoComment();
                                foreach ($model2->attributes as $key => $value) {
                                    if (isset($model->$key)) {
                                        $model2->$key = $model->$key;
                                    }
                                }
                                $model2->entity_id = ($keepOriginalId) ? $model->entity_id : null;
                                $model2->parent_id = $salesCredit2->entity_id;
                                if (!$model2->save()) {
                                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                                } else {
                                    $this->_traceInfo();
                                }
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesOrderItem($parentId, $parentId2, $mappingStores, $mappingAttributes, $mappingSalesRules, $keepOriginalId)
    {
        //check has keep product Ids in the step #5
        $keepProductId = UBMigrate::getSetting(5, 'keep_original_id');

        /**
         * Table: sales_flat_order_item
         */
        $models = Mage1SalesOrderItem::model()->findAll("order_id = {$parentId}");
        if ($models) {
            foreach ($models as $model) {
                //check has migrate
                $m2Id = UBMigrate::getM2EntityId('7_order_item', 'sales_flat_order_item', $model->item_id);
                if (is_null($m2Id)) {
                    $model2 = new Mage2SalesOrderItem();
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key)) {
                            $val = $model->$key;
                            /**
                             * Because Magento2 was change method to save weee_tax_applied to database:
                             * So we have to make convert this
                             */
                            if ($key == 'weee_tax_applied') {
                                $val = json_encode(UBMigrate::mb_unserialize($val));
                            } else if ( in_array($key, array(
                                    'weight', 'row_weight',
                                    'row_total_incl_tax', 'base_row_total_incl_tax',
                                    'price_incl_tax', 'qty_ordered', 'base_cost'))
                                AND strlen(trim($val)) > 12 ) {
                                $val = substr(trim($val), 0, 12);
                            }
                            $model2->$key = $val;
                        }
                    }
                    $model2->item_id = ($keepOriginalId) ? $model->item_id : null;
                    //because some entity ids was changed
                    $model2->order_id = $parentId2;
                    $model2->store_id = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
                    if (!$keepOriginalId && $model2->parent_item_id) {
                        $model2->parent_item_id = UBMigrate::getM2EntityId('7_order_item', 'sales_flat_order_item', $model2->parent_item_id);
                    }
                    if (!$keepOriginalId && $model2->quote_item_id) {
                        $model2->quote_item_id = UBMigrate::getM2EntityId('7_quote_item', 'sales_flat_quote_item', $model2->quote_item_id);
                    }
                    if (!$keepProductId) {
                        $model2->product_id = UBMigrate::getM2EntityId(5, 'catalog_product_entity', $model->product_id);
                    }
                    if ($model2->created_at === '0000-00-00 00:00:00' || empty($model2->created_at)) {
                        $model2->created_at = date("Y-m-d H:i:s");
                    }
                    if ($model2->updated_at === '0000-00-00 00:00:00' || empty($model2->updated_at)) {
                        $model2->updated_at = date("Y-m-d H:i:s");
                    }
                    //we have to convert data in product_options to update new ids
                    $model2->product_options = $this->_convertProductOptions($model->product_options, $mappingAttributes, $keepProductId, $keepOriginalId);

                    if (!$keepOriginalId && $model2->applied_rule_ids) {
                        $appliedRuleIds = explode(',', $model2->applied_rule_ids);
                        $appliedRuleIds2 = [];
                        if (is_array($appliedRuleIds)) {
                            foreach ($appliedRuleIds as $id) {
                                if (isset($mappingSalesRules[$id])) {
                                    $appliedRuleIds2[] = $mappingSalesRules[$id];
                                }
                            }
                        }
                        $model2->applied_rule_ids = implode(',', $appliedRuleIds2);
                    }
                } else {
                    //update
                    $model2 = Mage2SalesOrderItem::model()->find("item_id = {$m2Id}");
                    //update values
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key) AND !in_array($key, array('item_id','order_id','store_id','parent_item_id','quote_item_id','created_at'))) {
                            $val = $model->$key;
                            /**
                             * Because Magento2 was change method to save weee_tax_applied to database:
                             * So we have to make convert this
                             */
                            if ($key == 'weee_tax_applied') {
                                $val = json_encode(UBMigrate::mb_unserialize($val));
                            } elseif (in_array($key, array('weight', 'row_weight', 'row_total_incl_tax', 'base_row_total_incl_tax')) AND strlen(trim($val)) > 12) {
                                /**
                                 * Have some new max length rule in Magento 2. So we have to check length to split here
                                 */
                                $val = substr(trim($val), 0, 12);
                            }
                            $model2->$key = $val;
                        }
                    }
                    if (!$keepProductId) {
                        $model2->product_id = UBMigrate::getM2EntityId(5, 'catalog_product_entity', $model->product_id);
                    }
                    //we have to convert data in product_options to update new ids
                    $model2->product_options = $this->_convertProductOptions($model->product_options, $mappingAttributes, $keepProductId, $keepOriginalId);

                    if (!$keepOriginalId && $model2->applied_rule_ids) {
                        $appliedRuleIds = explode(',', $model2->applied_rule_ids);
                        $appliedRuleIds2 = [];
                        if (is_array($appliedRuleIds)) {
                            foreach ($appliedRuleIds as $id) {
                                if (isset($mappingSalesRules[$id])) {
                                    $appliedRuleIds2[] = $mappingSalesRules[$id];
                                }
                            }
                        }
                        $model2->applied_rule_ids = implode(',', $appliedRuleIds2);
                    }
                }
                //save/update
                if (!$model2->save()) {
                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                } else {
                    if (is_null($m2Id)) {
                        UBMigrate::log([
                            'entity_name' => $model->tableName(),
                            'm1_id' => $model->item_id,
                            'm2_id' => $model2->item_id,
                            'm2_model_class' => get_class($model2),
                            'm2_key_field' => 'item_id',
                            'can_reset' => UBMigrate::RESET_YES,
                            'step_index' => "7OrderItem"
                        ]);
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesOrderAddress($parentId, $parentId2, $keepOriginalId, $keepCustomerId)
    {
        /**
         * Table: sales_flat_order_address
         */
        $models = Mage1SalesOrderAddress::model()->findAll("parent_id = {$parentId}");
        if ($models) {
            foreach ($models as $model) {
                //check has migrated
                $m2Id = UBMigrate::getM2EntityId("7_order_address", 'sales_flat_order_address', $model->entity_id);
                if (is_null($m2Id)) {
                    $model2 = new Mage2SalesOrderAddress();
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key)) {
                            $model2->$key = $model->$key;
                        }
                    }
                    $model2->entity_id = ($keepOriginalId) ? $model->entity_id : null;
                    //because some entity ids was changed
                    $model2->parent_id = $parentId2;
                    if (!$keepCustomerId) {
                        $model2->customer_id = UBMigrate::getM2EntityId(6, 'customer_entity', $model2->customer_id);
                        $model2->customer_address_id = UBMigrate::getM2EntityId('6_customer_address', 'customer_address_entity', $model2->customer_address_id); //coming soon
                    }
                    if (!$keepOriginalId && $model2->quote_address_id) {
                        $model2->quote_address_id = UBMigrate::getM2EntityId("7_quote_address", 'sales_flat_quote_address', $model2->quote_address_id);
                    }
                } else {
                    //update
                    $model2 = Mage2SalesOrderAddress::model()->find("entity_id = {$m2Id}");
                    //update values
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key) AND !in_array($key, array('entity_id','parent_id','customer_id', 'customer_address_id','quote_address_id'))) {
                            $model2->$key = $model->$key;
                        }
                    }
                }
                //save/update
                if (!$model2->save()) {
                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                } else {
                    if (is_null($m2Id)) {
                        UBMigrate::log([
                            'entity_name' => $model->tableName(),
                            'm1_id' => $model->entity_id,
                            'm2_id' => $model2->entity_id,
                            'm2_model_class' => get_class($model2),
                            'm2_key_field' => 'entity_id',
                            'can_reset' => UBMigrate::RESET_YES,
                            'step_index' => "7OrderAddress"
                        ]);
                    }
                    $this->_traceInfo();
                }
            }
        }

        return true;
    }

    private function _migrateSalesOrderGrid($salesOrder1, $salesOrder2, $mappingStores, $keepCustomerId)
    {
        /**
         * Table: sales_flat_order_grid
         */
        $models = Mage1SalesOrderGrid::model()->findAll("entity_id = {$salesOrder1->entity_id}");
        if ($models) {
            foreach ($models as $model) {
                $storeId2 = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
                $condition = "increment_id = '{$model->increment_id}'";
                if (is_null($storeId2)) {
                    $condition .= " AND store_id IS NULL";
                } else {
                    $condition .= " AND store_id = {$storeId2}";
                }
                $model2 = Mage2SalesOrderGrid::model()->find($condition);
                if (!$model2) {
                    //add new
                    $model2 = new Mage2SalesOrderGrid();
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key)) {
                            $val = $model->$key;
                            if (in_array($key, array('base_grand_total', 'grand_total')) AND strlen($val) > 12) {
                                $val = substr(trim($val), 0, 12);
                            }
                            $model2->$key = $val;
                        }
                    }
                    //because some entity ids was changed
                    $model2->entity_id = $salesOrder2->entity_id;
                    $model2->store_id = $storeId2;
                    $model2->customer_id = (!$keepCustomerId) ? UBMigrate::getM2EntityId(6, 'customer_entity', $model2->customer_id) : $model2->customer_id;
                    /**
                     * we will update for some new added fields
                     * 'billing_address', 'shipping_address', 'shipping_information','payment_method', - coming soon if needed
                     * 'customer_email','customer_group','customer_name' // get from sales_order: firstname + middlename + lastname
                     */
                    $model2->customer_email = $salesOrder2->customer_email;
                    $model2->customer_group = $salesOrder2->customer_group_id;
                    $model2->customer_name = "{$salesOrder2->customer_firstname} {$salesOrder2->customer_middlename} {$salesOrder2->customer_lastname}";
                } else {
                    //update
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key) AND !in_array($key, array('entity_id','store_id','customer_id','created_at'))) {
                            $val = $model->$key;
                            if (in_array($key, array('base_grand_total', 'grand_total')) AND strlen($val) > 12) {
                                $val = substr(trim($val), 0, 12);
                            }
                            $model2->$key = $val;
                        }
                    }
                    /**
                     * we will update for some new added fields
                     * 'billing_address', 'shipping_address', 'shipping_information','payment_method', - coming soon if needed
                     * 'customer_email','customer_group','customer_name' // get from sales_order: firstname + middlename + lastname
                     */
                    $model2->customer_email = $salesOrder2->customer_email;
                    $model2->customer_group = $salesOrder2->customer_group_id;
                    $model2->customer_name = "{$salesOrder2->customer_firstname} {$salesOrder2->customer_middlename} {$salesOrder2->customer_lastname}";
                }
                //save/update
                if (!$model2->save()) {
                    $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                } else {
                    $this->_traceInfo();
                }
            }
        }

        return true;
    }

    private function _migrateSalesOrderStatusHistory($parentId, $parentId2)
    {
        /**
         * Table: sales_flat_order_status_history
         */
        $models = Mage1SalesOrderStatusHistory::model()->findAll("parent_id = {$parentId}");
        if ($models) {
            foreach ($models as $model) {
                $model2 = Mage2SalesOrderStatusHistory::model()->find("parent_id = {$parentId2} AND created_at = '{$model->created_at}'");
                if (!$model2) {
                    $model2 = new Mage2SalesOrderStatusHistory();
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key)) {
                            $model2->$key = $model->$key;
                        }
                    }
                    $model2->entity_id = null;
                    //because some entity ids was changed
                    $model2->parent_id = $parentId2;
                    if (!$model2->save()) {
                        $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                    } else {
                        $this->_traceInfo();
                    }
                }
            }
        }

        return true;
    }

    private function _migrateSalesOrderTax($parentId, $parentId2, $keepOriginalId)
    {
        /**
         * Table: sales_order_tax
         */
        $models = Mage1SalesOrderTax::model()->findAll("order_id = {$parentId}");
        if ($models) {
            foreach ($models as $model) {
                $condition = "order_id = {$parentId2} AND code = '{$model->code}'";
                $model2 = Mage2SalesOrderTax::model()->find($condition);
                if (!$model2) {
                    $model2 = new Mage2SalesOrderTax();
                    foreach ($model2->attributes as $key => $value) {
                        if (isset($model->$key)) {
                            $model2->$key = $model->$key;
                        }
                    }
                    $model2->tax_id = ($keepOriginalId) ? $model->tax_id : null;
                    //because some entity ids was changed
                    $model2->order_id = $parentId2;
                    if ($model2->save()) {
                        $this->_traceInfo();
                        /**
                         * Table: sales_order_tax_item
                         */
                        $items = Mage1SalesOrderTaxItem::model()->findAll("tax_id = {$model->tax_id}");
                        if ($items) {
                            foreach ($items as $item) {
                                $itemId2 = UBMigrate::getM2EntityId('7_order_item', 'sales_flat_order_item', $item->item_id);
                                if ($itemId2) {
                                    $condition = "tax_id = {$model2->tax_id} AND item_id = {$itemId2}";
                                    $item2 = Mage2SalesOrderTaxItem::model()->find($condition);
                                    if (!$item2) {
                                        $item2 = new Mage2SalesOrderTaxItem();
                                        foreach ($item2->attributes as $key => $value) {
                                            if (isset($item->$key)) {
                                                $item2->$key = $item->$key;
                                            }
                                        }
                                        $item2->tax_item_id = ($keepOriginalId) ? $item->tax_item_id : null;
                                        //because some entity ids was changed
                                        $item2->tax_id = $model2->tax_id;
                                        $item2->item_id = $itemId2;
                                        if ($item2->item_id) {
                                            //below fields is new added in Magento 2 and it was not exists in Magento1
                                            $item2->amount = 0;
                                            $item2->base_amount = 0;
                                            $item2->real_amount = 0;
                                            $item2->real_base_amount = 0;
                                            $item2->associated_item_id = null;
                                            $item2->taxable_item_type = '';
                                            if (!$item2->save()) {
                                                $this->errors[] = get_class($item2) . ": " . UBMigrate::getStringErrors($item2->getErrors());
                                            } else {
                                                $this->_traceInfo();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        $this->errors[] = get_class($model2) . ": " . UBMigrate::getStringErrors($model2->getErrors());
                    }
                }
            }
        }

        return true;
    }

    private function _migrateListObjects($list, $modelClass, $mappingStores) {
        foreach ($list as $model) {
            $storeId2 = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
            $con = "period = '{$model->period}' AND order_status = '{$model->order_status}'";
            if (!is_null($storeId2)) {
                $con .= " AND store_id = {$storeId2}";
            } else {
                $con .= " AND store_id IS NULL";
            }
            $model2 = $modelClass::model()->find($con);
            if (!$model2) {
                $model2 = new $modelClass();
                foreach ($model2->attributes as $key => $value) {
                    if (isset($model->$key)) {
                        $model2->$key = $model->$key;
                    }
                }
                $model2->id = null;
                $model2->store_id = $storeId2;
                //save
                if (!$model2->save()) {
                    $this->errors[] = get_class($model2).": ".UBMigrate::getStringErrors($model2->getErrors());
                } else {
                    $this->_traceInfo();
                }
            }
        }

        return true;
    }

    private function _migrateShippingAggregatedData($list, $modelClass, $mappingStores) {
        foreach ($list as $model) {
            $storeId2 = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
            $shippingDescription = addslashes($model->shipping_description);
            $con = "period = '{$model->period}' AND order_status = '{$model->order_status}' AND shipping_description = '{$shippingDescription}'";
            if (!is_null($storeId2)) {
                $con .= " AND store_id = {$storeId2}";
            } else {
                $con .= " AND store_id IS NULL";
            }
            $model2 = $modelClass::model()->find($con);
            if (!$model2) {
                $model2 = new $modelClass();
                foreach ($model2->attributes as $key => $value) {
                    if (isset($model->$key)) {
                        $model2->$key = $model->$key;
                    }
                }
                $model2->id = null;
                $model2->store_id = $storeId2;
                //save
                if (!$model2->save()) {
                    $this->errors[] = get_class($model2).": ".UBMigrate::getStringErrors($model2->getErrors());
                } else {
                    $this->_traceInfo();
                }
            }
        }

        return true;
    }

    private function _migrateBestsellerData($list, $modelClass, $mappingStores) {
        //check has keep product ids
        $keepProductId = UBMigrate::getSetting(5, 'keep_original_id');
        foreach ($list as $model) {
            $storeId2 = isset($mappingStores[$model->store_id]) ? $mappingStores[$model->store_id] : null;
            $productId2 = (!$keepProductId) ? UBMigrate::getM2EntityId(5, 'catalog_product_entity', $model->product_id) : $model->product_id;
            $con = "period = '{$model->period}'";
            if (!is_null($productId2)){
                $con .= " AND product_id = {$productId2}";
            } else {
                $con .= " AND product_id IS NULL";
            }
            if (!is_null($storeId2)) {
                $con .= " AND store_id = {$storeId2}";
            } else {
                $con .= " AND store_id IS NULL";
            }
            $model2 = $modelClass::model()->find($con);
            if (!$model2) {
                $model2 = new $modelClass();
                foreach ($model2->attributes as $key => $value) {
                    if (isset($model->$key)) {
                        $model2->$key = $model->$key;
                    }
                }
                $model2->id = null;
                $model2->store_id = $storeId2;
                $model2->product_id = $productId2;
                //save
                if (!$model2->save()) {
                    $this->errors[] = get_class($model2).": ".UBMigrate::getStringErrors($model2->getErrors());
                } else {
                    $this->_traceInfo();
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
