<?php

/**
 * This command allow clean duplicated products url_key and url_path
 * CleanduplicateurlCommand class - CLI
 */
class FixduplicateurlCommand extends CConsoleCommand
{
    public function actionIndex()
    {

        //we will clean duplicate values of the product attributes url_key and url_path
        $attributeCodes = ['url_key', 'url_path'];
        $attributeIds = [];

        echo "\nProcessing for categories...\n";
        $entityTypeId = UBMigrate::getM2EntityTypeIdByCode(UBMigrate::CATEGORY_TYPE_CODE);
        foreach ($attributeCodes as $attributeCode) {
            $attribute = Mage2Attribute::model()->find("attribute_code = '{$attributeCode}' AND entity_type_id = {$entityTypeId}");
            if ($attribute) {
                $attributeIds[$attributeCode] = $attribute->attribute_id;
            }
        }
        if ($attributeIds) {
            $tablePrefix = Yii::app()->db->tablePrefix;
            foreach ($attributeIds as $attributeCode => $attributeId) {
                //get good items
                $query = "SELECT `value_id`, `store_id`, `value` FROM `{$tablePrefix}catalog_category_entity_varchar` WHERE `attribute_id` = {$attributeId} GROUP BY `store_id`, `value`";
                $command = Yii::app()->db->createCommand($query);
                $items = $command->queryAll();
                $ids = [];
                foreach ($items as $item) {
                    $ids[] = $item['value_id'];
                }
                $strIds = implode(',', $ids);

                echo "...";

                //fix value of all records with duplicated values
                $total = 0;
                $query = "SELECT * FROM `{$tablePrefix}catalog_category_entity_varchar` WHERE `attribute_id` = {$attributeId} AND `value_id` NOT IN ({$strIds})";
                $duplicatedItems = Yii::app()->db->createCommand($query)->queryAll();
                if ($duplicatedItems) {
                    foreach ($duplicatedItems as $item) {
                        $value = $item['value'].'-'.$item['value_id'];
                        $query = "UPDATE `{$tablePrefix}catalog_category_entity_varchar` SET `value` = '{$value}' WHERE `value_id` = {$item['value_id']}";
                        Yii::app()->db->createCommand($query)->query();
                    }
                    $total = sizeof($duplicatedItems);
                }

                echo "\nFixed {$total} items duplicated {$attributeCode} in table {$tablePrefix}catalog_category_entity_varchar.\n";
            }
        }

        echo "\nProcessing for products...\n";
        $entityTypeId = UBMigrate::getM2EntityTypeIdByCode(UBMigrate::PRODUCT_TYPE_CODE);
        foreach ($attributeCodes as $attributeCode) {
            $attribute = Mage2Attribute::model()->find("attribute_code = '{$attributeCode}' AND entity_type_id = {$entityTypeId}");
            if ($attribute) {
                $attributeIds[$attributeCode] = $attribute->attribute_id;
            }
        }
        if ($attributeIds) {
            $tablePrefix = Yii::app()->db->tablePrefix;
            foreach ($attributeIds as $attributeCode => $attributeId) {
                //get good items
                $query = "SELECT `value_id`, `store_id`, `value` FROM `{$tablePrefix}catalog_product_entity_varchar` WHERE `attribute_id` = {$attributeId} GROUP BY `store_id`, `value`";
                $command = Yii::app()->db->createCommand($query);
                $items = $command->queryAll();
                $ids = [];
                foreach ($items as $item) {
                    $ids[] = $item['value_id'];
                }
                $strIds = implode(',', $ids);

                echo "...";

                //fix name of all records with duplicated values
                $total = 0;
                $query = "SELECT * FROM `{$tablePrefix}catalog_product_entity_varchar` WHERE `attribute_id` = {$attributeId} AND `value_id` NOT IN ({$strIds})";
                $duplicatedItems = Yii::app()->db->createCommand($query)->queryAll();
                if ($duplicatedItems) {
                    foreach ($duplicatedItems as $item) {
                        //$value = $item['value'].uniqid();
                        $value = $item['value'].'-'.$item['value_id'];
                        $query = "UPDATE `{$tablePrefix}catalog_product_entity_varchar` SET `value` = '{$value}' WHERE `value_id` = {$item['value_id']}";
                        Yii::app()->db->createCommand($query)->query();
                    }
                    $total = sizeof($duplicatedItems);
                }

                echo "\nFixed {$total} items duplicated {$attributeCode} in table {$tablePrefix}catalog_product_entity_varchar.\n";
            }
        }

        echo "\nDone.\n";
    }

}