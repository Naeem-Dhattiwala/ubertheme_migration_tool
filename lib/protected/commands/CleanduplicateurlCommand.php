<?php

/**
 * This command allow clean duplicated products url_key and url_path
 * CleanduplicateurlCommand class - CLI
 */
class CleanduplicateurlCommand extends CConsoleCommand
{
    public function actionIndex()
    {
        echo "Processing...";
        //we will clean duplicate values of the product attributes url_key and url_path
        $attributeCodes = ['url_key', 'url_path'];
        $attributeIds = [];
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
                echo '...';

                //get good items
                $query = "SELECT `value_id`, `store_id` FROM `{$tablePrefix}catalog_product_entity_varchar` WHERE `attribute_id` = {$attributeId} GROUP BY `store_id`, `value`";
                $command = Yii::app()->db->createCommand($query);
                $items = $command->queryAll();
                $ids = [];
                foreach ($items as $item) {
                    $ids[] = $item['value_id'];
                }
                $strIds = implode(',', $ids);
                //get total records with duplicated values
                $query = "SELECT COUNT(value_id) FROM `{$tablePrefix}catalog_product_entity_varchar` WHERE `attribute_id` = {$attributeId} AND `value_id` NOT IN ({$strIds})";
                $total = Yii::app()->db->createCommand($query)->queryScalar();
                //delete
                $query = "DELETE FROM `{$tablePrefix}catalog_product_entity_varchar` WHERE `attribute_id` = {$attributeId} AND `value_id` NOT IN ({$strIds})";
                Yii::app()->db->createCommand($query)->query();

                echo "Deleted {$total} items has duplicated {$attributeCode} in table {$tablePrefix}catalog_product_entity_varchar.";
            }
        }

        echo "\nDone.\n";
    }

}