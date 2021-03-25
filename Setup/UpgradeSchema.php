<?php
/**
 * @category    Ubertheme
 * @package     Ubertheme_UbDatamigration
 * @author      Ubertheme.com
 * @copyright   Copyright 2009-2016 Ubertheme
 */

namespace Ubertheme\Ubdatamigration\Setup;

use Magento\Framework\Setup\UpgradeSchemaInterface;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;

/**
 * @codeCoverageIgnore
 */
class UpgradeSchema implements UpgradeSchemaInterface
{
    /**
     * @param SchemaSetupInterface $setup
     * @param ModuleContextInterface $context
     */
    public function upgrade(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $installer = $setup;
        $installer->startSetup();

        $version = $context->getVersion();
        if ($version) {
            if (version_compare($version, '3.0.0', '<')) {
                //install library of tool
                UBMigrationSetup::deployLibrary($installer);
                //create needed tables for this tool
                UBMigrationSetup::createTables($installer);
            } else {
                //back-up current settings and deploy new source of lib
                $this->_backUpAndDeployNewSource($installer);
                /**
                 * Check for some special upgrade cases
                 */
                if (version_compare($version, '3.0.7', '<')) {
                    UBMigrationSetup::createMappingTable($installer, '8_downloadable_link_purchased');
                }
                if (version_compare($version, '3.1.0', '<')) {
                    //convert some data in first migration
                    $this->_convertLogData($installer);
                }
                if (version_compare($version, '3.2.2', '<')) {
                    //create more needed table
                    UBMigrationSetup::createMappingTable($installer, '8_cms');
                    //add more new field in mapping data tables
                    foreach (UBMigrationSetup::$mappingTableKeyNames as $tableKeyName) {
                        UBMigrationSetup::addFieldToMappingTable($installer, $tableKeyName, 'mapped', [
                            'type' => \Magento\Framework\DB\Ddl\Table::TYPE_SMALLINT,
                            1,
                            'nullable' => false,
                            'default' => '1',
                            'comment' => 'Mapping status'
                        ]);
                    }
                }
            }
        }

        $installer->endSetup();
    }

    private function _backUpAndDeployNewSource($installer) {
        //back-up current settings
        UBMigrationSetup::backupConfig();
        //deploy new source of lib
        UBMigrationSetup::deployLibrary($installer);
    }

    private function _convertLogData($installer) {
        /** @var SchemaSetupInterface $installer */

        $tblName = $installer->getTable('ub_migrate_step');

        //convert all step's statuses 4-finished -> 5 - finished
        $installer->run("UPDATE `{$tblName}` SET `status` = 5 WHERE `status` = 4");

        //update step's title
        $installer->run("UPDATE `{$tblName}` SET `title` = 'Sites, Stores' WHERE id = 2");

        //update step's desc
        $installer->run("UPDATE `{$tblName}` SET `descriptions` = NULL");

        //convert all step's setting data
        $rows = $installer->getConnection()->fetchAll("SELECT `id`, `setting_data` FROM `{$tblName}` WHERE `id` > 1 AND `setting_data` IS NOT NULL");
        if ($rows) {
            foreach ($rows as $row) {
                $newSettingData = base64_encode($row['setting_data']);
                $installer->run("UPDATE `{$tblName}` SET `setting_data` = '{$newSettingData}' WHERE id = {$row['id']}");
            }
        }
    }

}
