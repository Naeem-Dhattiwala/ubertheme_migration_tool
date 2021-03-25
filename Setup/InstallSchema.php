<?php
/**
 * @category    Ubertheme
 * @package     Ubertheme_UbDatamigration
 * @author      Ubertheme.com
 * @copyright   Copyright 2009-2016 Ubertheme
 */

namespace Ubertheme\Ubdatamigration\Setup;

use Magento\Framework\Setup\InstallSchemaInterface;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;

/**
 * @codeCoverageIgnore
 */
class InstallSchema implements InstallSchemaInterface
{
    /**
     * @param SchemaSetupInterface $setup
     * @param ModuleContextInterface $context
     */
    public function install(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $setup->startSetup();
        //install library of tool
        UBMigrationSetup::deployLibrary($setup);
        //create needed tables for this tool
        UBMigrationSetup::createTables($setup);
        $setup->endSetup();
    }

}
