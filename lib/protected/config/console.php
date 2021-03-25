<?php
/**
 * This is the configuration for ubmigration console application.
 */
return CMap::mergeArray(
    require(dirname(__FILE__) . '/db.php'), array(
        'basePath' => dirname(__FILE__) . DIRECTORY_SEPARATOR . '..',
        'name' => 'UB Data Migration Tool - CLI Application',
        'preload' => array('log'),
        // auto loading model and component classes
        'import' => array(
            'application.components.*',
            'application.models.*',
            'application.models.mage1.*',
            'application.models.mage2.*',
            'application.controllers.*'
        ),
        'components' => array(
            'log' => array(
                'class' => 'CLogRouter',
                'routes' => array(
                    array(
                        'class' => 'CFileLogRoute',
                        'levels' => 'error, warning, info',
                        'logFile' => 'ub_data_migration.log',
                        'categories' => 'ub_data_migration.*',
                    )
                ),
            ),
            'cache'=> require(dirname(__FILE__) . '/cache.php'),
        ),
    )
);