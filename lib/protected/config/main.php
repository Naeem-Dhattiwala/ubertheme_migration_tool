<?php
/**
 * This is the main configuration ob UB data migration tool
 * Any CWebApplication properties can be configured here.
 */
return CMap::mergeArray(
    require(dirname(__FILE__) . '/db.php'), array(
        'basePath'=>dirname(__FILE__).DIRECTORY_SEPARATOR.'..',
        'name'=>'UB Data Migration Pro: Allow migrate data from Magento CE 1.x to Magento CE 2.x',
        'language' => 'en',
        // preloading 'log' component
        'preload'=>array('log'),
        'defaultController'=>'base',
        // application components
        'components'=>array(
            'user'=>array(
                // enable cookie-based authentication
                'allowAutoLogin'=>true,
            ),
            'errorHandler'=>array(
                'errorAction'=>'base/error',
            ),
            'urlManager'=>array(
                'urlFormat'=>'path',
                'showScriptName'=>true,
                'rules'=>array(
                    '<controller:\w+>/<action:\w+>'=>'<controller>/<action>',
                ),
            ),
            'log'=>array(
                'class'=>'CLogRouter',
                'routes'=>array(
                    array(
                        'class'=>'CFileLogRoute',
                        'levels'=>'error, warning, info',
                        'logFile'=>'ub_data_migration.log',
                        'categories'=>'ub_data_migration.*',
                    ),
                    // uncomment the following to show log messages on web pages
                    /*array(
                        'class'=>'CWebLogRoute',
                    ),*/
                ),
            ),
            'cache'=> require(dirname(__FILE__) . '/cache.php'),
        ),
        // auto loading model and component classes
        'import'=>array(
            'application.components.*',
            'application.models.*',
            'application.models.mage1.*',
            'application.models.mage2.*'
        ),
        // application-level parameters that can be accessed
        // using Yii::app()->params['paramName']
        'params'=> CMap::mergeArray(require(dirname(__FILE__) . '/params.php'), array(
            //default language
            'defaultLanguage' => 'en',
            //this is displayed in the header section
            'title'=>'UB Data migration Tool for Magento',
            //admin email
            'adminEmail'=>'quynhvv@joomsolutions.com',
            // the copyright information displayed in the footer section
            'copyrightInfo'=>'Copyright &copy; 2015 by Ubertheme.com',
        ))
    )
);
