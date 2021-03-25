<?php
return array(
    'components'=>array(
        //database of Magento1
        'db1' => array(
            'connectionString' => 'mysql:host={MG1_HOST};port={MG1_DB_PORT};dbname={MG1_DB_NAME}',
            'emulatePrepare' => true,
            'username' => '{MG1_DB_USER}',
            'password' => '{MG1_DB_PASS}',
            'charset' => 'utf8',
            'tablePrefix' => '{MG1_TABLE_PREFIX}',
            'class' => 'CDbConnection'
        ),
        //database of Magento 2 (we use this database for this tool too)
        'db' => array(
            'connectionString' => 'mysql:host={MG2_HOST};port={MG2_DB_PORT};dbname={MG2_DB_NAME}',
            'emulatePrepare' => true,
            'username' => '{MG2_DB_USER}',
            'password' => '{MG2_DB_PASS}',
            'charset' => 'utf8',
            'tablePrefix' => '{MG2_TABLE_PREFIX}',
            'class' => 'CDbConnection'
        ),
    )
);
