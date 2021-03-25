<?php

/**
 * Controller is the customized base controller class.
 * All controller classes for this application should extend from this base class.
 */
class Controller extends CController
{
    /**
     * @var string the default layout for the controller view. Defaults to 'column1',
     * meaning using a single column layout. See 'protected/views/layouts/column1.php'.
     */
    public $layout = 'column1';
    /**
     * @var array context menu items. This property will be assigned to {@link CMenu::items}.
     */
    public $menu = array();
    /**
     * @var array the breadcrumbs of the current page. The value of this property will
     * be assigned to {@link CBreadcrumbs::links}. Please refer to {@link CBreadcrumbs::links}
     * for more details on how to specify this property.
     */
    public $breadcrumbs = array();

    /**
     * Init function
     */
    public function init()
    {
        /**
         * check for security
         * We only allow access this tool with valid token
         **/
        $token = Yii::app()->request->getParam('token', null);
        if ($token != UBMigrate::getToken()) {
            throw new CHttpException(400,Yii::t('frontend','Your request is invalid.'));
        }

        //initial language
        if (!isset(Yii::app()->session['_lang'])) {
            Yii::app()->session['_lang'] = Yii::app()->params['defaultLanguage'];
        }
        Yii::app()->language = Yii::app()->session['_lang'];

        return parent::init();
    }
}