<?php

/**
 * This is the model class for table "catalog_category_product".
 *
 * The followings are the available columns in table 'catalog_category_product':
 * @property string $category_id
 * @property string $product_id
 * @property integer $position
 */
class Mage2CatalogCategoryProduct extends Mage2ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{catalog_category_product}}';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('position', 'numerical', 'integerOnly'=>true),
			/*
			 * This field is new from Magento 2.1.0 and it's value is auto increment
			 * and we don't need to declare this at here.
			 * array('entity_id', 'length', 'max'=>11),*/
			array('category_id, product_id', 'length', 'max'=>10),
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage2CatalogCategoryProduct the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
