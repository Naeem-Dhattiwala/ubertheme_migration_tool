<?php

/**
 * This is the model class for table "downloadable_link_purchased".
 *
 * The followings are the available columns in table 'downloadable_link_purchased':
 * @property string $purchased_id
 * @property string $order_id
 * @property string $order_increment_id
 * @property string $order_item_id
 * @property string $created_at
 * @property string $updated_at
 * @property string $customer_id
 * @property string $product_name
 * @property string $product_sku
 * @property string $link_section_title
 */
class Mage1DownloadableLinkPurchased extends Mage1ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{downloadable_link_purchased}}';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('created_at', 'required'),
			array('order_id, order_item_id, customer_id', 'length', 'max'=>10),
			array('order_increment_id', 'length', 'max'=>50),
			array('product_name, product_sku, link_section_title', 'length', 'max'=>255),
			array('updated_at', 'safe')
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage1DownloadableLinkPurchased the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
