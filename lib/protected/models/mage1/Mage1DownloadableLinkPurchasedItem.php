<?php

/**
 * This is the model class for table "downloadable_link_purchased_item".
 *
 * The followings are the available columns in table 'downloadable_link_purchased_item':
 * @property string $item_id
 * @property string $purchased_id
 * @property string $order_item_id
 * @property string $product_id
 * @property string $link_hash
 * @property string $number_of_downloads_bought
 * @property string $number_of_downloads_used
 * @property string $link_id
 * @property string $link_title
 * @property integer $is_shareable
 * @property string $link_url
 * @property string $link_file
 * @property string $link_type
 * @property string $status
 * @property string $created_at
 * @property string $updated_at
 */
class Mage1DownloadableLinkPurchasedItem extends Mage1ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{downloadable_link_purchased_item}}';
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
			array('is_shareable', 'numerical', 'integerOnly'=>true),
			array('purchased_id, order_item_id, product_id, number_of_downloads_bought, number_of_downloads_used, link_id', 'length', 'max'=>10),
			array('link_hash, link_title, link_url, link_file, link_type', 'length', 'max'=>255),
			array('status', 'length', 'max'=>50),
			array('updated_at', 'safe')
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage1DownloadableLinkPurchasedItem the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
