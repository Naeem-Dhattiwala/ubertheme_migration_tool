<?php

/**
 * This is the model class for table "newsletter_queue_store_link".
 *
 * The followings are the available columns in table 'newsletter_queue_store_link':
 * @property string $queue_id
 * @property integer $store_id
 */
class Mage1NewsletterQueueStoreLink extends Mage1ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{newsletter_queue_store_link}}';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('store_id', 'numerical', 'integerOnly'=>true),
			array('queue_id', 'length', 'max'=>10)
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage1NewsletterQueueStoreLink the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
