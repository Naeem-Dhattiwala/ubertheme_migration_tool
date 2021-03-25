<?php

/**
 * This is the model class for table "newsletter_subscriber".
 *
 * The followings are the available columns in table 'newsletter_subscriber':
 * @property string $subscriber_id
 * @property integer $store_id
 * @property string $change_status_at
 * @property string $customer_id
 * @property string $subscriber_email
 * @property integer $subscriber_status
 * @property string $subscriber_confirm_code
 */
class Mage1NewsletterSubscriber extends Mage1ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{newsletter_subscriber}}';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('store_id, subscriber_status', 'numerical', 'integerOnly'=>true),
			array('customer_id', 'length', 'max'=>10),
			array('subscriber_email', 'length', 'max'=>150),
			array('subscriber_confirm_code', 'length', 'max'=>32),
			array('change_status_at', 'safe')
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage1NewsletterSubscriber the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
