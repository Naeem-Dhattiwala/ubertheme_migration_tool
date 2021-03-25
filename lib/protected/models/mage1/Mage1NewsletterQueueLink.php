<?php

/**
 * This is the model class for table "newsletter_queue_link".
 *
 * The followings are the available columns in table 'newsletter_queue_link':
 * @property string $queue_link_id
 * @property string $queue_id
 * @property string $subscriber_id
 * @property string $letter_sent_at
 */
class Mage1NewsletterQueueLink extends Mage1ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{newsletter_queue_link}}';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('queue_id, subscriber_id', 'length', 'max'=>10),
			array('letter_sent_at', 'safe')
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage1NewsletterQueueLink the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
